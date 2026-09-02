"""Core logic for offsetfind - Buffer Overflow Offset Finder."""

from __future__ import annotations

import gc
import os
import signal
import time
from dataclasses import dataclass, field
from typing import Optional

PATTERN_ALPHABET = b"abcdefghijklmnopqrstuvwxyz"


@dataclass
class ChecksecInfo:
    arch_bits: int = 0
    nx: Optional[bool] = None
    pie: Optional[bool] = None
    canary: Optional[bool] = None
    relro: Optional[str] = None
    aslr: Optional[bool] = None
    stripped: Optional[bool] = None


@dataclass
class CrashResult:
    crashed: bool = False
    fault_addr: Optional[int] = None
    fault_addr_hex: str = ""
    offset: Optional[int] = None
    rip: Optional[int] = None
    rsp: Optional[int] = None
    pie_base: Optional[int] = None
    notes: list = field(default_factory=list)


@dataclass
class OffsetResult:
    checksec: ChecksecInfo
    crash: CrashResult
    remote_reached: Optional[bool] = None
    remote_note: Optional[str] = None


def _pwn() -> object:
    """Lazily import pwntools with a clear error if it is missing."""
    try:
        import pwntools as _  # noqa: F401
    except ImportError:
        pass
    try:
        import pwn
    except ImportError:
        raise RuntimeError(
            "pwntools is not installed. Install it with: "
            "pip install pwntools (use a Python 3.13 venv if native "
            "wheels for Python 3.14 are not available yet)."
        )
    return pwn


def get_checksec(binary: str) -> ChecksecInfo:
    pwn = _pwn()
    elf = pwn.ELF(binary, checksec=False) if hasattr(pwn, "ELF") else None
    info = ChecksecInfo()

    def _attr(name, cast=None):
        try:
            v = getattr(elf, name)
            if v is None:
                return None
            return cast(v) if cast else v
        except (AttributeError, ValueError, TypeError):
            return None

    info.arch_bits = _attr("bits")
    info.nx = _attr("nx")
    info.pie = _attr("pie")
    info.canary = _attr("canary")
    info.relro = _attr("relro")
    info.aslr = _attr("aslr")
    info.stripped = _attr("stripped")
    return info


def make_pattern(length: int, bits: int = 64) -> bytes:
    """Cyclic pattern (de Bruijn) via pwntools, word size matching the
    architecture."""
    pwn = _pwn()
    try:
        from pwn import cyclic
    except ImportError:
        cyclic = pwn.cyclic
    return cyclic(length, n=bits // 8)


def pie_base_from_core(core, binary_path: str) -> Optional[int]:
    """PIE base address from the corefile mapping list (/proc maps-style string)."""
    try:
        text = core.maps
    except Exception:
        return None
    if text is None:
        return None
    if isinstance(text, bytes):
        try:
            text = text.decode("utf-8", "replace")
        except Exception:
            return None
    target = os.path.realpath(binary_path)
    base = None
    for line in (text or "").splitlines():
        if target not in line:
            continue
        parts = line.split()
        if not parts or "-" not in parts[0]:
            continue
        try:
            lo = int(parts[0].split("-")[0], 16)
        except ValueError:
            continue
        if base is None or lo < base:
            base = lo
    return base or None


def find_offset_in_pattern(value: int, bits: int) -> Optional[int]:
    try:
        from pwn import cyclic_find
    except ImportError:
        pwn = _pwn()
        cyclic_find = pwn.cyclic_find
    try:
        off = int(cyclic_find(value, n=bits // 8))
        return off if off >= 0 else None
    except ValueError:
        return None
    except Exception:
        return None


def run_local_crash(binary: str, payload: bytes, timeout: float = 5.0) -> CrashResult:
    """Run the local binary with the payload, extracting the fault address
    from the core.

    Uses pwntools corefiles so it does not depend on the core ulimit or the
    /proc/sys/kernel/core_pattern configuration.
    """
    pwn = _pwn()
    res = CrashResult()
    exe = os.path.abspath(binary)
    proc = None
    try:
        proc = pwn.process(exe, stdin=pwn.PTY, stderr=pwn.PTY)
        try:
            proc.sendline(payload)
        except Exception as exc:
            res.notes.append(f"failed to send payload: {exc}")
        try:
            proc.wait(timeout=timeout)
        except Exception:
            proc.kill()
            res.notes.append(f"process did not crash within {timeout}s (killed)")
            return res
    except Exception as exc:
        res.notes.append(f"error running binary: {exc}")
        return res

    if proc.returncode != -signal.SIGSEGV and proc.returncode != -signal.SIGILL:
        res.notes.append(
            f"process exited with {proc.returncode} (not a crash); "
            "make sure the binary is vulnerable and the payload is long enough"
        )
        try:
            proc.close()
        except Exception:
            pass
        return res

    res.crashed = True
    try:
        core = proc.corefile
    except Exception as exc:
        res.notes.append(f"failed to read corefile: {exc}")
        return res
    if core is None:
        res.notes.append("process crashed but no corefile is available")
        return res

    try:
        base = pie_base_from_core(core, exe)
        if base is not None:
            res.pie_base = base
    except Exception:
        res.pie_base = None

    try:
        res.fault_addr = int(core.fault_addr) if core.fault_addr is not None else None
    except (AttributeError, TypeError, ValueError):
        res.fault_addr = None

    for name in ("pc", "rip", "eip"):
        try:
            v = getattr(core, name)
            if v is not None:
                setattr(res, "rip", int(v))
                break
        except (AttributeError, TypeError, ValueError):
            continue

    try:
        rsp = getattr(core, "sp", None)
        if rsp is None:
            rsp = getattr(core, "rsp", None)
        res.rsp = int(rsp) if rsp is not None else None
    except (AttributeError, TypeError, ValueError):
        res.rsp = None

    if res.fault_addr is None:
        fa_src = res.rip or res.rsp
        if fa_src is not None:
            res.fault_addr = fa_src
            res.fault_addr_hex = f"0x{fa_src:x}"
            res.notes.append("fault_addr unavailable; using RIP/RSP as the pattern value")
    else:
        res.fault_addr_hex = f"0x{res.fault_addr:x}"

    try:
        proc.close()
    except Exception:
        pass

    gc.collect()
    return res


def match_offset(crash: CrashResult, bits: int, pattern: bytes) -> Optional[int]:
    """Compute the offset from the fault address if it holds a cyclic value."""
    if crash.fault_addr is None:
        return None
    for candidate in (crash.fault_addr, crash.rip):
        if candidate is None:
            continue
        off = find_offset_in_pattern(candidate, bits)
        if off is not None:
            crash.offset = off
            return off
    return None


def probe_remote(host: str, port: int, payload: bytes, timeout: float = 5.0):
    """Send the pattern to a remote service; return (crash?, note)."""
    pwn = _pwn()
    r = None
    try:
        r = pwn.remote(host, port, timeout=timeout)
    except Exception as exc:
        if r is not None:
            try:
                r.close()
            except Exception:
                pass
        return None, f"connection to {host}:{port} failed: {exc}"

    try:
        try:
            r.recv(timeout=1.5)  # optional banner/prompt — ignored
        except EOFError:
            pass
        try:
            r.sendline(payload)
        except Exception as exc:
            return None, f"failed to send payload: {exc}"

        deadline = time.time() + timeout
        got_data = False
        while time.time() < deadline:
            try:
                if r.recv(timeout=0.5):
                    got_data = True
            except EOFError:
                if got_data:
                    return False, "service responded then closed the connection (alive)"
                return True, "connection dropped with no response (likely crash)"
            except Exception as exc:
                return None, f"error while interacting with remote: {exc}"
        if got_data:
            return False, "service still responsive after payload (no crash)"
        return False, "no response within the window; increase --timeout if needed"
    finally:
        try:
            r.close()
        except Exception:
            pass


def find_offset(binary: Optional[str],
                host: Optional[str] = None,
                port: Optional[int] = None,
                pattern_length: int = 1024,
                timeout: float = 5.0) -> OffsetResult:
    if binary is None:
        raise ValueError("binary path is required")

    checksec = get_checksec(binary)
    info = checksec
    bits = info.arch_bits or 64
    pattern = make_pattern(pattern_length, bits)
    crash = run_local_crash(binary, pattern, timeout)
    match_offset(crash, bits, pattern)

    result = OffsetResult(checksec=checksec, crash=crash)

    if host and port:
        hit, note = probe_remote(host, port, pattern, timeout)
        result.remote_reached = hit
        result.remote_note = note
        if hit:
            crash.notes.append("remote: service crash confirmed")
        elif note:
            crash.notes.append(f"remote: {note}")

    return result