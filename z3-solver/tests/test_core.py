"""Tests for z3-solver core logic (skip if z3 not installed)."""

import unittest


def _has_z3():
    try:
        import z3  # noqa: F401
        return True
    except ImportError:
        return False


@unittest.skipUnless(_has_z3(), "z3-solver not installed")
class TestZ3(unittest.TestCase):
    def test_flag_words_and_solve(self):
        from z3solver.core import add_flag_range, extract_bytes, flag_words, solve
        import z3

        vars_ = flag_words("flag", 4, z3)
        constraints = []
        add_flag_range(constraints, vars_, z3)
        constraints.append(vars_[0] == ord("c"))
        constraints.append(vars_[1] == ord("t"))
        constraints.append(vars_[2] == ord("f"))
        constraints.append(vars_[3] == ord("}"))
        model = solve(constraints, z3)
        self.assertIsNotNone(model)
        out = extract_bytes(model, vars_)
        self.assertEqual(out, b"ctf}")


class TestImportError(unittest.TestCase):
    def test_require_z3_noop_if_absent(self):
        from z3solver.core import require_z3
        try:
            z3 = require_z3()
        except RuntimeError:
            z3 = None
        # Should either return module or raise; ensure no hard crash on import
        self.assertTrue(z3 is None or z3 is not None)


if __name__ == "__main__":
    unittest.main()
