import unittest

from ssh_monitor import sanitize_username


class SanitizerTests(unittest.TestCase):
    def test_removes_terminal_controls_and_line_breaks(self) -> None:
        self.assertEqual(sanitize_username("evil\x1b[31m\nroot\r"), "evil[31mroot")

    def test_removes_unicode_format_controls(self) -> None:
        self.assertEqual(sanitize_username("ad\u202emin"), "admin")

    def test_limits_length_after_removing_controls(self) -> None:
        self.assertEqual(sanitize_username("\x1b" + "a" * 100, max_length=8), "a" * 8)

    def test_none_and_invalid_limit(self) -> None:
        self.assertIsNone(sanitize_username(None))
        with self.assertRaises(ValueError):
            sanitize_username("alice", max_length=0)


if __name__ == "__main__":
    unittest.main()
