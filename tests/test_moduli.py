"""Regression tests for the role-owned DH modulus filtering policy."""

import unittest
from pathlib import Path

from library.openssh_moduli import filter_moduli


def record(bits: int, *, prime_type: int = 2, tests: int = 6) -> str:
    """Create format fixtures; filtering deliberately trusts vendor primality tests."""
    modulus = (1 << (bits - 1)) + 1
    return f"20260913000000 {prime_type} {tests} 100 {bits - 1} 2 {modulus:X}\n"


class ModuliTests(unittest.TestCase):
    """Exercise threshold boundaries, vendor metadata and failure behavior."""

    def test_boundary_and_source_order(self) -> None:
        """A 3072-bit modulus has a 3071 size field and must be retained."""
        strong = record(3072) + record(4096)
        output, retained, removed = filter_moduli("# vendor\n" + record(2048) + strong, 3072)
        self.assertEqual(output, "# vendor\n" + strong)
        self.assertEqual((retained, removed), (2, 1))
        self.assertEqual(filter_moduli(output, 3072), (output, 2, 0))

    def test_reject_untested_and_composite_records(self) -> None:
        """Only vendor-tested safe primes contribute to the managed output."""
        strong = record(4096)
        source = record(4096, prime_type=4) + record(4096, tests=0) + record(4096, tests=7)
        self.assertEqual(filter_moduli(source + strong, 3072), (strong, 1, 3))

    def test_fail_before_empty_or_malformed_output(self) -> None:
        """Invalid sources and empty selections must never become server input."""
        sources = ["# no primes\n", record(2048), "broken\n", record(4096).replace("4095", "3071")]
        for source in sources:
            with self.subTest(source=source[:30]), self.assertRaises(ValueError):
                filter_moduli(source, 3072)
        with self.assertRaises(ValueError):
            filter_moduli(record(4096), 2048)

    def test_vendor_file(self) -> None:
        """The installed vendor file provides realistic hexadecimal records."""
        fixture = Path(__file__).parent / "fixtures" / "moduli"
        output, retained, removed = filter_moduli(fixture.read_text(encoding="ascii"), 3072)
        self.assertEqual((retained, removed), (1, 1))
        self.assertIn("# OpenSSH vendor samples", output)


if __name__ == "__main__":
    unittest.main()
