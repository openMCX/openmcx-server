"""Basic executable contract; the speech scenario supplies behavioral coverage.

No 3GPP procedure is under test: the built server binary must refuse to start without --config.
"""

import pathlib
import subprocess
import unittest


# ------------------------------------------------------------------------------
class Binaries(unittest.TestCase):
    """The native binaries in build/."""

    # ------------------------------------------------------------------------------
    def test_native_tools_require_configuration(self):
        """Each binary run without arguments exits non-zero and names --config."""
        for name in ('openmcx-mcptt-server',):
            with self.subTest(name=name):
                binary = pathlib.Path(__file__).resolve().parents[2] / 'build' / name
                self.assertTrue(binary.is_file(), f'{name} has not been built')
                result = subprocess.run([str(binary)], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('--config', result.stderr)


if __name__ == '__main__':
    unittest.main()
