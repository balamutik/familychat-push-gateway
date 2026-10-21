from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]


class InstallerEntrypointTests(unittest.TestCase):
    def test_install_help_is_available_without_root_or_network(self):
        result = subprocess.run(['bash', str(ROOT / 'install.sh'), '--help'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--domain', result.stdout)
        self.assertIn('--ip', result.stdout)
        self.assertIn('9443', result.stdout)


if __name__ == '__main__':
    unittest.main()
