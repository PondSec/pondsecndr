from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import unittest


class DocRedactionTests(unittest.TestCase):
    def test_public_markdown_does_not_contain_live_network_identifiers(self) -> None:
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            [sys.executable, "tools/check_doc_redaction.py"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
