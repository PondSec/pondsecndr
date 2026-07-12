from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PackagingTests(unittest.TestCase):
    def run_deinstall(self, tmp: Path, extra_env: dict[str, str]) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update({
            "PONDSEC_NDR_DATA_DIR": str(tmp / "data"),
            "PONDSEC_NDR_CONFIG_DIR": str(tmp / "config"),
            "PONDSEC_NDR_RUN_DIR": str(tmp / "run"),
            **extra_env,
        })
        return subprocess.run(
            ["/bin/sh", str(ROOT / "pkg-deinstall"), "dummy", "DEINSTALL"],
            cwd=ROOT,
            env=env,
            stdin=subprocess.DEVNULL,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_deinstall_keeps_forensic_data_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as work:
            tmp = Path(work)
            data = tmp / "data"
            config = tmp / "config"
            run = tmp / "run"
            model_dir = data / "models"
            model_dir.mkdir(parents=True)
            config.mkdir()
            run.mkdir()
            (data / "pondsec-ndr.db").write_text("placeholder", encoding="utf-8")
            (model_dir / "model.npz").write_text("placeholder", encoding="utf-8")

            result = self.run_deinstall(tmp, {})

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(config.exists())
            self.assertTrue((data / "pondsec-ndr.db").exists())
            self.assertTrue((model_dir / "model.npz").exists())
            self.assertFalse(run.exists())

    def test_deinstall_full_cleanup_is_env_controlled(self) -> None:
        with tempfile.TemporaryDirectory() as work:
            tmp = Path(work)
            data = tmp / "data"
            config = tmp / "config"
            run = tmp / "run"
            (data / "models").mkdir(parents=True)
            config.mkdir()
            run.mkdir()
            (data / "pondsec-ndr.db").write_text("placeholder", encoding="utf-8")
            (data / "models" / "model.npz").write_text("placeholder", encoding="utf-8")

            result = self.run_deinstall(tmp, {
                "PONDSEC_KEEP_CONFIG": "no",
                "PONDSEC_KEEP_DATABASE": "no",
                "PONDSEC_KEEP_MODELS": "no",
                "PONDSEC_REMOVE_PF_BLOCKS": "no",
            })

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(config.exists())
            self.assertFalse(run.exists())
            self.assertFalse(data.exists())

    def test_deinstall_marks_pf_blocks_removed_with_python_sqlite_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as work:
            tmp = Path(work)
            data = tmp / "data"
            config = tmp / "config"
            run = tmp / "run"
            helpers = tmp / "helpers"
            data.mkdir()
            config.mkdir()
            run.mkdir()
            helpers.mkdir()
            (helpers / "python3").symlink_to(Path(sys.executable))
            (helpers / "tr").symlink_to(Path("/usr/bin/tr"))

            db = data / "pondsec-ndr.db"
            with sqlite3.connect(db) as conn:
                conn.execute(
                    "CREATE TABLE block_entries (source_ip TEXT, status TEXT, removal_reason TEXT)"
                )
                conn.execute(
                    "INSERT INTO block_entries VALUES ('192.0.2.44', 'active', NULL)"
                )

            env = {
                "PATH": f"{helpers}:/bin",
                "PONDSEC_KEEP_CONFIG": "yes",
                "PONDSEC_KEEP_DATABASE": "yes",
                "PONDSEC_KEEP_MODELS": "yes",
                "PONDSEC_REMOVE_PF_BLOCKS": "yes",
            }
            result = self.run_deinstall(tmp, env)

            self.assertEqual(result.returncode, 0, result.stderr)
            with sqlite3.connect(db) as conn:
                row = conn.execute(
                    "SELECT status, removal_reason FROM block_entries WHERE source_ip = '192.0.2.44'"
                ).fetchone()
            self.assertEqual(row, ("removed", "package_deinstall"))

    def test_package_shell_scripts_parse(self) -> None:
        for script in ("pkg-install", "pkg-deinstall", "tools/build_signed_repo.sh"):
            with self.subTest(script=script):
                result = subprocess.run(
                    ["/bin/sh", "-n", str(ROOT / script)],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_pkg_message_documents_operational_prerequisites(self) -> None:
        message = (ROOT / "pkg-message").read_text(encoding="utf-8")
        self.assertIn("Suricata EVE JSON", message)
        self.assertIn("Zenarmor or Squid", message)
        self.assertIn("monitor/learning", message)

    def test_release_repository_doc_requires_signed_metadata(self) -> None:
        doc = (ROOT / "docs" / "RELEASE_REPOSITORY.md").read_text(encoding="utf-8")
        self.assertIn("pkg repo", doc)
        self.assertIn("signature_type: \"PUBKEY\"", doc)
        self.assertIn("must not download unsigned code, model artifacts, or package data", doc)

    def test_incident_view_exposes_manual_and_dns_response_actions(self) -> None:
        view = (ROOT / "src" / "opnsense" / "mvc" / "app" / "views" / "OPNsense" / "PondSecNDR" / "list.volt").read_text(encoding="utf-8")
        self.assertIn('data-action="manual-block"', view)
        self.assertIn('data-action="propose-sinkhole"', view)
        self.assertIn("/api/pondsecndr/sinkhole/propose/", view)
        self.assertIn("top: 96px;", view)
        self.assertIn("File sandbox and file verdicts", view)
        self.assertNotIn("padding-top: 48px;", view)

    def test_blocklist_view_exposes_dns_sinkhole_lifecycle(self) -> None:
        view = (ROOT / "src" / "opnsense" / "mvc" / "app" / "views" / "OPNsense" / "PondSecNDR" / "blocklist.volt").read_text(encoding="utf-8")
        self.assertIn("/api/pondsecndr/sinkhole/list", view)
        self.assertIn("/api/pondsecndr/sinkhole/add", view)
        self.assertIn("/api/pondsecndr/sinkhole/edit/", view)
        self.assertIn("/api/pondsecndr/sinkhole/activate/", view)
        self.assertIn("/api/pondsecndr/sinkhole/remove/", view)
        self.assertIn("pondsec_sinkhole_edit_form", view)
        self.assertIn("Ablauf leer lassen fuer einen unbegrenzten DNS-Sinkhole", view)

    def test_backend_json_trait_reports_invalid_backend_payloads(self) -> None:
        trait = (ROOT / "src" / "opnsense" / "mvc" / "app" / "controllers" / "OPNsense" / "PondSecNDR" / "Api" / "BackendJsonTrait.php").read_text(encoding="utf-8")
        self.assertIn("json_last_error_msg()", trait)
        self.assertIn("'raw_excerpt'", trait)
        self.assertIn("Bad Gateway", trait)

    def test_safe_pentest_tools_cover_enterprise_validation_and_evidence_collection(self) -> None:
        suite = (ROOT / "tools" / "pentest" / "ndr_safe_pentest_suite.py").read_text(encoding="utf-8")
        dummy = (ROOT / "tools" / "pentest" / "ndr_dummy_vulnerable_service.py").read_text(encoding="utf-8")
        collector = (ROOT / "tools" / "pentest" / "ndr_collect_evidence.py").read_text(encoding="utf-8")
        readme = (ROOT / "tools" / "pentest" / "README.md").read_text(encoding="utf-8")

        self.assertIn("email_url_file_like", suite)
        self.assertIn("exfil_like_transfer", suite)
        self.assertIn("--include-eicar", suite)
        self.assertIn("/webmail/attachment/", dummy)
        self.assertIn("/upload/dummy-exfil", dummy)
        self.assertIn("false_negative", collector)
        self.assertIn("detection_latency_seconds", collector)
        self.assertIn("ndr_collect_evidence.py", readme)


if __name__ == "__main__":
    unittest.main()
