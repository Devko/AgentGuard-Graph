import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from _helpers import ROOT


class V1ReleaseReadinessTests(unittest.TestCase):
    def test_roadmap_no_longer_reports_open_v1_product_gaps(self):
        roadmap = (ROOT / "docs" / "ROADMAP.md").read_text(encoding="utf-8")
        stale_gap_markers = [
            "v1.0 readiness: **mid-stage",
            "roughly 70-75%",
            "The remaining work is",
            "Remaining 1.0 hardening",
            "Before 1.0, they need",
            "Next Best Engineering Steps",
        ]
        for marker in stale_gap_markers:
            self.assertNotIn(marker, roadmap)
        self.assertIn("v1.0 readiness: **complete for the stable local-first baseline**", roadmap)
        self.assertIn("docs/V1_READINESS.md", roadmap)
        self.assertIn("docs/FIXTURE_REVIEW_NOTES.md", roadmap)
        self.assertIn("docs/MIGRATION_0_1_TO_1_0.md", roadmap)
        self.assertIn("docs/RELEASE_PROVENANCE.md", roadmap)
        self.assertIn("schemas/v1/manifest.json", roadmap)

    def test_v1_closure_artifacts_are_present_and_non_placeholder(self):
        required_docs = [
            ROOT / "docs" / "V1_READINESS.md",
            ROOT / "docs" / "FIXTURE_REVIEW_NOTES.md",
            ROOT / "docs" / "MIGRATION_0_1_TO_1_0.md",
            ROOT / "docs" / "RELEASE_PROVENANCE.md",
        ]
        for path in required_docs:
            content = path.read_text(encoding="utf-8")
            self.assertGreater(len(content), 500, path.name)
            self.assertNotIn("TBD", content)
            self.assertNotIn("TODO", content)

    def test_v1_schema_freeze_manifest_references_existing_contracts(self):
        manifest_path = ROOT / "schemas" / "v1" / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["release_contract"], "agentguard-graph-v1")
        self.assertEqual(manifest["product_version"], "1.0.0")
        self.assertEqual(manifest["evidence_schema_version"], "0.1")
        self.assertEqual(manifest["report_schema_version"], "0.1")
        self.assertEqual(manifest["stability"], "frozen")
        stable_contracts = "\n".join(manifest["stable_contracts"])
        self.assertIn("Evidence manifest fields", stable_contracts)
        self.assertIn("Compare drift fields", stable_contracts)
        self.assertIn("Offline control analysis fields", stable_contracts)
        self.assertIn("Portfolio rollup fields", stable_contracts)
        self.assertIn("rule_risks", stable_contracts)
        self.assertIn("Remediation plan fields", stable_contracts)
        for entry in manifest["schemas"]:
            self.assertTrue((ROOT / entry["path"]).exists(), entry["path"])
            self.assertEqual(entry["status"], "frozen")

    def test_package_metadata_marks_stable_v1(self):
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        init = (ROOT / "src" / "agentguard_graph" / "__init__.py").read_text(encoding="utf-8")
        self.assertIn('version = "1.0.0"', pyproject)
        self.assertIn('Development Status :: 5 - Production/Stable', pyproject)
        self.assertIn('__version__ = "1.0.0"', init)

    def test_built_wheel_contains_current_source_modules_and_samples(self):
        source_root = ROOT / "src" / "agentguard_graph"
        expected = {
            str(path.relative_to(source_root).as_posix())
            for path in source_root.rglob("*")
            if path.is_file()
            and "__pycache__" not in path.parts
            and (path.suffix == ".py" or "sample_packs" in path.parts)
        }
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "wheel",
                    str(ROOT),
                    "--no-deps",
                    "--no-build-isolation",
                    "--wheel-dir",
                    tmp,
                ],
                check=True,
                stdout=subprocess.DEVNULL,
            )
            wheel = Path(tmp) / "agentguard_graph-1.0.0-py3-none-any.whl"
            self.assertTrue(wheel.exists(), "The package build gate did not produce the expected wheel.")
            packaged = _wheel_agentguard_files(wheel)
        self.assertFalse(sorted(expected - packaged))


def _wheel_agentguard_files(wheel: Path) -> set[str]:
    with zipfile.ZipFile(wheel) as archive:
        return {
            name.removeprefix("agentguard_graph/")
            for name in archive.namelist()
            if name.startswith("agentguard_graph/")
        }


if __name__ == "__main__":
    unittest.main()
