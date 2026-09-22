"""Structural checks for the skill package itself."""

from __future__ import annotations

import json
import os
import re
import unittest

from ._paths import REPO_ROOT, SKILL_DIR

FRONTMATTER = re.compile(r"^---\n(.*?)\n---\n", re.DOTALL)


def parse_frontmatter(text: str) -> dict:
    match = FRONTMATTER.match(text)
    if not match:
        raise AssertionError("SKILL.md must start with YAML frontmatter")
    fields = {}
    for line in match.group(1).splitlines():
        if not line.strip() or line.startswith(" "):
            continue
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip()
    return fields


class SkillPackageTests(unittest.TestCase):
    def setUp(self):
        self.skill_md = SKILL_DIR / "SKILL.md"
        self.text = self.skill_md.read_text()

    def test_frontmatter_has_name_and_description(self):
        fields = parse_frontmatter(self.text)
        self.assertEqual(fields["name"], "jev-command-classifier")
        self.assertEqual(fields["name"], SKILL_DIR.name)
        self.assertGreater(len(fields["description"]), 40)
        self.assertLessEqual(len(fields["description"]), 1024)

    def test_skill_has_no_unfinished_placeholders(self):
        self.assertNotIn("[TODO:", self.text)

    def test_referenced_files_exist(self):
        for target in re.findall(r"\]\((references/[^)]+)\)", self.text):
            with self.subTest(target=target):
                self.assertTrue((SKILL_DIR / target).is_file())

    def test_reference_files_are_linked_from_the_entrypoint(self):
        for path in sorted((SKILL_DIR / "references").glob("*.md")):
            with self.subTest(path=path.name):
                self.assertIn(f"references/{path.name}", self.text)

    def test_script_entrypoints_are_executable(self):
        for name in ("classify_command.py", "classify_command.mjs"):
            with self.subTest(name=name):
                self.assertTrue(os.access(SKILL_DIR / "scripts" / name, os.X_OK))

    def test_javascript_package_matches_python_package(self):
        scripts = SKILL_DIR / "scripts"
        package = json.loads((scripts / "jev_classifier_js" / "package.json").read_text())
        self.assertEqual(package["type"], "module")
        self.assertIn("node", package["engines"])
        self.assertIn("cli.mjs", package["bin"]["jev-classify-js"])
        for module in ("client.mjs", "classifier.mjs", "cli.mjs", "index.mjs"):
            with self.subTest(module=module):
                self.assertTrue((scripts / "jev_classifier_js" / module).is_file())

    def test_shared_fixtures_exist(self):
        fixtures = SKILL_DIR / "scripts" / "fixtures" / "cases.json"
        data = json.loads(fixtures.read_text())
        self.assertGreater(len(data["decide"]), 0)
        self.assertGreater(len(data["split"]), 0)
        self.assertGreater(len(data["hard_deny"]), 0)

    def test_both_implementations_reference_shared_fixtures(self):
        python_cli = (SKILL_DIR / "scripts" / "jev_classifier" / "cli.py").read_text()
        js_cli = (SKILL_DIR / "scripts" / "jev_classifier_js" / "cli.mjs").read_text()
        self.assertIn("fixtures", python_cli)
        self.assertIn("fixtures", js_cli)

    def test_agents_metadata_points_at_the_skill(self):
        metadata = (SKILL_DIR / "agents" / "openai.yaml").read_text()
        self.assertIn("$jev-command-classifier", metadata)
        self.assertIn("display_name", metadata)

    def test_installer_targets_all_documented_harnesses(self):
        installer = (REPO_ROOT / "install.sh").read_text()
        for harness in ("codex", "opencode", "pi", "commandcode"):
            with self.subTest(harness=harness):
                self.assertIn(harness, installer)


if __name__ == "__main__":
    unittest.main()
