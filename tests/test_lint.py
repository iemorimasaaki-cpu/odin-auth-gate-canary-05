import glob
import os
import re
import shutil
import tempfile
import unittest

from helpers import sh  # noqa: F401
from odin_gate import lint_workflows

ROOT = os.path.join(os.path.dirname(__file__), "..")
WF = os.path.join(ROOT, ".github/workflows/gate.yml")


class LintTests(unittest.TestCase):
    def lint_text(self, text):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "w.yml")
        open(p, "w").write(text)
        return lint_workflows.lint(p)[0]

    def test_real_workflows_clean(self):
        probs, reps = lint_workflows.lint_all(os.path.join(ROOT, ".github/workflows/*.y*ml"))
        self.assertEqual(probs, [])
        self.assertEqual(reps[0]["triggers"], ["push", "workflow_dispatch"])
        w = {j for j, v in reps[0]["jobs"].items() if "write" in v["permissions"].values()}
        self.assertEqual(w, {"claim", "publish"})

    def test_mutations_detected(self):
        base = open(WF).read()
        muts = {
            "extra trigger": base.replace("on:\n  push:", "on:\n  issue_comment:\n    types: [created]\n  push:", 1),
            "pull_request_target": base.replace("on:\n  push:", "on:\n  pull_request_target:\n  push:", 1),
            "worker write": re.sub(r"(  worker:.*?permissions:\n      contents: )read", r"\1write", base, flags=re.S),
            "gate write": re.sub(r"(  gate:.*?permissions:\n      contents: )read", r"\1write", base, count=1, flags=re.S),
            "actions scope": base.replace("      pull-requests: read", "      actions: write", 1),
            "secrets": base.replace("TRIGGERING_ACTOR:", "FOO: ${{ secrets.X }}\n          TRIGGERING_ACTOR:", 1),
            "uses": base.replace("      - id: g", "      - uses: actions/checkout@v4\n      - id: g", 1),
            "latest runner": base.replace("ubuntu-24.04", "ubuntu-latest", 1),
            "timeout": base.replace("timeout-minutes: 5", "timeout-minutes: 30", 1),
            "expr in run": base.replace("-m odin_gate gate", "-m odin_gate gate ${{ inputs.package_id }}", 1),
            "no top perms": base.replace("permissions: {}\n", "", 1),
            "all branches": base.replace("branches: [main]", "branches: ['**']", 1),
            "format secrets": base.replace("TRIGGERING_ACTOR:", "FOO: ${{ format('{0}', secrets.X) }}\n          TRIGGERING_ACTOR:", 1),
            "always publish": base.replace("    needs: [gate, worker, verify]\n", "    needs: [gate, worker, verify]\n    if: always()\n", 1),
            "continue-on-error": base.replace("      - id: g", "      - continue-on-error: true\n        id: g", 1),
            "shell key": base.replace("      - id: g", "      - shell: bash\n        id: g", 1),
            "push tags": base.replace("    branches: [main]", "    branches: [main]\n    tags: ['*']", 1),
            "job env secrets": base.replace("    timeout-minutes: 5\n    permissions:\n      contents: read\n      pull-requests: read", "    timeout-minutes: 5\n    env:\n      K: ${{ secrets.K }}\n    permissions:\n      contents: read\n      pull-requests: read", 1),
            "extra job": base + "  extra:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    permissions:\n      contents: read\n    steps:\n      - run: echo hi\n",
            "no paths": re.sub(r"    paths:.*\n", "", base, count=1),
        }
        for name, text in muts.items():
            self.assertTrue(text != base, f"mutation {name} did not change file")
            self.assertTrue(self.lint_text(text), f"lint missed: {name}")

    def test_no_python_in_repo_root(self):
        self.assertEqual(glob.glob(os.path.join(ROOT, "*.py")), [])


if __name__ == "__main__":
    unittest.main()
