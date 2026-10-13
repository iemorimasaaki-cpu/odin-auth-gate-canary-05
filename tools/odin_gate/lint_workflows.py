"""Static enumeration + enforcement of workflow triggers, permissions and privileged job paths."""
import glob
import re
import sys

import yaml

ALLOWED_TRIGGERS = {"push", "workflow_dispatch"}
WRITE_JOBS = {"claim": {"contents": "write"}, "publish": {"contents": "write"}}
SECRET_RE = re.compile(r"\$\{\{[^}]*\bsecrets\b|ANTHROPIC|OPENAI|OAUTH_TOKEN|API_KEY|PRIVATE_KEY", re.I)
EXPR_RE = re.compile(r"\$\{\{")
ANY_EXPR_RE = re.compile(r"\$\{\{(.*?)\}\}", re.S)
TOP_KEYS = {"name", "run-name", "on", "permissions", "env", "jobs", True}
JOB_KEYS = {"runs-on", "timeout-minutes", "permissions", "needs", "if", "outputs", "environment", "steps"}
STEP_KEYS = {"name", "id", "env", "run"}
PUSH_KEYS = {"branches", "paths"}
# Golden job graph: any change to needs/if (e.g. `if: always()`) is a lint failure.
GOLDEN_GRAPH = {
    "gate": (None, None),
    "claim": ("gate", "needs.gate.outputs.decision == 'GO'"),
    "worker": (["gate", "claim"], "needs.claim.outputs.claimed == 'true'"),
    "verify": (["gate", "worker"], None),
    "publish": (["gate", "worker", "verify"], None),
}


def lint(path):
    problems, report = [], {"file": path, "triggers": [], "jobs": {}}
    text = open(path).read()
    wf = yaml.safe_load(text)
    on = wf.get("on", wf.get(True))
    triggers = sorted(on) if isinstance(on, dict) else sorted([on] if isinstance(on, str) else on)
    report["triggers"] = triggers
    for t in triggers:
        if t not in ALLOWED_TRIGGERS:
            problems.append(f"{path}: trigger {t!r} not allowed")
    push = (on or {}).get("push") if isinstance(on, dict) else None
    if "push" in triggers and (push or {}).get("branches") != ["main"]:
        problems.append(f"{path}: push must be restricted to branches [main]")
    if "push" in triggers and not (push or {}).get("paths"):
        problems.append(f"{path}: push must have a paths filter")
    for k in wf:
        if k not in TOP_KEYS:
            problems.append(f"{path}: unexpected top-level key {k!r}")
    if isinstance(push, dict) and set(push) - PUSH_KEYS:
        problems.append(f"{path}: unexpected push keys {sorted(set(push) - PUSH_KEYS)}")
    if set(wf["jobs"]) != set(GOLDEN_GRAPH):
        problems.append(f"{path}: job set {sorted(wf['jobs'])} != golden {sorted(GOLDEN_GRAPH)}")
    for m in ANY_EXPR_RE.finditer(text):
        if re.search(r"secrets|vars\.|env\.", m.group(1)):
            problems.append(f"{path}: expression references secrets/vars/env: {m.group(0)[:60]}")
    if wf.get("permissions") != {}:
        problems.append(f"{path}: workflow-level permissions must be {{}}")
    if set(wf.get("env") or {}) != {"PYTHONDONTWRITEBYTECODE", "ODIN_TOOLS_TREE"}:
        problems.append(f"{path}: workflow env keys must be exactly PYTHONDONTWRITEBYTECODE, ODIN_TOOLS_TREE")
    if SECRET_RE.search(text):
        problems.append(f"{path}: references secrets / model credentials")
    if re.search(r"self-hosted|larger|ubuntu-latest", text):
        problems.append(f"{path}: non-pinned or non-standard runner")
    if re.search(r"^\s*-?\s*uses:", text, re.M):
        problems.append(f"{path}: third-party/first-party actions (uses:) are not allowed in this canary")
    for name, job in wf["jobs"].items():
        perms = job.get("permissions")
        if not isinstance(perms, dict) or not perms:
            problems.append(f"{path}:{name}: explicit permissions required")
            perms = {}
        writes = {k: v for k, v in perms.items() if v == "write"}
        if writes != WRITE_JOBS.get(name, {}):
            problems.append(f"{path}:{name}: write permissions {writes} != allowed {WRITE_JOBS.get(name, {})}")
        for k in job:
            if k not in JOB_KEYS:
                problems.append(f"{path}:{name}: unexpected job key {k!r}")
        if name in GOLDEN_GRAPH and (job.get("needs"), job.get("if")) != GOLDEN_GRAPH[name]:
            problems.append(f"{path}:{name}: needs/if differ from golden graph")
        if any(k in perms for k in ("actions", "id-token", "packages", "deployments", "statuses", "checks", "workflows")):
            problems.append(f"{path}:{name}: forbidden permission scope")
        if job.get("runs-on") != "ubuntu-24.04":
            problems.append(f"{path}:{name}: runs-on must be ubuntu-24.04")
        if not isinstance(job.get("timeout-minutes"), int) or job["timeout-minutes"] > 5:
            problems.append(f"{path}:{name}: timeout-minutes must be <= 5")
        for i, step in enumerate(job.get("steps", [])):
            if "odin_gate" in step.get("run", "") and "python3 -P -B -m odin_gate" not in step["run"]:
                problems.append(f"{path}:{name}:step{i}: odin_gate must run with python3 -P -B (no cwd on sys.path)")
            if "git archive" in step.get("run", "") and "ODIN_TOOLS_TREE" not in step["run"]:
                problems.append(f"{path}:{name}:step{i}: trusted tools copy must be pin-checked")
            if EXPR_RE.search(step.get("run", "")):
                problems.append(f"{path}:{name}:step{i}: expression inside run: (use env:)")
            for k in step:
                if k not in STEP_KEYS:
                    problems.append(f"{path}:{name}:step{i}: unexpected step key {k!r}")
            if "uses" in step:
                problems.append(f"{path}:{name}:step{i}: uses: not allowed")
        report["jobs"][name] = {"permissions": perms, "environment": job.get("environment"),
                                "needs": job.get("needs"), "if": job.get("if")}
    return problems, report


def lint_all(pattern=".github/workflows/*.y*ml"):
    files = sorted(glob.glob(pattern))
    problems, reports = [], []
    if not files:
        problems.append("no workflows found")
    for f in files:
        p, r = lint(f)
        problems += p
        reports.append(r)
    return problems, reports


if __name__ == "__main__":
    probs, reps = lint_all()
    for r in reps:
        print(r["file"], "triggers=", r["triggers"])
        for j, v in r["jobs"].items():
            print("  job", j, v["permissions"], "env=", v["environment"])
    for p in probs:
        print("PROBLEM", p)
    sys.exit(1 if probs else 0)
