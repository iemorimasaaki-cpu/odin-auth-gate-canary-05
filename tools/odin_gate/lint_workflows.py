"""Static enumeration + enforcement of workflow triggers, permissions and privileged job paths."""
import glob
import re
import sys

import yaml

ALLOWED_TRIGGERS = {"push", "workflow_dispatch"}
WRITE_JOBS = {"claim": {"contents": "write"}, "publish": {"contents": "write"}}
SECRET_RE = re.compile(r"\$\{\{[^}]*\bsecrets\b|ANTHROPIC|OPENAI|OAUTH_TOKEN|API_KEY|PRIVATE_KEY", re.I)
EXPR_RE = re.compile(r"\$\{\{")


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
    if wf.get("permissions") != {}:
        problems.append(f"{path}: workflow-level permissions must be {{}}")
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
        if any(k in perms for k in ("actions", "id-token", "packages", "deployments", "statuses", "checks", "workflows")):
            problems.append(f"{path}:{name}: forbidden permission scope")
        if job.get("runs-on") != "ubuntu-24.04":
            problems.append(f"{path}:{name}: runs-on must be ubuntu-24.04")
        if not isinstance(job.get("timeout-minutes"), int) or job["timeout-minutes"] > 5:
            problems.append(f"{path}:{name}: timeout-minutes must be <= 5")
        for i, step in enumerate(job.get("steps", [])):
            if EXPR_RE.search(step.get("run", "")):
                problems.append(f"{path}:{name}:step{i}: expression inside run: (use env:)")
            if "uses" in step:
                problems.append(f"{path}:{name}:step{i}: uses: not allowed")
            if "secrets" in str(step.get("env", {})).lower():
                problems.append(f"{path}:{name}:step{i}: secrets in env")
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
