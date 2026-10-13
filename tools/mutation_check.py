"""Apply single-line mutations to security checks; every mutation MUST make the suite fail."""
import os, shutil, subprocess, sys, tempfile

MUTS = [
 ("gate.py", 'if merger != OWNER_LOGIN:', 'if False:'),
 ("gate.py", 'if attempt < 1 or attempt > 2:', 'if attempt < 1:'),
 ("gate.py", 'if outside:', 'if False:'),
 ("gate.py", 'if git("merge-base", "--is-ancestor"', 'if False and git("merge-base", "--is-ancestor"'),
 ("gate.py", 'if bad:\n        raise Reject("GATE_CHANGE"', 'if False:\n        raise Reject("GATE_CHANGE"'),
 ("gate.py", 'if not prs:', 'if False:'),
 ("gate.py", 'if rnd > rec["max_rounds"]:', 'if False:'),
 ("gate.py", 'if sha256_hex(read_tree_file(repo_dir, sha, rec["spec_path"])) != rec["spec_sha256"]:', 'if False:'),
 ("gate.py", 'if pr is None:', 'if False:'),
 ("gate.py", 'raise Reject("ACTOR_MISMATCH"', 'pass; (lambda *a: None)("ACTOR_MISMATCH"'),
 ("gate.py", 'if env.get("GITHUB_REF") != "refs/heads/main":', 'if False:'),
 ("gate.py", 'if event not in ("push", "workflow_dispatch"):', 'if False:'),
 ("gate.py", 'if load_json_strict(msg, "prior claim").get("authz_blob_sha") != d["authz_blob"]:', 'if False:'),
 ("gate.py", 'if prev_sha is None:', 'if False:'),
 ("common.py", 'if now >= expires:', 'if now > expires:'),
 ("common.py", 'if blob != expected_blob:', 'if False:'),
 ("common.py", 'if extra or missing:', 'if False:'),
 ("common.py", 'not (n + "/").startswith(f"synthetic-out/{pkg}/")', 'False'),
 ("common.py", 'e.status == 422 and "already exists" in e.body.lower()', 'e.status == 422'),
 ("verify.py", 'raise Reject("OUT_OF_SCOPE", path)', 'pass'),
 ("verify.py", 'if total > rec["max_patch_bytes"]:', 'if False:'),
 ("verify.py", 'if len(files) > rec["max_files"]:', 'if False:'),
 ("verify.py", 'if e["size"] != len(raw) or e["sha256"] != sha256_hex(raw):', 'if False:'),
 ("verify.py", 'if any(path.startswith(p) for p in FORBIDDEN_PREFIXES):', 'if False:'),
 ("verify.py", 'if len(path) > 200 or not all(SEG_RE.match(s)', 'if False and not all(SEG_RE.match(s)'),
 ("common.py", 'if name != path or mode != "100644" or typ != "blob":', 'if False:'),
 ("common.py", 'AUTHZ_PATH_RE = re.compile(r"authz/([a-z0-9][a-z0-9-]{2,39})\\.json\\Z")', 'AUTHZ_PATH_RE = re.compile(r"authz/([a-z0-9][a-z0-9-]{2,39})\\.json$")'),
 ("common.py", 'cur = api.get_contents(f"authz/{pkg}.json", "refs/heads/main")', 'cur = api.get_contents(f"authz/{pkg}.json", "main")'),
 ("gate.py", 'env.get("TRIGGERING_ACTOR", "") != OWNER_LOGIN', 'env.get("TRIGGERING_ACTOR", OWNER_LOGIN) != OWNER_LOGIN'),
 ("gate.py", 'if full.get("merged") and full.get("merge_commit_sha") == sha:', 'if True:'),
 ("gate.py", 'for delay in (0,) + tuple(PULL_RETRY_SLEEP):', 'for delay in (0,):'),
 ("publish.py", 'if existing is None or api.get_commit_tree(existing) != tree or', 'if existing is None or False or'),
 ("lint_workflows.py", 'if name in GOLDEN_GRAPH and (job.get("needs"), job.get("if")) != GOLDEN_GRAPH[name]:', 'if False:'),
 ("lint_workflows.py", 'if re.search(r"secrets|vars\\.|env\\.", m.group(1)):', 'if False:'),
 ("publish.py", '    live_check(api, pkg, blob)  # revocation before the write\n', ''),
 ("publish.py", 'run_verify(env, repo_dir, bundle_text, now)  # defense in depth', '(None, {}, {"files": []})'),
 ("publish.py", 'raise Reject("NO_CLAIM", "publish without a claim")', 'pass'),
 ("publish.py", 'if not api.create_ref(f"refs/heads/{branch}", commit):', 'if False:'),
 ("claim.py", '    live_check(api, pkg, blob)  # revocation between GATE and CLAIM is caught here\n', ''),
 ("claim.py", 'return "claimed" if created else "duplicate"', 'return "claimed"'),
 ("worker_echo.py", "    live_check(api, pkg, blob)\n    files =", "    files ="),
 ("worker_echo.py", "        live_check(api, pkg, blob)  # in-flight", "        pass  # in-flight"),
 ("lint_workflows.py", 'if t not in ALLOWED_TRIGGERS:', 'if False:'),
 ("lint_workflows.py", 'if writes != WRITE_JOBS.get(name, {}):', 'if False:'),
]

def main():
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    survived = []
    for f, old, new in MUTS:
        tmp = tempfile.mkdtemp()
        shutil.copytree(root, tmp, dirs_exist_ok=True, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        p = os.path.join(tmp, "tools/odin_gate", f)
        s = open(p).read()
        if old not in s:
            print("MISSING-PATTERN", f, old[:50]); survived.append((f, old)); continue
        open(p, "w").write(s.replace(old, new, 1))
        r = subprocess.run([sys.executable, "-W", "ignore", "-m", "unittest", "discover", "-s", "tests", "-t", "tests"],
                           cwd=tmp, capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=os.path.join(tmp, "tools") + ":" + os.path.join(tmp, "tests"), PYTHONDONTWRITEBYTECODE="1"))
        killed = r.returncode != 0
        print("KILLED " if killed else "SURVIVED", f, "|", old[:60].replace("\n", " "))
        if not killed:
            survived.append((f, old))
        shutil.rmtree(tmp)
    print(f"mutations={len(MUTS)} survived={len(survived)}")
    return 1 if survived else 0

if __name__ == "__main__":
    sys.exit(main())
