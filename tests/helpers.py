import atexit
import base64
import datetime
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from odin_gate.common import (ApiError, EXPECTED_REPO, OWNER_LOGIN, sha256_hex)  # noqa: E402

from odin_gate import gate as _gate  # noqa: E402
_gate.PULL_RETRY_SLEEP = (0, 0)
NOW = datetime.datetime(2026, 10, 14, 0, 0, 0)
PKG = "demo-package"


def sh(cwd, *args, env=None):
    e = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t",
             GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="commit.gpgsign", GIT_CONFIG_VALUE_0="false",
             GIT_CONFIG_GLOBAL="/dev/null")  # throwaway repos must never use the real signing service
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True, env=e).stdout.strip()


def record(pkg=PKG, baseline="0" * 40, spec=b"fixture: echo\nsynthetic\n", **over):
    r = {"schema": "odin-authz/1", "package_id": pkg, "revision": 1, "baseline_sha": baseline,
         "spec_path": f"specs/{pkg}.md", "spec_sha256": sha256_hex(spec), "allowed_ops": ["synthetic-echo"],
         "scope_paths": [f"synthetic-out/{pkg}/"], "max_files": 3, "max_patch_bytes": 1024,
         "issued_at": "2026-10-13T00:00:00Z", "expires_at": "2026-10-15T00:00:00Z", "max_rounds": 2,
         "worker_timeout_min": 5, "status": "approved", "summary": "synthetic test"}
    r.update(over)
    return r


class Repo:
    """Local git repo with a base commit and helpers to add commits."""

    def __init__(self):
        self.root = tempfile.mkdtemp(prefix="odin-t-")
        atexit.register(shutil.rmtree, self.root, True)
        self.d = os.path.join(self.root, "repo")
        os.mkdir(self.d)
        sh(self.d, "git", "init", "-q", "-b", "main")
        os.makedirs(os.path.join(self.d, ".github/workflows"))
        self.write(".github/workflows/gate.yml", "name: x\n")
        self.write("README.md", "base\n")
        self.base = self.commit("base")

    def write(self, rel, content):
        p = os.path.join(self.d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(content if isinstance(content, bytes) else content.encode())

    def commit(self, msg):
        sh(self.d, "git", "add", "-A")
        sh(self.d, "git", "commit", "-q", "-m", msg, "--allow-empty")
        return sh(self.d, "git", "rev-parse", "HEAD")

    def authorize(self, pkg=PKG, spec=b"fixture: echo\nsynthetic\n", baseline=None, **over):
        self.write(f"specs/{pkg}.md", spec)
        self.write(f"authz/{pkg}.json", json.dumps(record(pkg, baseline or self.base, spec, **over), indent=1))
        return self.commit(f"authz {pkg}")


class FakeAPI:
    def __init__(self, repo_obj=None):
        self.refs, self.tags, self.pulls, self.blobs = {}, {}, {}, {}
        self.main_contents = {}
        self.lock = threading.Lock()
        self.commits_pulls = {}
        self.writes = []
        self.trees = {}
        self.commit_objs = {}
        self.base_commit_trees = {}
        self.n = 0

    def _id(self):
        with self.lock:
            self.n += 1
            return f"{self.n:040x}"

    def get_ref_sha(self, ref):
        return self.refs.get("refs/" + ref)

    def create_ref(self, ref, sha):
        with self.lock:
            if ref in self.refs:
                return False
            self.refs[ref] = sha
            self.writes.append(ref)
            return True

    def get_contents(self, path, ref):
        assert ref == "refs/heads/main"
        return self.main_contents.get(path)

    def set_main_record(self, repo, pkg=PKG):
        text = open(os.path.join(repo.d, f"authz/{pkg}.json")).read()
        blob = sh(repo.d, "git", "hash-object", f"authz/{pkg}.json")
        self.main_contents[f"authz/{pkg}.json"] = (blob, text)
        return blob

    def commit_pulls(self, sha):
        return self.commits_pulls.get(sha, [])

    def get_pull(self, n):
        return self.pulls[n]

    def add_pr(self, sha, merged_by=OWNER_LOGIN, number=7, merge_sha=None, merged=True, base="main"):
        self.commits_pulls[sha] = [{"number": number, "merged_at": "2026-10-14T00:00:00Z" if merged else None,
                                    "base": {"ref": base}}]
        self.pulls[number] = {"number": number, "merged": merged, "merge_commit_sha": merge_sha or sha,
                              "merged_by": {"login": merged_by}}

    def create_tag_object(self, tag, message, object_sha):
        i = self._id()
        self.tags[i] = message
        return i

    def get_tag_message(self, sha):
        return self.tags[sha]

    def create_blob(self, b64):
        raw = base64.b64decode(b64)
        i = "blob" + sha256_hex(raw)[:36]  # content-addressed like git
        self.blobs[i] = raw
        return i

    def get_commit_parents(self, sha):
        return self.commit_objs[sha][2] if sha in self.commit_objs else []

    def get_commit_tree(self, sha):
        return self.commit_objs[sha][1] if sha in self.commit_objs else "t" * 40

    def create_tree(self, base, entries):
        i = "tree" + sha256_hex(json.dumps(entries, sort_keys=True).encode())[:36]
        self.trees[i] = entries
        return i

    def create_commit(self, msg, tree, parents):
        i = self._id()
        self.commit_objs[i] = (msg, tree, parents)
        return i


def push_env(repo, before, after, **over):
    ev = os.path.join(repo.root, f"ev-{after}.json")
    with open(ev, "w") as f:
        json.dump({"before": before, "after": after}, f)
    env = {"GITHUB_REPOSITORY": EXPECTED_REPO, "GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/main",
           "GITHUB_SHA": after, "GITHUB_EVENT_PATH": ev, "GITHUB_ACTOR": OWNER_LOGIN,
           "GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_ID": "1001"}
    env.update(over)
    return env
