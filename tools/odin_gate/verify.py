"""VERIFY logic: deterministic check of the ACTUAL bytes the worker produced (never its self-description)."""
import base64
import json
import os
import re

from .common import (FORBIDDEN_PREFIXES, EXPECTED_REPO, Reject, load_json_strict, norm_rel_path,
                     read_tree_file, sha256_hex, summary, utcnow, validate_record)

MAX_BUNDLE_CHARS = 120_000
SEG_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")  # ASCII lowercase only: no case/Unicode/NTFS tricks


def decode_bundle(text):
    if len(text) > MAX_BUNDLE_CHARS:
        raise Reject("BUNDLE_TOO_LARGE", f"{len(text)} chars")
    b = load_json_strict(text, "bundle")
    if not isinstance(b, dict) or set(b) != {"schema", "files"} or b["schema"] != "odin-bundle/1" \
            or not isinstance(b["files"], list):
        raise Reject("BUNDLE_SCHEMA", "top level")
    files = {}
    for e in b["files"]:
        if not isinstance(e, dict) or set(e) != {"path", "size", "sha256", "b64"}:
            raise Reject("BUNDLE_SCHEMA", "entry keys")
        if e["path"] in files:
            raise Reject("DUPLICATE_PATH", e["path"])
        try:
            raw = base64.b64decode(e["b64"], validate=True)
        except Exception:
            raise Reject("BUNDLE_SCHEMA", "base64")
        # declared metadata is checked against the real bytes, never trusted
        if e["size"] != len(raw) or e["sha256"] != sha256_hex(raw):
            raise Reject("MANIFEST_MISMATCH", e["path"])
        files[e["path"]] = raw
    return files


def verify_files(files, rec):
    """files: {path: bytes}. Raises Reject. Returns verified manifest dict."""
    if not files:
        raise Reject("EMPTY_OUTPUT", "")
    if len(files) > rec["max_files"]:
        raise Reject("TOO_MANY_FILES", f"{len(files)} > {rec['max_files']}")
    total, manifest = 0, []
    scopes = [norm_rel_path(s) for s in rec["scope_paths"]]
    for path, raw in sorted(files.items()):
        if any(path.startswith(p) for p in FORBIDDEN_PREFIXES):
            raise Reject("FORBIDDEN_PATH", path)
        segs = path.split("/")
        if len(path) > 200 or not all(SEG_RE.match(s) and not s.endswith(".") and not s.startswith("git~") for s in segs):
            raise Reject("BAD_PATH", repr(path))
        if not any(path == s or path.startswith(s + "/") for s in scopes):
            raise Reject("OUT_OF_SCOPE", path)
        total += len(raw)
        manifest.append({"path": path, "size": len(raw), "sha256": sha256_hex(raw)})
    if total > rec["max_patch_bytes"]:
        raise Reject("TOO_LARGE", f"{total} > {rec['max_patch_bytes']}")
    return {"schema": "odin-verified/1", "files": manifest, "total_bytes": total}


def run_verify(env, repo_dir, bundle_text, now=None):
    now = now or utcnow()
    pkg = env["PACKAGE_ID"]
    rec = validate_record(load_json_strict(read_tree_file(repo_dir, env.get("GITHUB_SHA", "HEAD"), f"authz/{pkg}.json").decode(), "record"), pkg, now)
    files = decode_bundle(bundle_text)
    return rec, files, verify_files(files, rec)


def main(env=None):
    env = dict(os.environ if env is None else env)
    assert env.get("GITHUB_REPOSITORY") == EXPECTED_REPO
    try:
        _, _, m = run_verify(env, ".", env["BUNDLE"])
    except Reject as r:
        summary(f"### Verify\nREJECT {r.code}: {r.detail}")
        return 1
    summary(f"### Verify\nPASS files={len(m['files'])} bytes={m['total_bytes']}")
    return 0
