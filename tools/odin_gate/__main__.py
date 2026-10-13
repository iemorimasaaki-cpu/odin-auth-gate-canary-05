import sys

from . import claim, gate, publish, verify, worker_echo

CMDS = {"gate": gate.main, "claim": claim.main, "worker": worker_echo.main,
        "verify": verify.main, "publish": publish.main}

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in CMDS:
        sys.exit("usage: python -m odin_gate {gate|claim|worker|verify|publish}")
    sys.exit(CMDS[sys.argv[1]]())
