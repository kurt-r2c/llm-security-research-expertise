"""CLI: ablate {run,score,pairwise,reverify,build-cve} ..."""
import importlib
import sys

COMMANDS = {"run": "run_eval", "score": "score", "pairwise": "pairwise", "reverify": "reverify",
            "build-cve": "build_cve_corpus"}


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        raise SystemExit(f"usage: ablate {{{','.join(COMMANDS)}}} [args]")
    mod = importlib.import_module(f"{__package__}.{COMMANDS[sys.argv[1]]}")
    mod.main(sys.argv[2:])


if __name__ == "__main__":
    main()
