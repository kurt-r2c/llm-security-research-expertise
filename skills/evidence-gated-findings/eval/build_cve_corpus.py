"""Fetch the vulnerable (pre-fix) source for post-cutoff advisories and write gold from the fix diff.

Public advisories only. Output: eval/corpus-cve/<id>/ (gitignored third-party code) and
eval/gold-cve.json (changed non-test source files with old-side hunk ranges).
Usage: uv run python eval/build_cve_corpus.py
"""
import io
import json
import re
import shutil
import subprocess
import tarfile
from pathlib import Path

EVAL = Path(__file__).parent
OUT = EVAL / "corpus-cve"

# id, repo, fix commit, advisory, subdir to stage, source files that carry the bug
SPECS = [
    ("fastjwt-unsigned", "nearform/fast-jwt", "e22a151e83bf6d5e54e281216982d204d5665534", "GHSA-8wpc-h4q6-8fxv", "src", ["src/verifier.js"]),
    ("fastjwt-array", "nearform/fast-jwt", "86e83efd8b5244f50859532d99244f0a9a9a4368", "GHSA-5hjw-83fp-phq9", "src", ["src/decoder.js"]),
    ("fastjwt-jwk", "nearform/fast-jwt", "10f9591349199ed2ab9fa1748ce92cdca697f6cf", "GHSA-g3jj-5cmm-3hxx", "src", ["src/crypto.js"]),
    ("dmcg-protobuf", "datamodel-code-generator/datamodel-code-generator", "5e94b8f4203198798ec66b8e48217f70af69a0dc", "GHSA-77xj-x4rm-935c", "src", ["src/datamodel_code_generator/parser/protobuf.py"]),
    ("mariadb-nobs", "mariadb-corporation/mariadb-connector-nodejs", "6995c8cf8e51b2ad055de63dcaa4094eebbef5ce", "GHSA-r3rv-jm3r-62q2", "lib", ["lib/io/packet-output-stream.js", "lib/misc/utils.js"]),
    ("mariadb-setkey", "mariadb-corporation/mariadb-connector-nodejs", "144b8f4ef29539a9fb4b75d972b9dcdac4088b4e", "GHSA-v6pj-gxxw-phfw", "lib", ["lib/cmd/encoder/text-encoder.js", "lib/misc/utils.js"]),
    ("strawberry-await", "strawberry-graphql/strawberry", "2ebb79796c0e5ebb43cae1abd2b5a21363b1c00e", "GHSA-pfvf-fwfp-25mp", "strawberry", ["strawberry/permission.py"]),
]


def gh(*args):
    return subprocess.run(["gh", "api", *args], capture_output=True, check=True).stdout


def main():
    gold = {}
    for cid, repo, sha, ghsa, sub, files in SPECS:
        dest = OUT / cid
        meta = json.loads(gh(f"repos/{repo}/commits/{sha}"))
        parent = meta["parents"][0]["sha"]
        if not dest.exists():
            tar = tarfile.open(fileobj=io.BytesIO(gh(f"repos/{repo}/tarball/{parent}")), mode="r:gz")
            pre = tar.getmembers()[0].name.split("/")[0] + "/" + sub + "/"
            dest.mkdir(parents=True)
            for m in tar.getmembers():
                if m.name.startswith(pre) and (m.isfile() or m.isdir()):
                    m.name = sub + "/" + m.name[len(pre):]
                    tar.extract(m, dest, filter="data")
        tp = []
        for f in meta["files"]:
            if f["filename"] in files:
                for m in re.finditer(r"^@@ -(\d+)(?:,(\d+))? ", f.get("patch", ""), re.M):
                    start, n = int(m.group(1)), int(m.group(2) or 1)
                    tp.append({"file": f["filename"], "from": start, "to": start + max(n - 1, 0)})
        gold[cid] = {"cls": "cve", "advisory": ghsa, "repo": repo, "parent": parent, "tp": tp}
        size = sum(p.stat().st_size for p in dest.rglob("*") if p.is_file()) // 1024
        print(cid, parent[:10], f"{size}KB", tp)
    (EVAL / "gold-cve.json").write_text(json.dumps(gold, indent=1))


if __name__ == "__main__":
    main()
