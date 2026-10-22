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
    # second batch, screened from GitHub advisories: fix commit on or after 2026-07-01, one commit, <=2 source files, <=70 lines
    ("ipaddress-ipv6", "beaugunderson/ip-address", "ab3dc88bcf5374344168a2ba075ca7ac4ff257f8", "GHSA-2vr4-cq9g-pvrc", "src", ["src/ipv6.ts"]),
    ("dulwich-stash", "jelmer/dulwich", "40a542cb02f9ac39a9eeac1193472903098698f9", "GHSA-cm62-gvxx-vmxx", "dulwich", ["dulwich/stash.py"]),
    ("fastify-static", "fastify/fastify-static", "db4276f846ba56b21f93768cd6636ee5e2fc58b1", "GHSA-83w8-p2f5-377r", ".", ["index.js"]),
    ("loofah-scrub", "flavorjones/loofah", "20867b9be689521887364b74822c41ef830523c9", "GHSA-9wjq-cp2p-hrgf", "lib", ["lib/loofah/html5/safelist.rb", "lib/loofah/html5/scrub.rb"]),
    ("commonmark-attrs", "thephpleague/commonmark", "dfcdf4554c16aa37c15e3a5ee3243ee26147c239", "GHSA-f8fg-pg57-v4j8", "src", ["src/Extension/Attributes/Util/AttributesHelper.php"]),
    ("pyjwt-jws", "jpadilla/pyjwt", "f91ed44dd65baaf457f4b3353ed35e98a753934c", "GHSA-9j54-fg26-wv3r", "jwt", ["jwt/api_jws.py"]),
    ("pyjwt-algs", "jpadilla/pyjwt", "3cd9ceec33ced359decbad75b413ad668ae6332c", "GHSA-x33g-cr3x-6449", "jwt", ["jwt/algorithms.py"]),
    ("kinopenapi-auth", "getkin/kin-openapi", "f0407d53b0730280266f454b755010e7eeb985da", "GHSA-r277-6w6q-xmqw", "openapi3filter", ["openapi3filter/validation_handler.go"]),
    ("gitpython-submodule", "gitpython-developers/GitPython", "1ed0ebc2f2e74d979cdc367a4864a7731fdcc093", "GHSA-59cr-6r3x-644w", "git", ["git/objects/submodule/base.py"]),
    ("olivetin-api", "OliveTin/OliveTin", "e421780c9885aa5024d2f47b4ed4898f2f18eb90", "GHSA-jm28-2wcr-qf3h", "service", ["service/internal/api/api.go"]),
]

SKIP = re.compile(r"(^|/)(tests?|spec|__tests__|testdata|docs?|examples?|benchmarks?|node_modules|\.github|\.git)(/|$)|\.md$")


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
            top = tar.getmembers()[0].name.split("/")[0]
            pre = top + "/" + (sub + "/" if sub != "." else "")
            dest.mkdir(parents=True)
            for m in tar.getmembers():
                rel = m.name[len(pre):]
                if m.name.startswith(pre) and (m.isfile() or m.isdir()) and not SKIP.search(rel):
                    m.name = (sub + "/" if sub != "." else "") + rel
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
