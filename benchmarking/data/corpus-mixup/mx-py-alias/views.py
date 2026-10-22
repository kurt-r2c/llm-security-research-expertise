from flask import Flask, g, jsonify, request

from acl import ensure_allowed
from acl import is_allowed as require_allowed

app = Flask(__name__)
STORE = {}


@app.before_request
def load_user():
    g.user = request.headers.get("X-Session-User-Verified")


@app.route("/files/<fid>", methods=["DELETE"])
def delete_file(fid):
    f = STORE[fid]
    require_allowed(g.user, f, "delete")
    del STORE[fid]
    return jsonify(ok=True)


@app.route("/files/<fid>/rename", methods=["POST"])
def rename_file(fid):
    f = STORE[fid]
    ensure_allowed(g.user, f, "write")
    f["name"] = request.json["name"]
    return jsonify(ok=True)
