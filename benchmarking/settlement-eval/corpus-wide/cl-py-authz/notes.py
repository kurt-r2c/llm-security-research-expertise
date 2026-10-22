from flask import Flask, abort, g, jsonify, request

app = Flask(__name__)
NOTES = {}


def can_view(user, note):
    return note["owner"] == user or user in note["shared"]


def require_view(user, note):
    if not can_view(user, note):
        abort(403)


def can_edit(user, note):
    return note["owner"] == user


def require_edit(user, note):
    if not can_edit(user, note):
        abort(403)


@app.route("/n/<nid>")
def read(nid):
    n = NOTES[nid]
    require_view(g.user, n)
    return jsonify(n)


@app.route("/n/<nid>", methods=["PUT"])
def write(nid):
    n = NOTES[nid]
    if not can_edit(g.user, n):
        abort(403)
    n["body"] = request.json["body"]
    return jsonify(ok=True)


@app.route("/n/<nid>/share", methods=["POST"])
def share(nid):
    n = NOTES[nid]
    require_edit(g.user, n)
    n["shared"].append(request.json["user"])
    return jsonify(ok=True)
