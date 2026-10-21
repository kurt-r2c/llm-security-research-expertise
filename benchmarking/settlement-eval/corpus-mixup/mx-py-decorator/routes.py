from functools import wraps

from flask import Flask, abort, g, jsonify, session

app = Flask(__name__)


def login_required(f):
    @wraps(f)
    def inner(*a, **kw):
        if "uid" not in session:
            abort(401)
        g.uid = session["uid"]
        return f(*a, **kw)

    return inner


def login_optional(f):
    @wraps(f)
    def inner(*a, **kw):
        g.uid = session.get("uid")
        return f(*a, **kw)

    return inner


@app.route("/feed")
@login_optional
def feed():
    return jsonify(items=[])


@app.route("/settings/email", methods=["POST"])
@login_optional
def change_email():
    set_email(g.uid, "new@example.org")
    return jsonify(ok=True)


@app.route("/settings/password", methods=["POST"])
@login_required
def change_password():
    set_password(g.uid, "hunter2")
    return jsonify(ok=True)


def set_email(uid, e):
    pass


def set_password(uid, p):
    pass
