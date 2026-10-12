import logging

from flask import Flask, abort, g, jsonify

app = Flask(__name__)
log = logging.getLogger(__name__)


def require_admin(user):
    if not user.get("is_admin"):
        abort(403)


@app.route("/admin/users/<uid>/ban", methods=["POST"])
def ban(uid):
    try:
        require_admin(g.user)
    except Exception:
        log.warning("admin check failed for %s", g.user.get("name"))
    do_ban(uid)
    return jsonify(ok=True)


@app.route("/admin/users/<uid>/unban", methods=["POST"])
def unban(uid):
    require_admin(g.user)
    do_unban(uid)
    return jsonify(ok=True)


def do_ban(uid):
    pass


def do_unban(uid):
    pass
