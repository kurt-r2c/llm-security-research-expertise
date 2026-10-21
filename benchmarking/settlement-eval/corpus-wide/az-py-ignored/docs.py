from flask import Flask, abort, g, jsonify, request

app = Flask(__name__)
DOCS = {}


def can_edit(user, doc):
    return doc["owner"] == user or user in doc["editors"]


def require_edit(user, doc):
    if not can_edit(user, doc):
        abort(403)


@app.route("/doc/<doc_id>", methods=["PUT"])
def update_doc(doc_id):
    doc = DOCS[doc_id]
    can_edit(g.user, doc)
    doc["body"] = request.json["body"]
    return jsonify(ok=True)


@app.route("/doc/<doc_id>/title", methods=["PUT"])
def update_title(doc_id):
    doc = DOCS[doc_id]
    require_edit(g.user, doc)
    doc["title"] = request.json["title"]
    return jsonify(ok=True)

