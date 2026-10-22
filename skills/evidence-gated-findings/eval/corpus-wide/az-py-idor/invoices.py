from flask import Flask, abort, g, jsonify

app = Flask(__name__)
INVOICES = {}


@app.route("/invoice/<inv_id>")
def get_invoice(inv_id):
    inv = INVOICES.get(inv_id) or abort(404)
    return jsonify(inv)


@app.route("/my/invoice/<inv_id>")
def get_my_invoice(inv_id):
    inv = INVOICES.get(inv_id) or abort(404)
    if inv["customer"] != g.user["id"]:
        abort(404)
    return jsonify(inv)


@app.route("/my/invoices")
def list_mine():
    return jsonify([i for i in INVOICES.values() if i["customer"] == g.user["id"]])
