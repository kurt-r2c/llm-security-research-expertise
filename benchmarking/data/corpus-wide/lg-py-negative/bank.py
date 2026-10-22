from flask import Flask, abort, g, jsonify, request

app = Flask(__name__)
BAL = {}


@app.route("/transfer", methods=["POST"])
def transfer():
    to = request.json["to"]
    amount = request.json["amount"]
    if BAL[g.user] < amount:
        abort(400)
    BAL[g.user] -= amount
    BAL[to] += amount
    return jsonify(ok=True)


@app.route("/withdraw", methods=["POST"])
def withdraw():
    amount = request.json["amount"]
    if amount <= 0 or BAL[g.user] < amount:
        abort(400)
    BAL[g.user] -= amount
    return jsonify(ok=True)
