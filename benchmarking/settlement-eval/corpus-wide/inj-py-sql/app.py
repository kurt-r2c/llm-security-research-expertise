import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)
db = sqlite3.connect("shop.db", check_same_thread=False)


@app.route("/search")
def search():
    term = request.args.get("q", "")
    rows = db.execute(f"SELECT id, name FROM products WHERE name LIKE '%{term}%'").fetchall()
    return jsonify(rows)


@app.route("/product/<int:pid>")
def product(pid):
    row = db.execute("SELECT id, name, price FROM products WHERE id = ?", (pid,)).fetchone()
    return jsonify(row)


@app.route("/by-owner")
def by_owner():
    owner = request.args.get("owner", "")
    rows = db.execute("SELECT id, name FROM products WHERE owner = ?", (owner,)).fetchall()
    return jsonify(rows)
