import requests
from flask import Flask, jsonify, request

from validators import is_http_url, is_safe_url

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    if not is_safe_url(url):
        return jsonify({"error": "blocked"}), 400
    return jsonify({"body": requests.get(url, timeout=5, allow_redirects=False).text[:200]})


@app.route("/fetch2")
def fetch2():
    url = request.args.get("url", "")
    if not is_http_url(url):
        return jsonify({"error": "bad scheme"}), 400
    return jsonify({"body": requests.get(url, timeout=5).text[:200]})
