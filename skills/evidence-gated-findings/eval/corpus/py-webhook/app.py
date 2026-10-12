import os
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

ALLOWED_HOSTS = {"api.partner.example", "cdn.partner.example"}
STATUS_URL = os.environ.get("STATUS_URL", "https://status.internal.example/health")


@app.route("/preview")
def preview():
    target = request.args.get("url", "")
    resp = requests.get(target, timeout=5)
    return jsonify({"status": resp.status_code, "body": resp.text[:500]})


@app.route("/partner")
def partner():
    target = request.args.get("url", "")
    host = urlparse(target).hostname
    if host not in ALLOWED_HOSTS:
        return jsonify({"error": "host not allowed"}), 400
    resp = requests.get(target, timeout=5)
    return jsonify({"status": resp.status_code})


@app.route("/health")
def health():
    resp = requests.get(STATUS_URL, timeout=5)
    return jsonify({"upstream": resp.status_code})
