import os

import requests

BASE = "https://api.vendor.example/v2"
TOKEN = os.environ["VENDOR_TOKEN"]
MIRROR = os.environ.get("MIRROR_URL")


def get_item(item_id: str):
    return requests.get(f"{BASE}/items/{item_id}", headers={"Authorization": TOKEN}, timeout=5).json()


def list_items():
    return requests.get(f"{BASE}/items", headers={"Authorization": TOKEN}, timeout=5).json()


def refresh_mirror():
    if MIRROR:
        requests.post(MIRROR, json={"refresh": True}, timeout=5)


def download_manifest():
    return requests.get("https://releases.vendor.example/manifest.json", timeout=5).json()
