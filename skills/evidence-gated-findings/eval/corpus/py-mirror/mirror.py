from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, HTTPException

app = FastAPI()
ALLOWED_SUFFIX = ".example.com"


@app.get("/mirror")
async def mirror(url: str):
    host = urlparse(url).hostname or ""
    if not host.endswith("example.com"):
        raise HTTPException(400, "host not allowed")
    async with httpx.AsyncClient() as c:
        r = await c.get(url)
    return {"len": len(r.text)}


@app.get("/ping")
async def ping():
    async with httpx.AsyncClient() as c:
        r = await c.get("https://example.com/ping")
    return {"ok": r.status_code == 200}
