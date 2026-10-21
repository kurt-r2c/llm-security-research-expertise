const express = require("express");
const { execFile } = require("child_process");
const path = require("path");

const app = express();
const ROOT = path.resolve("public");

app.get("/users", async (req, res) => {
  const { rows } = await req.pg.query("SELECT id, name FROM users WHERE org = $1", [req.query.org]);
  res.json(rows);
});

app.get("/file", (req, res) => {
  const p = path.resolve(ROOT, req.query.name);
  if (!p.startsWith(ROOT + path.sep)) return res.status(403).end();
  res.sendFile(p);
});

app.get("/count", (req, res) => {
  execFile("wc", ["-l", "data.csv"], (e, out) => res.send(out));
});

app.listen(3002);
