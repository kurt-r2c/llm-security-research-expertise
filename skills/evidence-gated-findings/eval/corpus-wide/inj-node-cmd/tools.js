const { exec, execFile } = require("child_process");
const express = require("express");

const app = express();

app.get("/ping", (req, res) => {
  exec("ping -c 1 " + req.query.host, (err, out) => {
    if (err) {
      return res.status(502).end();
    }
    res.send(out);
  });
});

app.get("/version", (req, res) => {
  execFile("git", ["rev-parse", "HEAD"], (err, out) => {
    if (err) {
      return res.status(500).end();
    }
    res.send(out.trim());
  });
});

app.get("/uptime", (req, res) => {
  exec("uptime", (err, out) => res.send(out));
});

app.listen(3001);
