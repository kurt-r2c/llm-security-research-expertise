const express = require("express");
const axios = require("axios");

const pub = express.Router();
const admin = express.Router();

function requireAdmin(req, res, next) {
  if (!req.session || req.session.role !== "admin") return res.status(403).end();
  next();
}

admin.use(requireAdmin);

admin.get("/diagnostics/fetch", async (req, res) => {
  const r = await axios.get(req.query.url);
  res.json({ status: r.status });
});

pub.post("/hooks/test", async (req, res) => {
  const r = await axios.post(req.body.callback, { ping: true });
  res.json({ status: r.status });
});

module.exports = { pub, admin };
