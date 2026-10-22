const express = require("express");
const axios = require("axios");

const app = express();
app.use(express.json());

const USER_SVC = "http://users.internal:8080";

app.post("/profile/avatar", async (req, res) => {
  const url = req.body.avatarUrl;
  if (typeof url !== "string" || !url.startsWith("https://")) {
    return res.status(400).json({ error: "https only" });
  }
  const img = await axios.get(url, { responseType: "arraybuffer" });
  res.json({ bytes: img.data.length });
});

app.get("/users/:id", async (req, res) => {
  const id = encodeURIComponent(req.params.id);
  const r = await axios.get(`${USER_SVC}/v1/users/${id}`);
  res.json(r.data);
});

app.listen(3000);
