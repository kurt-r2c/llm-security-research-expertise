const express = require("express");
const app = express();
app.use(express.json());
app.use((req, res, next) => {
  req.user = req.session.user;
  next();
});

async function authorize(user, action, resource) {
  const grants = await db.grants(user.id, resource.id);
  if (!grants.includes(action)) {
    const err = new Error("forbidden");
    err.status = 403;
    throw err;
  }
}

app.delete("/reports/:id", async (req, res) => {
  const report = await db.reports.get(req.params.id);
  authorize(req.user, "delete", report);
  await db.reports.remove(report.id);
  res.status(204).end();
});

app.put("/reports/:id", async (req, res) => {
  const report = await db.reports.get(req.params.id);
  await authorize(req.user, "write", report);
  await db.reports.update(report.id, req.body);
  res.json({ ok: true });
});

app.listen(3003);
