const express = require("express");
const router = express.Router();

function authorize(user, resource) {
  if (resource.ownerId !== user.id && !user.isAdmin) {
    const e = new Error("forbidden");
    e.status = 403;
    throw e;
  }
}

function authorized(user, resource) {
  return resource.ownerId === user.id || user.isAdmin === true;
}

router.delete("/projects/:id", (req, res) => {
  const project = req.store.projects.get(req.params.id);
  authorized(req.user, project);
  req.store.projects.delete(project.id);
  res.status(204).end();
});

router.put("/projects/:id/name", (req, res) => {
  const project = req.store.projects.get(req.params.id);
  authorize(req.user, project);
  project.name = req.body.name;
  res.json(project);
});

module.exports = router;
