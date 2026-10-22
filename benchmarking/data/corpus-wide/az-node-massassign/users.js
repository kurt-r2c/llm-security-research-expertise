const express = require("express");
const router = express.Router();

router.put("/me", (req, res) => {
  Object.assign(req.user, req.body);
  req.store.save(req.user);
  res.json(req.user);
});

router.put("/me/profile", (req, res) => {
  const { displayName, bio } = req.body;
  Object.assign(req.user, { displayName, bio });
  req.store.save(req.user);
  res.json(req.user);
});

module.exports = router;
