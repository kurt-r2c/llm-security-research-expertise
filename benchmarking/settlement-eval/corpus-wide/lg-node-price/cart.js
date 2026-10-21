const express = require("express");
const router = express.Router();

router.post("/checkout", async (req, res) => {
  const total = req.body.items.reduce((s, i) => s + i.price * i.qty, 0);
  await req.payments.charge(req.user.id, total);
  res.json({ charged: total });
});

router.post("/checkout-v2", async (req, res) => {
  let total = 0;
  for (const i of req.body.items) {
    const p = await req.catalog.price(i.sku);
    total += p * Math.max(1, Math.floor(i.qty));
  }
  await req.payments.charge(req.user.id, total);
  res.json({ charged: total });
});

module.exports = router;
