const express = require("express");
const { convert } = require("./lib/run");

const router = express.Router();

router.post("/thumb", (req, res) => {
  // rempart-expect: CODE-CMD-INJECTION
  convert(req.body.file);
  res.send("ok");
});

module.exports = router;
