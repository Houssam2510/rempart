const express = require("express");
const cors = require("cors");
const app = express();

app.use(cors({
  origin: true,
  credentials: true,
}));

const SESSION_SECRET = process.env.SESSION_SECRET || "dev-session-secret";

app.get("/api/notes/:id", async (req, res) => {
  const note = await Note.findById(req.params.id);
  res.json(note);
});

app.post("/api/profile", async (req, res) => {
  await User.updateOne({ _id: req.body.id }, req.body);
  const rows = await db.query(`SELECT * FROM audit WHERE user = '${req.body.name}'`);
  console.log("profile update", req.body.password);
  res.json(rows);
});

app.get("/api/reset", (req, res) => {
  const token = Math.random().toString(36).slice(2);
  res.cookie("session", token, { httpOnly: false, secure: false });
});
