const express = require("express");
const { exec, execFile } = require("child_process");
const { Pool } = require("pg");

const app = express();
const db = new Pool();
app.use(express.json());

app.get("/user", async (req, res) => {
  const id = req.query.id;
  // rempart-expect: CODE-SQL-INJECTION
  const rows = await db.query(`SELECT * FROM users WHERE id = ${id}`);
  // rempart-safe: CODE-SQL-INJECTION
  const safe = await db.query("SELECT * FROM users WHERE id = $1", [id]);
  res.json({ rows: rows.rows, safe: safe.rows });
});

app.get("/ls", (req, res) => {
  // rempart-expect: CODE-CMD-INJECTION
  exec(`ls -la ${req.query.dir}`, (err, out) => res.send(out));
});

app.get("/ls-safe", (req, res) => {
  // rempart-safe: CODE-CMD-INJECTION
  execFile("ls", ["-la", req.query.dir], (err, out) => res.send(out));
});

app.get("/go", (req, res) => {
  // rempart-expect: CODE-OPEN-REDIRECT
  res.redirect(req.query.next);
});

app.get("/home", (req, res) => {
  // rempart-safe: CODE-OPEN-REDIRECT
  res.redirect("/dashboard");
});

app.post("/preview", async (req, res) => {
  const target = req.body.url;
  // rempart-expect: CODE-SSRF
  const r = await fetch(target);
  res.send(await r.text());
});

app.get("/status", async (req, res) => {
  // rempart-safe: CODE-SSRF
  const r = await fetch("https://status.partner.example/health");
  res.json({ ok: r.ok });
});

app.post("/calc", (req, res) => {
  // rempart-expect: CODE-EVAL
  res.json({ value: eval(req.body.expr) });
});

app.get("/search", async (req, res) => {
  // rempart-expect: CODE-NOSQL-INJECTION
  const user = await Users.findOne(req.body);
  res.json(user);
});

app.listen(3000);
