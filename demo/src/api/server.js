// Demo fixture: deliberately vulnerable. Never executed.

const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3");

const app = express();
const db = new sqlite3.Database("/srv/api/api.sqlite3");

app.get("/search", (req, res) => {
  const term = req.query.q;
  db.query(`SELECT id, title FROM notes WHERE title LIKE '%${term}%'`, (err, rows) => {
    if (err) return res.status(500).send(err.message);
    res.json(rows);
  });
});

app.get("/read", (req, res) => {
  fs.readFile(req.query.path, "utf8", (err, data) => {
    if (err) return res.status(404).send("missing");
    res.send(data);
  });
});

app.get("/run", (req, res) => {
  exec("convert " + req.query.name + " /tmp/api.png", (err) => {
    res.json({ ok: !err });
  });
});

app.post("/eval", (req, res) => {
  res.json({ result: eval(req.body.expr) });
});

app.get("/me", (req, res) => {
  const claims = jwt.decode(req.headers.authorization);
  res.json({ claims });
});

app.listen(8086, "0.0.0.0");
