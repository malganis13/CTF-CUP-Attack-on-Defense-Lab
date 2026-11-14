#!/usr/bin/env node
/* archive — сервис полигона A/D. Node 22, только встроенные модули.

Намеренно уязвим:

  SQLi          /api/search?q=     запрос собирается шаблонной строкой
  Traversal     /api/file?name=    fs.readFile(path.join(root, req.query.name))
  Cmd injection /api/export?name=  child_process.exec со строкой из запроса
  JWT           /api/jwt?token=    jwt.decode без проверки подписи
  SSRF          /api/fetch?url=    http.get по адресу из запроса
  Redirect      /api/login?next=   res.redirect(req.query.next)

Слушает 0.0.0.0:8082. Данные — /srv/archive/data, индекс — /srv/archive/index.json.
*/
"use strict";

const http = require("http");
const fs = require("fs");
const path = require("path");
const { exec } = require("child_process");
const { URL } = require("url");

const PORT = 8082;
const ROOT = "/srv/archive";
const DATA = path.join(ROOT, "data");
const INDEX = path.join(ROOT, "index.json");

function readIndex() {
  try { return JSON.parse(fs.readFileSync(INDEX, "utf8")); } catch (_) { return { files: [] }; }
}

function writeIndex(index) {
  fs.writeFileSync(INDEX, JSON.stringify(index, null, 2));
}

/* Эмуляция слоя БД. Настоящая sqlite не нужна: важно, что запрос
   собирается строкой и что кавычка ломает синтаксис ровно так же. */
const db = {
  query(sql) {
    /* Склейка строки: кавычка внутри значения рвёт литерал — ровно то, что
       делает настоящая sqlite. Считаем кавычки: их должно быть ровно две. */
    const quotes = (sql.match(/'/g) || []).length;
    if (quotes !== 2) {
      const error = new Error('SQLITE_ERROR: near "' + String(sql).slice(0, 24) + '": syntax error');
      error.code = "SQLITE_ERROR";
      throw error;
    }
    const literal = /'([^']*)'/.exec(sql);
    const needle = (literal ? literal[1] : "").replace(/%/g, "");
    const files = readIndex().files.filter((entry) => entry.title.includes(needle));
    return files.map((entry) => ({ id: entry.id, title: entry.title }));
  },
};

function send(res, status, body, type) {
  const payload = Buffer.isBuffer(body) ? body : Buffer.from(String(body), "utf8");
  res.writeHead(status, { "Content-Type": type || "text/plain; charset=utf-8", "Content-Length": payload.length });
  res.end(payload);
}

function json(res, status, value) {
  send(res, status, JSON.stringify(value), "application/json; charset=utf-8");
}

function decodeJwt(token) {
  const parts = String(token || "").split(".");
  if (parts.length < 2) throw new Error("malformed token");
  const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  return { header: JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8")), payload, verified: false };
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://archive.local");
  const route = url.pathname;
  const q = url.searchParams;

  if (route === "/health" || route === "/") {
    return json(res, 200, { service: "archive", ok: true, files: readIndex().files.length });
  }

  if (route === "/api/search") {
    const term = q.get("q") || "";
    try {
      const rows = db.query(`SELECT id, title FROM files WHERE title LIKE '%${term}%'`);
      return json(res, 200, { count: rows.length, items: rows });
    } catch (error) {
      return send(res, 500, `${error.code || "Error"}: ${error.message}`);
    }
  }

  if (route === "/api/file") {
    const name = q.get("name") || "readme.txt";
    fs.readFile(path.join(DATA, name), (error, data) => {
      if (error) return send(res, 404, `read error: ${error.code}`);
      send(res, 200, data, "application/octet-stream");
    });
    return;
  }

  if (route === "/api/export") {
    const name = q.get("name") || "bundle";
    exec(`tar -czf /tmp/bundle.tgz -C ${DATA} ${name} 2>&1`, { timeout: 4000 }, (error, stdout, stderr) => {
      send(res, 200, `name=${name}\nstdout=${stdout}\nstderr=${stderr}\nexit=${error ? error.code : 0}\n`);
    });
    return;
  }

  if (route === "/api/jwt") {
    try { return json(res, 200, decodeJwt(q.get("token"))); }
    catch (error) { return send(res, 400, `jwt: ${error.message}`); }
  }

  if (route === "/api/fetch") {
    const target = q.get("url") || "http://127.0.0.1:8082/health";
    try {
      const parsed = new URL(target);
      if (!/^https?:$/.test(parsed.protocol)) return send(res, 400, "bad scheme");
      http.get(target, { timeout: 3000 }, (upstream) => {
        const chunks = [];
        upstream.on("data", (chunk) => chunks.push(chunk));
        upstream.on("end", () => send(res, 200, Buffer.concat(chunks)));
      }).on("error", (error) => send(res, 502, `upstream: ${error.message}`));
    } catch (error) {
      send(res, 400, `bad url: ${error.message}`);
    }
    return;
  }

  if (route === "/api/login") {
    res.writeHead(302, { Location: q.get("next") || "/health" });
    return res.end();
  }

  if (route === "/routes") {
    return json(res, 200, { routes: ["/api/search", "/api/file", "/api/export", "/api/jwt", "/api/fetch", "/api/login"] });
  }

  send(res, 404, "not found");
});

fs.mkdirSync(DATA, { recursive: true });
if (!fs.existsSync(INDEX)) {
  writeIndex({ files: [{ id: 1, title: "release-notes", name: "release.txt" }] });
  fs.writeFileSync(path.join(DATA, "release.txt"), "archive service, build 41\n");
}

server.listen(PORT, "0.0.0.0", () => console.log(`archive listening on ${PORT}`));
