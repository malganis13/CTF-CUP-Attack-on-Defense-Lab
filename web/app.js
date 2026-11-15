/* Аудит A/D — клиент. Без зависимостей и сборки. */
"use strict";

const $ = (selector, root) => (root || document).querySelector(selector);
const $$ = (selector, root) => Array.from((root || document).querySelectorAll(selector));

const TITLES = {
  connect: ["Подключение", "укажите хост и пользователя"],
  audit: ["Аудит", "сбор портов, процессов и исходников"],
  services: ["Сервисы", "порты, процессы, стеки"],
  findings: ["Находки", "что нашлось и где именно"],
  files: ["Файлы", "исходники на цели"],
  generator: ["Генератор", "проба и заготовка"],
  report: ["Отчёт", "markdown для команды"],
  traffic: ["Трафик", "доказательство: не флуд"],
  stand: ["Стенд турнира", "сервер, сервисы, команды — схема целиком"],
  map: ["Карта уязвимостей", "класс → файл → строка: что закрыто, что нет"],
  journal: ["Журнал находок", "что было до патча и что стало после"],
  rules: ["Правила сканера", "что находит аудит и как это закрыть"],
  knowledge: ["База знаний", "регламент A/D, патчи, оценка, тренажёр"],
};

const ORDER = ["connect", "audit", "services", "findings", "files", "generator", "report", "traffic", "stand", "map", "journal", "rules", "knowledge"];

// Цифры остались за прежними вкладками: 9 — правила, 0 — база знаний.
// Карта и журнал получили буквы, чтобы не сдвигать привычную навигацию.
const SHORTCUTS = {
  "1": "connect", "2": "audit", "3": "services", "4": "findings", "5": "files",
  "6": "generator", "7": "report", "8": "traffic", "9": "rules", "0": "knowledge",
};

const SEV_ORDER = { high: 0, medium: 1, low: 2, info: 3 };

const VERDICT_RU = {
  signal: "сигнал",
  diff: "отличие",
  clean: "чисто",
  error: "ошибка",
  blocked: "заблокировано",
};

// Вердикт пары «без сессии / с сессией». open — маршрут не различает
// вызывающих, guarded — различает, unknown — сказать нечего.
const AUTH_RU = {
  open: "маршрут не закрыт",
  guarded: "маршрут закрыт",
  unknown: "не определить",
  shared: "объект виден обоим",
  isolated: "объект закрыт владельцем",
  other: "ответил обоим, объекты разные",
  "no-access": "у A нет доступа",
};

const SUMMARY_RU = {
  confirmed: "подтверждено",
  candidate: "кандидат",
  "no signal": "сигналов нет",
  manual: "только вручную",
  blocked: "заблокировано",
};

const state = {
  config: { target: {} },
  demo: false,
  audit: null,
  findings: [],
  filter: { q: "", sev: "", kind: "", conf: "", status: "", review: false },
  sort: "rank",
  map: null,
  journal: null,
  stand: null,
  standSelected: null,
  standEdit: false,
  svcFilter: "",
  liveness: null,
  preflight: null,
  compare: null,
  logUnit: "",
  rulesFilter: "",
  rulesSev: "",
  activeFinding: null,
  activeFile: null,
  probe: null,
  probeResult: null,
  report: null,
  budget: null,
};

/* ---------- утилиты ---------- */

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function esc(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function setStatus(node, text, kind) {
  node.textContent = text || "";
  node.className = "status" + (kind ? " " + kind : "");
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function toast(message, kind) {
  const box = $("#toasts");
  const node = el("div", "toast" + (kind ? " " + kind : ""), message);
  box.appendChild(node);
  setTimeout(() => {
    node.classList.add("out");
    setTimeout(() => node.remove(), 200);
  }, 2800);
}

async function api(path, options) {
  const response = await fetch(path, Object.assign({ headers: { "Content-Type": "application/json" } }, options || {}));
  const text = await response.text();
  let body = null;
  try { body = text ? JSON.parse(text) : null; } catch (_) { body = { raw: text }; }
  if (!response.ok) {
    throw new Error((body && (body.error || body.raw)) || response.statusText);
  }
  return body;
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (_) {
    const area = el("textarea");
    area.value = text;
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(area);
    return ok;
  }
}

function download(name, text) {
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = el("a");
  anchor.href = url;
  anchor.download = name;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

/* ---------- мини-markdown ---------- */

function inline(text) {
  return esc(text)
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
}

function mdToHtml(text) {
  const lines = String(text || "").split("\n");
  const out = [];
  let inCode = false;
  let code = [];
  let inList = false;
  let table = [];

  const flushList = () => { if (inList) { out.push("</ul>"); inList = false; } };
  const flushTable = () => {
    if (!table.length) return;
    const rows = table.filter((row) => !/^\|[\s:|-]+\|$/.test(row));
    const cells = rows.map((row) => row.replace(/^\||\|$/g, "").split("|").map((cell) => cell.trim()));
    if (cells.length) {
      const head = cells.shift();
      out.push("<div class='table-wrap' style='margin:12px 0'><table><thead><tr>" +
        head.map((cell) => `<th>${inline(cell)}</th>`).join("") + "</tr></thead><tbody>" +
        cells.map((row) => "<tr>" + row.map((cell) => `<td>${inline(cell)}</td>`).join("") + "</tr>").join("") +
        "</tbody></table></div>");
    }
    table = [];
  };

  for (const line of lines) {
    if (line.trim().startsWith("```")) {
      if (inCode) { out.push(`<pre class="code" style="margin:10px 0">${esc(code.join("\n"))}</pre>`); code = []; inCode = false; }
      else { flushList(); flushTable(); inCode = true; }
      continue;
    }
    if (inCode) { code.push(line); continue; }
    if (/^\|/.test(line.trim())) { flushList(); table.push(line.trim()); continue; }
    flushTable();
    if (!line.trim()) { flushList(); continue; }
    const heading = /^(#{1,4})\s+(.*)$/.exec(line);
    if (heading) {
      flushList();
      const level = heading[1].length;
      out.push(`<h${level} style="margin:14px 0 6px">${inline(heading[2])}</h${level}>`);
      continue;
    }
    const bullet = /^\s*[-*]\s+(.*)$/.exec(line);
    if (bullet) {
      if (!inList) { out.push("<ul style='margin:8px 0;padding-left:20px'>"); inList = true; }
      out.push(`<li>${inline(bullet[1])}</li>`);
      continue;
    }
    out.push(`<p style="margin:8px 0">${inline(line)}</p>`);
  }
  if (inCode) out.push(`<pre class="code">${esc(code.join("\n"))}</pre>`);
  flushList();
  flushTable();
  return out.join("");
}

/* ---------- навигация ---------- */

function showTab(name, push) {
  if (!TITLES[name]) name = "connect";
  $$("#tabs button").forEach((button) => button.classList.toggle("active", button.dataset.tab === name));
  $$(".panel").forEach((panel) => panel.classList.toggle("active", panel.id === "panel-" + name));
  const [title, sub] = TITLES[name];
  $("#page-title").textContent = title;
  $("#page-sub").textContent = sub;
  if (push !== false && location.hash !== "#" + name) history.replaceState(null, "", "#" + name);
  if (name === "traffic") loadTraffic();
  if (name === "stand") loadStand();
  if (name === "map") loadMap();
  if (name === "journal") loadJournal();
}

$$("#tabs button").forEach((button) => {
  button.addEventListener("click", () => showTab(button.dataset.tab));
});

/* ---------- бюджет ---------- */

function renderBudget(budget) {
  if (budget) state.budget = budget;
  const data = state.budget;
  if (!data) return;
  const used = Math.max(0, Math.min(data.capacity, data.used || 0));
  const percent = Math.round((used / Math.max(1, data.capacity)) * 100);
  $("#budget-text").textContent = `${used}/${data.capacity}`;
  const fill = $("#budget-fill");
  fill.style.width = percent + "%";
  fill.className = "fill" + (percent >= 95 ? " full" : percent >= 60 ? " warn" : "");
}

/* ---------- быстрый старт ---------- */

function renderSteps() {
  const target = state.config.target || {};
  const done = [
    Boolean(target.host && target.user),
    Boolean(state.audit),
    Boolean(state.activeFinding),
    Boolean(state.probeResult),
  ];
  const ids = ["step-connect", "step-audit", "step-finding", "step-probe"];
  let current = -1;
  ids.forEach((id, index) => {
    const node = document.getElementById(id);
    if (!node) return;
    node.classList.toggle("done", done[index]);
    node.classList.toggle("current", false);
    if (current === -1 && !done[index]) current = index;
  });
  if (current >= 0) {
    const node = document.getElementById(ids[current]);
    if (node) node.classList.add("current");
  }
}

function renderBadges() {
  const target = state.config.target || {};
  const connected = Boolean(target.host && target.user);
  $("#chip-target").className = "chip " + (connected ? "on" : "off");
  $("#chip-target-text").textContent = connected ? `${target.user}@${target.host}:${target.port || 22}` : "не подключено";
  $("#chip-demo").hidden = !state.demo;

  const counts = (state.audit && state.audit.counts) || {};
  const chip = $("#chip-audit");
  if (!state.audit) {
    chip.className = "chip off";
    $("#chip-audit-text").textContent = "аудита нет";
  } else {
    chip.className = "chip " + ((counts.high || 0) > 0 ? "demo" : "on");
    $("#chip-audit-text").textContent = `${counts.high || 0} high · ${counts.medium || 0} med`;
  }
  $("#nav-findings").textContent = state.findings.length;
  $("#brand-version").textContent = state.version ? "v" + state.version : "v—";
  renderSteps();
}

/* ---------- подключение ---------- */

function fillForm() {
  const target = state.config.target || {};
  $("#cfg-host").value = target.host || "";
  $("#cfg-port").value = target.port || 22;
  $("#cfg-user").value = target.user || "root";
  $("#cfg-auth").value = target.auth === "password" ? "password" : "key";
  $("#cfg-key").value = target.key_path || "";
  $("#cfg-cookie").value = "";
  $("#cfg-cookie").placeholder = state.config.has_cookie
    ? "кука уже в памяти — введите новую, чтобы заменить"
    : "session=… из браузера";
  $("#cfg-cookie-b").value = "";
  $("#cfg-cookie-b").placeholder = state.config.has_cookie_b
    ? "кука B уже в памяти — введите новую, чтобы заменить"
    : "session=… другого пользователя";
  $("#password-row").hidden = $("#cfg-auth").value !== "password";
}

$("#cfg-auth").addEventListener("change", () => {
  $("#password-row").hidden = $("#cfg-auth").value !== "password";
});

$("#btn-save").addEventListener("click", async () => {
  const status = $("#connect-status");
  try {
    const body = {
      target: {
        host: $("#cfg-host").value.trim(),
        port: Number($("#cfg-port").value) || 22,
        user: $("#cfg-user").value.trim(),
        auth: $("#cfg-auth").value,
        key_path: $("#cfg-key").value.trim(),
      },
    };
    if ($("#cfg-auth").value === "password") body.password = $("#cfg-password").value;
    const cookie = $("#cfg-cookie").value.trim();
    if (cookie) body.probe_cookie = cookie;
    const cookieB = $("#cfg-cookie-b").value.trim();
    if (cookieB) body.probe_cookie_b = cookieB;
    const result = await api("/api/config", { method: "POST", body: JSON.stringify(body) });
    state.config = result.state;
    renderBadges();
    setStatus(status, "сохранено", "ok");
    toast("Цель сохранена", "ok");
  } catch (error) {
    setStatus(status, error.message, "bad");
    toast(error.message, "bad");
  }
});

$("#btn-test").addEventListener("click", async () => {
  const status = $("#connect-status");
  const log = $("#connect-log");
  setStatus(status, "подключаюсь…");
  try {
    const result = await api("/api/test", { method: "POST", body: "{}" });
    log.hidden = false;
    log.textContent = `бэкенд: ${result.backend}\n$ id\n${result.output}`;
    setStatus(status, "связь есть", "ok");
    toast("Связь установлена", "ok");
  } catch (error) {
    log.hidden = false;
    log.textContent = error.message;
    setStatus(status, "не вышло", "bad");
    toast(error.message, "bad");
  }
});

/* ---------- аудит ---------- */

async function pollJob(id, onLog) {
  const started = Date.now();
  for (;;) {
    const job = await api("/api/job?id=" + encodeURIComponent(id));
    if (onLog) onLog(job.log || []);
    if (job.status !== "running") return job;
    if (Date.now() - started > 15 * 60 * 1000) throw new Error("задача не уложилась в 15 минут");
    await sleep(600);
  }
}

$("#btn-audit").addEventListener("click", async () => {
  const button = $("#btn-audit");
  const status = $("#audit-status");
  const log = $("#audit-log");
  const bar = $("#audit-bar");
  button.disabled = true;
  bar.className = "bar running";
  log.textContent = "";
  setStatus(status, "запускаю…");
  try {
    const offline = ($("#audit-path").value || "").trim();
    const started = await api("/api/audit", { method: "POST", body: JSON.stringify(offline ? { path: offline } : {}) });
    const job = await pollJob(started.job, (lines) => {
      log.textContent = lines.join("\n");
      log.scrollTop = log.scrollHeight;
      setStatus(status, "идёт — шагов: " + lines.length);
    });
    if (job.status === "error") throw new Error(job.error || "аудит упал");
    ingest(job.result);
    bar.className = "bar done";
    setStatus(status, "готово", "ok");
    toast(`Аудит готов: ${state.findings.length} находок`, "ok");
    showTab("findings");
  } catch (error) {
    bar.className = "bar error";
    setStatus(status, error.message, "bad");
    toast(error.message, "bad");
  } finally {
    button.disabled = false;
  }
});

function ingest(audit) {
  state.audit = audit;
  state.findings = (audit.findings || []).slice().sort(
    (a, b) =>
      (a.rank ?? (SEV_ORDER[a.severity] ?? 9) * 10) - (b.rank ?? (SEV_ORDER[b.severity] ?? 9) * 10) ||
      (a.file || "").localeCompare(b.file || "") ||
      (a.line || 0) - (b.line || 0)
  );
  renderBadges();
  renderSummary();
  renderServices();
  renderFindings();
  renderConfidence();
  renderKindFilter();
  if (state.activeFinding) setGeneratorFinding(state.activeFinding);
  if ((audit.services || []).length && !state.liveness) {
    checkLiveness(false).catch(() => {});
  }
  state.auditsDone = (state.auditsDone || 0) + 1;
  if (state.auditsDone >= 2) runCompare();
}

function renderSummary() {
  const audit = state.audit;
  if (!audit) return;
  const counts = audit.counts || {};
  $("#audit-summary-card").hidden = false;
  $("#sum-high").textContent = counts.high || 0;
  $("#sum-medium").textContent = counts.medium || 0;
  $("#sum-low").textContent = counts.low || 0;
  $("#sum-info").textContent = counts.info || 0;
  $("#sum-files").textContent = (audit.files || []).length;
  $("#sum-endpoints").textContent = (audit.endpoints || []).length;
  $("#sum-services").textContent = (audit.services || []).length;
  $("#sum-time").textContent = (audit.meta && audit.meta.duration_ms) || 0;

  const langs = $("#audit-langs");
  langs.textContent = "";
  (audit.languages || []).forEach((entry) => {
    langs.appendChild(el("span", "pill", `${entry.language} ×${entry.files}`));
  });
}

$$("#audit-tiles .tile").forEach((tile) => {
  tile.addEventListener("click", () => {
    state.filter.sev = tile.dataset.sev || "";
    setSevChip(state.filter.sev);
    renderFindings();
    showTab("findings");
  });
});

/* ---------- сервисы ---------- */

const LIVE_LABEL = { up: "не лежит", down: "лежит", sick: "ошибки", open: "открыт", local: "loopback", unknown: "?" };

function liveRow(port) {
  const table = (state.liveness && state.liveness.rows) || [];
  return table.find((row) => Number(row.port) === Number(port)) || null;
}

function renderLivenessSummary() {
  const box = $("#svc-live-summary");
  const live = state.liveness;
  if (!box) return;
  if (live && live.error) {
    box.textContent = live.error;
    box.className = "status";
    return;
  }
  if (!live || !live.rows || !live.rows.length) {
    box.textContent = "";
    box.className = "status";
    return;
  }
  const summary = live.summary || {};
  const parts = [];
  if (summary.up) parts.push(`живых ${summary.up}`);
  if (summary.open) parts.push(`открытых ${summary.open}`);
  if (summary.down) parts.push(`лежит ${summary.down}`);
  if (summary.sick) parts.push(`с ошибками ${summary.sick}`);
  if (summary.local) parts.push(`только loopback ${summary.local}`);
  if (summary.unknown) parts.push(`без ответа ${summary.unknown}`);
  box.textContent = parts.join(" · ") + (live.avg_ms != null ? ` · отклик ${live.avg_ms} мс` : "");
  box.className = "status " + (summary.down || summary.sick ? "bad" : "ok");
}

async function checkLiveness(force = true) {
  const button = $("#btn-live");
  if (button) {
    button.disabled = true;
    button.textContent = "проверяю…";
  }
  try {
    state.liveness = await api(`/api/liveness${force ? "?force=1" : ""}`);
    renderServices();
    renderLivenessSummary();
    if (state.liveness.error) {
      if (force) toast(state.liveness.error, "bad");
      return;
    }
    const summary = state.liveness.summary || {};
    if (summary.down) toast(`сервисов лежит: ${summary.down}`, "bad");
    else toast(`все сервисы отвечают${state.liveness.avg_ms != null ? `, отклик ${state.liveness.avg_ms} мс` : ""}`, "ok");
  } catch (error) {
    toast("проверка живости: " + error.message, "bad");
  } finally {
    if (button) {
      button.disabled = false;
      button.textContent = "Проверить живость";
    }
  }
}

function renderServices() {
  const body = $("#services-table tbody");
  body.textContent = "";
  const services = ((state.audit && state.audit.services) || []).filter((service) => {
    const needle = state.svcFilter.trim().toLowerCase();
    if (!needle) return true;
    return `${service.port} ${service.service} ${service.stack} ${service.cwd}`.toLowerCase().includes(needle);
  });
  $("#svc-count").textContent = state.audit ? `${services.length} из ${(state.audit.services || []).length}` : "";
  if (!services.length) {
    const row = el("tr");
    const cell = el("td", "empty", state.audit ? "нет совпадений" : "запустите аудит");
    cell.colSpan = 9;
    row.appendChild(cell);
    body.appendChild(row);
    return;
  }
  services.forEach((service) => {
    const row = el("tr", "clickable");
    row.appendChild(el("td", "cell-mono", service.port));
    row.appendChild(el("td", "cell-mono", service.proto));
    row.appendChild(el("td", "cell-mono", service.service || service.process || "?"));

    const liveCell = el("td");
    const live = liveRow(service.port);
    if (live) {
      const chip = el("span", `live-lamp ${live.state}`, LIVE_LABEL[live.state] || live.state);
      chip.title = live.note || "";
      liveCell.appendChild(chip);
      if (live.ms != null) {
        const ms = el("span", "live-ms", `${live.ms} мс`);
        liveCell.appendChild(ms);
      }
    } else {
      liveCell.className = "empty";
      liveCell.textContent = "—";
    }
    row.appendChild(liveCell);

    const stackCell = el("td");
    if (service.stack) stackCell.appendChild(el("span", "pill", service.stack));
    else { stackCell.textContent = "—"; stackCell.className = "empty"; }
    row.appendChild(stackCell);
    row.appendChild(el("td", "cell-mono", service.pid ?? "—"));
    row.appendChild(el("td", "cell-mono", service.cwd || "—"));
    const cmd = el("td", "cell-mono", service.cmdline || "—");
    cmd.style.maxWidth = "380px";
    cmd.style.overflow = "hidden";
    cmd.style.textOverflow = "ellipsis";
    cmd.style.whiteSpace = "nowrap";
    row.appendChild(cmd);
    const logCell = el("td");
    const logButton = el("button", "ghost small", "логи");
    logButton.title = "journalctl по юниту сервиса";
    logButton.addEventListener("click", (event) => {
      event.stopPropagation();
      const name = (service.service || "").replace(/:$/, "");
      $("#log-unit").value = name ? `${name}.service` : "";
      openLog($("#log-unit").value);
    });
    logCell.appendChild(logButton);
    row.appendChild(logCell);
    if (service.cwd) {
      row.title = "открыть каталог";
      row.addEventListener("click", () => {
        showTab("files");
        $("#path-input").value = service.cwd;
        listPath(service.cwd);
      });
    }
    body.appendChild(row);
  });
  renderLivenessSummary();
  makeSortable($("#services-table"));
}

$("#svc-search").addEventListener("input", (event) => {
  state.svcFilter = event.target.value;
  renderServices();
});

$("#btn-live").addEventListener("click", () => checkLiveness(true));

/* ---------- журнал юнита ---------- */

async function openLog(unit) {
  const drawer = $("#log-drawer");
  drawer.hidden = false;
  if (unit) $("#log-unit").value = unit;
  await refreshLog();
}

async function refreshLog() {
  const unit = ($("#log-unit").value || "").trim();
  const status = $("#log-status");
  const text = $("#log-text");
  if (!unit) {
    setStatus(status, "укажите юнит", "bad");
    return;
  }
  setStatus(status, "читаю…");
  try {
    const answer = await api(`/api/logs?unit=${encodeURIComponent(unit)}&lines=120`);
    $("#log-title").textContent = unit;
    text.textContent = answer.text || "пусто";
    text.scrollTop = text.scrollHeight;
    setStatus(status, answer.empty ? "журнал пуст" : `${answer.lines} строк`, answer.empty ? "bad" : "ok");
  } catch (error) {
    setStatus(status, error.message, "bad");
    text.textContent = "";
  }
}

$("#log-refresh").addEventListener("click", refreshLog);
$("#log-close").addEventListener("click", () => { $("#log-drawer").hidden = true; });
$("#log-unit").addEventListener("keydown", (event) => {
  if (event.key === "Enter") refreshLog();
});

/* ---------- проверка перед игрой ---------- */

const PREFLIGHT_LABEL = { ok: "ок", warn: "внимание", fail: "стоп" };

function renderPreflight() {
  const result = state.preflight;
  const wrap = $("#preflight-wrap");
  const empty = $("#preflight-empty");
  const verdict = $("#preflight-verdict");
  if (!result) return;
  const body = $("#preflight-table tbody");
  body.textContent = "";
  (result.rows || []).forEach((row) => {
    const tr = el("tr");
    tr.appendChild(el("td", "cell-mono", row.title));
    const stateCell = el("td");
    stateCell.appendChild(el("span", `pf-chip ${row.status}`, PREFLIGHT_LABEL[row.status] || row.status));
    tr.appendChild(stateCell);
    tr.appendChild(el("td", "cell-mono", row.value || "—"));
    tr.appendChild(el("td", "pf-hint", row.hint || "—"));
    body.appendChild(tr);
  });
  wrap.hidden = false;
  empty.hidden = true;
  const summary = result.summary || {};
  const parts = [];
  if (summary.ok) parts.push(`ок ${summary.ok}`);
  if (summary.warn) parts.push(`внимание ${summary.warn}`);
  if (summary.fail) parts.push(`стоп ${summary.fail}`);
  setStatus(verdict, parts.join(" · "), summary.fail ? "bad" : summary.warn ? "warn" : "ok");
}

async function runPreflight() {
  const button = $("#btn-preflight");
  button.disabled = true;
  button.textContent = "проверяю…";
  try {
    state.preflight = await api("/api/preflight", { method: "POST", body: "{}" });
    renderPreflight();
    const summary = state.preflight.summary || {};
    if (summary.fail) toast(`проверка: ${summary.fail} стоп-пунктов`, "bad");
    else if (summary.warn) toast(`проверка: ${summary.warn} замечаний`, "warn");
    else toast("проверка чистая: можно играть", "ok");
  } catch (error) {
    toast("проверка не прошла: " + error.message, "bad");
  } finally {
    button.disabled = false;
    button.textContent = "Проверить всё";
  }
}

$("#btn-preflight").addEventListener("click", runPreflight);

/* ---------- что изменилось после патча ---------- */

function renderCompare() {
  const card = $("#compare-card");
  const body = $("#compare-body");
  const data = state.compare;
  if (!data) return;
  card.hidden = false;
  body.textContent = "";
  if (!data.available) {
    $("#compare-lead").textContent = data.reason || "нет данных";
    return;
  }
  $("#compare-lead").textContent =
    `${data.before.count} → ${data.after.count} находок · закрылось ${data.closed.length}, появилось ${data.appeared.length}`;

  const column = (title, rows, kind) => {
    const box = el("div", "cmp-col");
    box.appendChild(el("b", "cmp-head", `${title} (${rows.length})`));
    if (!rows.length) {
      box.appendChild(el("div", "empty", "—"));
      return box;
    }
    rows.forEach((row) => {
      const line = el("div", `cmp-row ${kind}`);
      line.appendChild(el("span", "pill", row.rule));
      line.appendChild(el("span", "cmp-file", `${(row.file || "").split("/").pop()}:${row.line}`));
      line.title = row.file;
      box.appendChild(line);
    });
    return box;
  };
  body.appendChild(column("закрылось", data.closed, "good"));
  body.appendChild(column("появилось", data.appeared, "bad"));
}

async function runCompare() {
  try {
    state.compare = await api("/api/compare");
    renderCompare();
    if (!state.compare.available) toast(state.compare.reason || "нужны два аудита", "warn");
  } catch (error) {
    toast("сравнение: " + error.message, "bad");
  }
}

$("#btn-compare").addEventListener("click", runCompare);

/* ---------- таймер раунда ---------- */

const ROUND_KEY = "ad-audit.round";

function roundState() {
  try {
    return JSON.parse(localStorage.getItem(ROUND_KEY) || "null");
  } catch (_) {
    return null;
  }
}

function tickRound() {
  const info = roundState();
  const left = $("#round-left");
  const fill = $("#round-fill");
  const box = $("#round-box");
  if (!info || !info.period) {
    left.textContent = "—";
    fill.style.width = "0%";
    box.classList.remove("low", "over");
    return;
  }
  const now = Date.now();
  const passed = (now - info.startedAt) % info.period;
  const remain = info.period - passed;
  const seconds = Math.ceil(remain / 1000);
  left.textContent = `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
  fill.style.width = `${Math.round((remain / info.period) * 100)}%`;
  box.classList.toggle("low", seconds <= 10);
  box.classList.toggle("over", seconds <= 3);
}

$("#btn-round").addEventListener("click", () => {
  const current = roundState();
  if (current && current.period) {
    localStorage.removeItem(ROUND_KEY);
    $("#btn-round").textContent = "старт раунда";
    toast("таймер раунда снят", "warn");
  } else {
    const raw = window.prompt("Длительность раунда, секунд", "60");
    const period = Math.max(15, Math.min(3600, Number(raw) || 60)) * 1000;
    localStorage.setItem(ROUND_KEY, JSON.stringify({ period, startedAt: Date.now() }));
    $("#btn-round").textContent = "снять таймер";
    toast(`раунд ${period / 1000} с: патч до последних 10 секунд`, "ok");
  }
  tickRound();
});

setInterval(tickRound, 250);
tickRound();
if (roundState() && roundState().period) $("#btn-round").textContent = "снять таймер";

/* ---------- находки ---------- */

function renderKindFilter() {
  const select = $("#f-kind");
  const current = select.value;
  select.textContent = "";
  select.appendChild(new Option("все классы", ""));
  const kinds = Array.from(new Set(state.findings.map((item) => item.kind))).sort();
  const labels = {};
  state.findings.forEach((item) => { labels[item.kind] = item.kind_ru || item.kind; });
  kinds.forEach((kind) => select.appendChild(new Option(labels[kind] || kind, kind)));
  select.value = kinds.includes(current) ? current : "";
  state.filter.kind = select.value;
}

function setSevChip(sev) {
  $$("#sev-chips .sev-chip").forEach((chip) => chip.classList.toggle("active", chip.dataset.sev === sev));
}

function visibleFindings() {
  const { q, sev, kind, conf, status, review } = state.filter;
  const needle = q.trim().toLowerCase();
  const items = state.findings.filter((item) => {
    if (sev && item.severity !== sev) return false;
    if (kind && item.kind !== kind) return false;
    if (conf && ((item.confidence || {}).level || "unsure") !== conf) return false;
    if (status && (item.status || "open") !== status) return false;
    if (review && !item.review) return false;
    if (!needle) return true;
    return `${item.kind} ${item.kind_ru || ""} ${item.file} ${item.snippet} ${item.rule} ${item.language}`
      .toLowerCase().includes(needle);
  });
  return sortFindings(items);
}

function sortFindings(items) {
  const score = (item) => ((item.confidence || {}).score ?? 50);
  const sev = (item) => SEV_ORDER[item.severity] ?? 9;
  const list = items.slice();
  switch (state.sort) {
    case "severity":
      list.sort((a, b) => sev(a) - sev(b) || (a.file || "").localeCompare(b.file || ""));
      break;
    case "severity-asc":
      list.sort((a, b) => sev(b) - sev(a) || (a.file || "").localeCompare(b.file || ""));
      break;
    case "confidence":
      list.sort((a, b) => score(b) - score(a) || sev(a) - sev(b));
      break;
    case "confidence-desc":
      list.sort((a, b) => score(a) - score(b) || sev(a) - sev(b));
      break;
    case "file":
      list.sort((a, b) => (a.file || "").localeCompare(b.file || "") || (a.line || 0) - (b.line || 0));
      break;
    case "line":
      list.sort((a, b) => (a.line || 0) - (b.line || 0));
      break;
    default:
      list.sort((a, b) =>
        (a.rank ?? sev(a) * 10) - (b.rank ?? sev(b) * 10) ||
        (a.file || "").localeCompare(b.file || "") ||
        (a.line || 0) - (b.line || 0));
  }
  return list;
}

function confPill(finding) {
  const level = (finding.confidence || {}).level || "unsure";
  const label = { certain: "уверен", likely: "скорее да", unsure: "не уверен" }[level] || level;
  return el("span", "pill conf-" + level, label);
}

// Сводка по уверенности над списком: три счётчика и доля «не уверен».
// Карточки кликабельны — фильтруют список тем же полем, что и чипы.
function renderConfidence() {
  const box = $("#conf-summary");
  if (!box) return;
  box.textContent = "";
  const levels = [
    ["certain", "уверен", "опасный вызов с видимым входом"],
    ["likely", "скорее да", "решает контекст и права"],
    ["unsure", "не уверен", "совпадение по форме"],
  ];
  levels.forEach(([level, label, hint]) => {
    const count = state.findings.filter(
      (item) => ((item.confidence || {}).level || "unsure") === level
    ).length;
    const card = el("div", "conf-card " + level);
    if (state.filter.conf === level) card.classList.add("active");
    card.appendChild(el("span", "n", String(count)));
    const text = el("div");
    text.appendChild(el("div", "l", label));
    text.appendChild(el("div", "l", hint));
    card.appendChild(text);
    card.title = `показать только «${label}»`;
    card.addEventListener("click", () => {
      state.filter.conf = state.filter.conf === level ? "" : level;
      $$("#conf-chips .conf-chip").forEach(
        (chip) => chip.classList.toggle("active", (chip.dataset.conf || "") === state.filter.conf)
      );
      renderConfidence();
      renderFindings();
    });
    box.appendChild(card);
  });
  const summary = (state.audit && state.audit.confidence) || {};
  if (state.findings.length && typeof summary.share_unsure === "number") {
    const note = el("div", "conf-card");
    note.style.cursor = "default";
    note.appendChild(el("span", "n", summary.share_unsure + "%"));
    const text = el("div");
    text.appendChild(el("div", "l", "доля «не уверен»"));
    text.appendChild(el("div", "l", "их читают глазами"));
    note.appendChild(text);
    box.appendChild(note);
  }
  const reviewCount = state.findings.filter((item) => item.review).length;
  const reviewCard = el("div", "conf-card review");
  if (state.filter.review) reviewCard.classList.add("active");
  reviewCard.appendChild(el("span", "n", String(reviewCount)));
  const reviewText = el("div");
  reviewText.appendChild(el("div", "l", "проверить"));
  reviewText.appendChild(el("div", "l", "поток и ветки, не шаблон"));
  reviewCard.appendChild(reviewText);
  reviewCard.title = "показать только находки, которые нужно проверить руками";
  reviewCard.addEventListener("click", toggleReview);
  box.appendChild(reviewCard);

  const button = $("#btn-review");
  if (button) {
    button.textContent = "проверить: " + reviewCount;
    button.classList.toggle("active", !!state.filter.review);
  }
}

function toggleReview() {
  state.filter.review = !state.filter.review;
  renderConfidence();
  renderFindings();
}

function statusPill(finding) {
  const status = finding.status || "open";
  const label = { open: "открыта", fixed: "закрыта", regressed: "вернулась", ignored: "игнор" }[status] || status;
  return el("span", "pill st-" + status, label);
}

function renderFindings() {
  const list = $("#findings-list");
  list.textContent = "";
  const items = visibleFindings();
  $("#f-count").textContent = `${items.length} из ${state.findings.length}`;
  if (!items.length) {
    list.appendChild(el("div", "empty", state.findings.length ? "нет совпадений — сбросьте фильтры" : "запустите аудит"));
    return;
  }
  items.forEach((finding) => {
    const item = el("div", "item");
    item.dataset.id = finding.id;
    if (state.activeFinding && state.activeFinding.id === finding.id) item.classList.add("active");
    item.appendChild(el("span", "pill " + finding.severity, finding.severity));
    item.appendChild(confPill(finding));
    if (finding.review) item.appendChild(el("span", "pill review", "проверить"));
    const body = el("div", "body");
    body.appendChild(el("b", null, finding.kind_ru || finding.kind));
    const meta = `${finding.file}:${finding.line}` + (finding.effort_ru ? ` · ${finding.effort_ru}` : "") + (finding.template ? " · шаблон" : "");
    body.appendChild(el("small", null, meta));
    item.appendChild(body);
    const status = finding.status || "open";
    if (status !== "open") item.appendChild(statusPill(finding));
    item.addEventListener("click", () => selectFinding(finding));
    list.appendChild(item);
  });
}

function selectFinding(finding) {
  state.activeFinding = finding;
  $$("#findings-list .item").forEach((node) => node.classList.toggle("active", node.dataset.id === finding.id));
  renderFindingDetail(finding);
  setGeneratorFinding(finding);
  renderSteps();
}

async function loadFix(finding, holder) {
  try {
    const result = await api("/api/fix?id=" + encodeURIComponent(finding.id));
    const fix = result.fix || {};
    holder.textContent = "";
    if (!fix.available) {
      const list = el("ol", "fix-steps");
      (fix.steps || []).forEach((step) => list.appendChild(el("li", null, step)));
      holder.appendChild(el("p", "fix-title", fix.title || "общий порядок"));
      holder.appendChild(list);
      return;
    }
    const head = el("div", "row tight");
    head.appendChild(el("b", "fix-title", fix.title));
    head.appendChild(el("span", "pill " + (fix.risk === "high" ? "high" : fix.risk === "medium" ? "medium" : "low"),
      "риск для раунда: " + (fix.risk === "high" ? "высокий" : fix.risk === "medium" ? "средний" : "низкий")));
    holder.appendChild(head);

    const code = el("div", "fix-code");
    (fix.before || []).forEach((line) => code.appendChild(el("div", "fix-line minus", "- " + line)));
    (fix.after || []).forEach((line) => code.appendChild(el("div", "fix-line plus", "+ " + line)));
    holder.appendChild(code);

    const copy = el("button", "ghost small", "Копировать безопасный вариант");
    copy.addEventListener("click", async () => {
      await copyText((fix.after || []).join("\n"));
      toast("Код скопирован", "ok");
    });
    holder.appendChild(copy);

    if (result.diff) {
      const download = el("button", "ghost small", "Скачать .patch");
      download.addEventListener("click", () => {
        const blob = new Blob([result.diff], { type: "text/x-diff" });
        const link = document.createElement("a");
        link.href = URL.createObjectURL(blob);
        link.download = result.diff_name || "finding.patch";
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        setTimeout(() => URL.revokeObjectURL(link.href), 4000);
        toast("Патч скачан", "ok");
      });
      download.title = "unified diff: git apply или patch -p1, применяет человек";
      holder.appendChild(download);
      holder.appendChild(el("div", "hint", "патч не применяется сам — только файл для git apply / patch -p1"));
    } else if (fix.available && fix.exact === false) {
      holder.appendChild(el("div", "hint",
        `патч не собран: рецепт для ${fix.sample_label}, а файл — ${fix.language_label}. ` +
        "Переноси смысл руками, готовый diff был бы чужой язык в этом файле."));
    }

    holder.appendChild(el("h4", null, "порядок"));
    const steps = el("ol", "fix-steps");
    (fix.steps || []).forEach((step) => steps.appendChild(el("li", null, step)));
    holder.appendChild(steps);

    if (fix.breaks) {
      const warn = el("div", "fix-breaks");
      warn.appendChild(el("b", null, "что может отвалиться: "));
      warn.appendChild(document.createTextNode(fix.breaks));
      holder.appendChild(warn);
    }
  } catch (error) {
    holder.textContent = "патч не загрузился: " + error.message;
  }
}

function renderFindingDetail(finding) {
  const detail = $("#finding-detail");
  detail.textContent = "";

  const head = el("div", "head");
  head.appendChild(el("h3", null, finding.kind_ru || finding.kind));
  head.appendChild(el("div", "loc", `${finding.file}:${finding.line} · правило ${finding.rule} · ${finding.language || "text"}`));
  const chips = el("div", "row tight");
  chips.appendChild(el("span", "pill " + finding.severity, finding.severity));
  if (finding.review) chips.appendChild(el("span", "pill review", "проверить"));
  chips.appendChild(el("span", "pill soft", "риск для чекера: " + (finding.checker_risk || "low")));
  if (finding.effort_ru) chips.appendChild(el("span", "pill soft", finding.effort_ru));
  if (finding.template) chips.appendChild(el("span", "pill soft", "шаблонный эксплойт"));
  head.appendChild(chips);
  detail.appendChild(head);

  const body = el("div", "body");

  const conf = finding.confidence || {};
  const confBlock = el("div", "conf-block");
  const confHead = el("div", "row tight");
  confHead.appendChild(el("h3", null, "уверенность: " + (conf.level_ru || "не уверен")));
  confHead.appendChild(confPill(finding));
  confHead.appendChild(statusPill(finding));
  confBlock.appendChild(confHead);
  confBlock.appendChild(el("div", "why", conf.hint || ""));
  if ((conf.plan || []).length) {
    confBlock.appendChild(el("h3", null, "план проверки"));
    const steps = el("ol");
    conf.plan.forEach((step) => steps.appendChild(el("li", null, step)));
    confBlock.appendChild(steps);
  }
  if ((conf.disproof || []).length) {
    confBlock.appendChild(el("h3", null, "что закроет находку"));
    const list = el("ul");
    conf.disproof.forEach((item) => list.appendChild(el("li", null, item)));
    confBlock.appendChild(list);
  }
  if ((conf.reasons || []).length) {
    confBlock.appendChild(el("div", "why", "почему такая оценка: " + conf.reasons.join("; ")));
  }
  const statusRow = el("div", "row tight");
  [["open", "вернуть в работу"], ["fixed", "закрыта"], ["ignored", "игнорировать"], ["regressed", "вернулась"]]
    .forEach(([value, label]) => {
      const button = el("button", "ghost small", label);
      button.addEventListener("click", () => setFindingStatus(finding, value));
      statusRow.appendChild(button);
    });
  confBlock.appendChild(statusRow);
  body.appendChild(confBlock);

  if (finding.review) {
    const note = el("div", "review-note");
    note.appendChild(el("h3", null, "проверить: это не шаблонное совпадение"));
    note.appendChild(el("p", null,
      "Находка получена разбором потока значений или порядка веток. Одна строка её "
      + "не подтверждает: рядом может стоять проверка, которой не видно в шаблоне. "
      + "Прочитайте план, отправьте одну пробу и только потом считайте это дырой."));
    body.appendChild(note);
  }

  const why = el("div", "block");
  why.appendChild(el("h4", null, "почему сработало"));
  why.appendChild(el("p", null, finding.why));
  body.appendChild(why);

  const patch = el("div", "block");
  patch.appendChild(el("h4", null, "как чинить"));
  patch.appendChild(el("p", null, finding.patch));
  body.appendChild(patch);

  const fixBlock = el("div", "block");
  fixBlock.appendChild(el("h4", null, "как закрыть · код"));
  const fixHolder = el("div", "fix-holder", "загружаю…");
  fixBlock.appendChild(fixHolder);
  body.appendChild(fixBlock);
  loadFix(finding, fixHolder);

  const ctx = el("div", "block");
  ctx.appendChild(el("h4", null, "контекст"));
  const box = el("div", "ctx");
  const start = finding.context_start || Math.max(1, finding.line - (finding.context ? finding.context.length : 1) + 1);
  (finding.context || []).forEach((line, index) => {
    const number = start + index;
    const mark = number === finding.line ? `mark ${finding.severity}` : "";
    box.appendChild(el("div", mark, `${String(number).padStart(4)}  ${line}`));
  });
  ctx.appendChild(box);
  body.appendChild(ctx);

  const actions = el("div", "row");
  const generate = el("button", "primary small", "В генератор");
  generate.addEventListener("click", () => { showTab("generator"); });
  actions.appendChild(generate);
  const open = el("button", "ghost small", "Открыть файл");
  open.addEventListener("click", () => {
    showTab("files");
    readFile(finding.file);
  });
  actions.appendChild(open);
  body.appendChild(actions);

  detail.appendChild(body);
}

$("#f-search").addEventListener("input", (event) => {
  state.filter.q = event.target.value;
  renderFindings();
});
$("#f-kind").addEventListener("change", (event) => {
  state.filter.kind = event.target.value;
  renderFindings();
});
$$("#sev-chips .sev-chip").forEach((chip) => {
  chip.addEventListener("click", () => {
    state.filter.sev = chip.dataset.sev || "";
    setSevChip(state.filter.sev);
    renderFindings();
  });
});
$$("#conf-chips .conf-chip").forEach((chip) => {
  chip.addEventListener("click", () => {
    state.filter.conf = chip.dataset.conf || "";
    $$("#conf-chips .conf-chip").forEach((node) => node.classList.toggle("active", node === chip));
    renderConfidence();
    renderFindings();
  });
});
$$("#status-chips .status-chip").forEach((chip) => {
  chip.addEventListener("click", () => {
    state.filter.status = chip.dataset.status || "";
    $$("#status-chips .status-chip").forEach((node) => node.classList.toggle("active", node === chip));
    renderFindings();
  });
});
$("#btn-review").addEventListener("click", toggleReview);
$("#f-sort").addEventListener("change", (event) => {
  state.sort = event.target.value;
  renderFindings();
});

async function setFindingStatus(finding, status) {
  try {
    await api("/api/status", {
      method: "POST",
      body: JSON.stringify({ fingerprint: finding.fingerprint, status }),
    });
    finding.status = status;
    const stored = state.findings.find((item) => item.fingerprint === finding.fingerprint);
    if (stored) stored.status = status;
    renderFindings();
    if (state.activeFinding) renderFindingDetail(state.activeFinding);
    if (state.journal) loadJournal();
    toast("статус: " + status, "ok");
  } catch (error) {
    toast(error.message, "bad");
  }
}

/* ---------- карта ---------- */

async function loadMap() {
  const status = $("#map-status");
  setStatus(status, "читаю карту…");
  try {
    state.map = await api("/api/map");
    renderMap();
    setStatus(status, "");
  } catch (error) {
    setStatus(status, error.message, "bad");
  }
}

function mapFilters() {
  return {
    q: $("#map-search").value.trim().toLowerCase(),
    openOnly: $("#map-open-only").checked,
    certain: $("#map-certain").checked,
    hideClosed: $("#map-unresolved").checked,
  };
}

function renderMap() {
  const holder = $("#map-body");
  holder.textContent = "";
  const map = state.map;
  if (!map || !(map.nodes || []).length) {
    holder.appendChild(el("div", "empty", (map && map.reason) || "сначала аудит"));
    return;
  }
  const filters = mapFilters();
  let shown = 0;
  map.nodes.forEach((node) => {
    const files = node.files
      .map((file) => ({
        ...file,
        findings: file.findings.filter((finding) => {
          if (filters.openOnly && finding.status !== "open" && finding.status !== "regressed") return false;
          if (filters.certain && finding.confidence !== "certain") return false;
          if (filters.hideClosed && (finding.status === "fixed" || finding.status === "ignored")) return false;
          if (filters.q) {
            const hay = `${node.kind_ru} ${file.file} ${finding.rule} ${finding.snippet}`.toLowerCase();
            if (!hay.includes(filters.q)) return false;
          }
          return true;
        }),
      }))
      .filter((file) => file.findings.length);
    if (!files.length) return;
    const total = files.reduce((sum, file) => sum + file.findings.length, 0);
    shown += total;

    const card = el("div", "map-node");
    const head = el("div", "map-head");
    head.appendChild(el("span", "dot " + node.severity));
    head.appendChild(el("span", "title", node.kind_ru));
    head.appendChild(el("span", "count", `${total}`));
    const state1 = el("span", "count", "открыто: " + (node.status.open || 0));
    head.appendChild(state1);
    if (node.status.fixed) head.appendChild(el("span", "count", "закрыто: " + node.status.fixed));
    if (node.review) head.appendChild(el("span", "count review", "проверить: " + node.review));
    card.appendChild(head);

    const bodyBox = el("div", "map-files");
    bodyBox.hidden = false;
    files.forEach((file) => {
      const fileRow = el("div", "map-file");
      fileRow.appendChild(el("span", "dot " + file.severity));
      fileRow.appendChild(el("span", "path", file.file));
      fileRow.appendChild(el("span", "count", String(file.findings.length)));
      bodyBox.appendChild(fileRow);
      const rows = el("div");
      rows.hidden = true;
      file.findings.forEach((finding) => {
        const row = el("div", "map-row");
        row.appendChild(el("span", "line", ":" + (finding.line || 0)));
        row.appendChild(el("span", "dot " + finding.severity));
        row.appendChild(confPill(finding));
        if (finding.review) row.appendChild(el("span", "pill review", "проверить"));
        row.appendChild(el("span", "snip", finding.snippet || finding.rule));
        if (finding.status !== "open") row.appendChild(statusPill(finding));
        row.addEventListener("click", () => {
          const full = state.findings.find((item) => item.id === finding.id);
          if (full) {
            selectFinding(full);
            showTab("findings");
          }
        });
        rows.appendChild(row);
      });
      bodyBox.appendChild(rows);
      fileRow.addEventListener("click", () => {
        rows.hidden = !rows.hidden;
      });
    });
    card.appendChild(bodyBox);
    head.addEventListener("click", () => {
      bodyBox.hidden = !bodyBox.hidden;
    });
    holder.appendChild(card);
  });
  if (!shown) holder.appendChild(el("div", "empty", "под фильтры ничего не попалось"));
}

/* ---------- журнал ---------- */

async function loadJournal() {
  const status = $("#journal-status");
  setStatus(status, "читаю журнал…");
  try {
    const data = await api("/api/journal");
    state.journal = data;
    renderJournal();
    setStatus(status, "");
  } catch (error) {
    setStatus(status, error.message, "bad");
  }
}

function renderJournal() {
  const data = state.journal;
  if (!data) return;
  const summary = data.summary || {};
  const stats = $("#journal-stats");
  stats.textContent = "";
  const block = (value, label) => {
    const item = el("div", "journal-stat");
    item.appendChild(el("div", "n", String(value)));
    item.appendChild(el("div", "l", label));
    return item;
  };
  stats.appendChild(block(summary.total || 0, "всего в базе"));
  stats.appendChild(block(summary.open || 0, "открыто"));
  stats.appendChild(block(summary.resolved || 0, "закрыто"));
  stats.appendChild(block(summary.regressed || (summary.by_status || {}).regressed || 0, "вернулось"));
  stats.appendChild(block(summary.ignored || 0, "игнор"));
  stats.appendChild(block((summary.share_closed || 0) + "%", "доля закрытых"));

  const runs = $("#journal-runs");
  runs.textContent = "";
  const runList = data.runs || [];
  if (!runList.length) runs.appendChild(el("div", "empty", "журнал пуст: нужен хотя бы один аудит"));
  runList.forEach((run) => {
    const item = el("div", "item");
    item.appendChild(el("span", "pill soft", new Date(run.at * 1000).toLocaleTimeString()));
    const body = el("div", "body");
    body.appendChild(el("b", null, `${run.total} находок · высоких ${run.high}`));
    body.appendChild(el("small", null, `${run.target || "—"} · закрыто в прогоне: ${run.closed_in_run || 0}`));
    item.appendChild(body);
    runs.appendChild(item);
  });

  const before = $("#journal-before");
  const after = $("#journal-after");
  before.textContent = "";
  after.textContent = "";
  runList.forEach((run) => {
    const label = `${new Date(run.at * 1000).toLocaleString()} · ${run.total}`;
    before.appendChild(new Option(label, String(run.id)));
    after.appendChild(new Option(label, String(run.id)));
  });
  if (runList.length >= 2) {
    before.value = String(runList[1].id);
    after.value = String(runList[0].id);
  } else if (runList.length === 1) {
    before.value = String(runList[0].id);
    after.value = String(runList[0].id);
  }

  const table = $("#journal-table tbody");
  table.textContent = "";
  const findings = data.findings || [];
  if (!findings.length) {
    const row = el("tr");
    const cell = el("td", "empty", "пока пусто");
    cell.colSpan = 7;
    row.appendChild(cell);
    table.appendChild(row);
  }
  findings.forEach((finding) => {
    const row = el("tr");
    const ruleCell = el("td", "cell-mono");
    ruleCell.appendChild(el("span", null, finding.rule));
    if ((finding.rule || "").startsWith("flow-")) {
      ruleCell.appendChild(el("span", "pill review", "проверить"));
    }
    row.appendChild(ruleCell);
    row.appendChild(el("td", null, finding.kind));
    row.appendChild(el("td", null, finding.severity));
    row.appendChild(el("td", null, finding.confidence || "—"));
    row.appendChild(el("td", "cell-mono", `${finding.file}:${finding.line}`));
    const statusCell = el("td");
    statusCell.appendChild(el("span", "pill st-" + finding.status,
      { open: "открыта", fixed: "закрыта", regressed: "вернулась", ignored: "игнор" }[finding.status] || finding.status));
    row.appendChild(statusCell);
    const actions = el("td");
    const box = el("div", "journal-actions");
    [["open", "вернуть"], ["fixed", "закрыть"], ["ignored", "игнор"]].forEach(([value, label]) => {
      const button = el("button", "ghost small", label);
      button.addEventListener("click", async () => {
        try {
          await api("/api/status", { method: "POST", body: JSON.stringify({ fingerprint: finding.fingerprint, status: value }) });
          const original = state.findings.find((item) => item.fingerprint === finding.fingerprint);
          if (original) original.status = value;
          await loadJournal();
          toast("статус: " + value, "ok");
        } catch (error) {
          toast(error.message, "bad");
        }
      });
      box.appendChild(button);
    });
    actions.appendChild(box);
    row.appendChild(actions);
    table.appendChild(row);
  });
  makeSortable($("#journal-table"));
}

async function loadJournalDiff() {
  const status = $("#journal-status");
  setStatus(status, "сравниваю…");
  try {
    const before = $("#journal-before").value;
    const after = $("#journal-after").value;
    const result = await api(`/api/journal/diff?before=${before}&after=${after}`);
    renderJournalDiff(result);
    setStatus(status, "");
  } catch (error) {
    setStatus(status, error.message, "bad");
  }
}

function renderJournalDiff(result) {
  const holder = $("#journal-diff");
  holder.textContent = "";
  if (!result || result.available === false) {
    holder.appendChild(el("div", "empty", (result && result.reason) || "разницы нет"));
    return;
  }
  const head = el("div", "head");
  head.appendChild(el("h3", null, "Разница между прогонами"));
  head.appendChild(el("div", "loc", `было ${result.before.total} → стало ${result.after.total} · осталось ${result.persisting}`));
  holder.appendChild(head);
  const wrap = el("div", "body");
  const section = (title, items, cls) => {
    const block = el("div", "block");
    block.appendChild(el("h4", null, `${title}: ${items.length}`));
    if (!items.length) {
      block.appendChild(el("div", "empty", "—"));
    } else {
      items.forEach((item) => {
        const row = el("div", "map-row");
        row.appendChild(el("span", "dot " + (item.severity || "info")));
        row.appendChild(el("span", "snip", `${item.rule} · ${item.file}:${item.line}`));
        if (item.status) {
          row.appendChild(el("span", "pill st-" + item.status,
            { open: "открыта", fixed: "закрыта", regressed: "вернулась", ignored: "игнор" }[item.status] || item.status));
        }
        block.appendChild(row);
      });
    }
    block.className = "block " + cls;
    wrap.appendChild(block);
  };
  section("пропало (закрыто)", result.closed || [], "closed");
  section("появилось", result.appeared || [], "appeared");
  holder.appendChild(wrap);
}

/* ---------- сортировка таблиц ---------- */

// Слова важности и состояния сортируются своим порядком, а не алфавитом.
const TEXT_RANK = {
  high: 0, medium: 1, low: 2, info: 3,
  "уверен": 0, "скорее да": 1, "не уверен": 2,
  "открыта": 0, "закрыта": 1, "вернулась": 2, "игнор": 3,
  "не лежит": 0, "лежит": 1, "ошибки": 2,
};

function cellValue(row, index) {
  const cell = row && row.cells[index];
  if (!cell) return "";
  const text = cell.textContent.trim();
  const rank = TEXT_RANK[text.toLowerCase()];
  if (rank !== undefined) return rank;
  const number = parseFloat(text.replace(",", "."));
  if (Number.isFinite(number) && /^[-+0-9.,\s]+$/.test(text)) return number;
  return text.toLowerCase();
}

function makeSortable(table) {
  if (!table || table.dataset.sortable === "1") return;
  table.dataset.sortable = "1";
  table.classList.add("sortable");
  const head = table.tHead;
  if (!head || !head.rows.length) return;
  Array.from(head.rows[0].cells).forEach((cell, index) => {
    const arrow = el("span", "arrow", "↕");
    cell.appendChild(arrow);
    // Направление живёт на ячейке, а не в замыкании: тогда «сбросить»
    // возвращает все столбцы в исходное состояние одним проходом.
    cell.dataset.asc = "1";
    cell.addEventListener("click", () => {
      const body = table.tBodies[0];
      if (!body) return;
      const ascending = cell.dataset.asc !== "0";
      // Раскрытый код правила — отдельная строка под своей: сортировать её
      // отдельно значит оторвать код от правила. Тащим парой.
      const groups = [];
      Array.from(body.rows).forEach((row) => {
        if (row.classList.contains("rule-code-row") && groups.length) {
          groups[groups.length - 1].push(row);
        } else {
          groups.push([row]);
        }
      });
      const valued = groups.map((group) => ({ group, value: cellValue(group[0], index) }));
      valued.sort((a, b) => {
        if (a.value === b.value) return 0;
        const result = a.value > b.value ? 1 : -1;
        return ascending ? result : -result;
      });
      arrow.textContent = ascending ? "↑" : "↓";
      cell.dataset.asc = ascending ? "0" : "1";
      valued.forEach((item) => item.group.forEach((row) => body.appendChild(row)));
    });
  });
}

function resetSort(table) {
  if (!table || !table.tHead || !table.tHead.rows.length) return;
  Array.from(table.tHead.rows[0].cells).forEach((cell) => {
    cell.dataset.asc = "1";
    const arrow = cell.querySelector(".arrow");
    if (arrow) arrow.textContent = "↕";
  });
}

function makeAllSortable() {
  $$("table").forEach((table) => makeSortable(table));
}

/* ---------- файлы ---------- */

async function listPath(path) {
  const status = $("#file-status");
  setStatus(status, "читаю каталог…");
  try {
    const result = await api("/api/files?path=" + encodeURIComponent(path));
    const list = $("#files-list");
    list.textContent = "";
    if (!result.entries.length) list.appendChild(el("div", "empty", "пусто или нет доступа"));
    result.entries.forEach((entry) => {
      const item = el("div", "item");
      item.appendChild(el("span", "pill soft", entry.type === "dir" ? "кат" : "файл"));
      const body = el("div", "body");
      body.appendChild(el("b", null, entry.name));
      body.appendChild(el("small", null, entry.size === null || entry.size === undefined ? "" : entry.size + " Б"));
      item.appendChild(body);
      item.addEventListener("click", () => {
        const next = path.replace(/\/+$/, "") + "/" + entry.name;
        $("#path-input").value = next;
        if (entry.type === "dir") listPath(next);
        else readFile(next);
      });
      list.appendChild(item);
    });
    setStatus(status, `записей: ${result.entries.length}`, "ok");
  } catch (error) {
    setStatus(status, error.message, "bad");
  }
}

async function readFile(path) {
  const view = $("#file-view");
  const status = $("#file-status");
  setStatus(status, "читаю файл…");
  try {
    const result = await api("/api/file?path=" + encodeURIComponent(path));
    $("#path-input").value = path;
    const head = $("#file-path");
    head.textContent = path;
    head.title = result.path && result.path !== path ? "на диске: " + result.path : path;
    state.activeFile = path;
    view.textContent = "";
    if (result.binary) {
      view.appendChild(el("div", "empty", "двоичный файл — не показываю"));
      setStatus(status, "двоичный", "bad");
      return;
    }
    const hits = new Map();
    (result.findings || []).forEach((finding) => {
      const current = hits.get(finding.line);
      if (!current || (SEV_ORDER[finding.severity] ?? 9) < (SEV_ORDER[current.severity] ?? 9)) {
        hits.set(finding.line, finding);
      }
    });
    $("#file-legend").hidden = hits.size === 0;
    const scroll = el("div", "code-scroll");
    const lines = result.lines || [];
    const cap = Math.min(lines.length, 4000);
    for (let index = 0; index < cap; index++) {
      const number = index + 1;
      const hit = hits.get(number);
      const row = el("div", "line" + (hit ? " hit " + hit.severity : ""));
      row.appendChild(el("span", "ln", number));
      row.appendChild(el("span", "src", lines[index]));
      if (hit) {
        row.title = `${hit.severity}: ${hit.kind_ru || hit.kind}`;
        row.addEventListener("click", () => {
          selectFinding(hit);
          showTab("findings");
        });
      }
      scroll.appendChild(row);
    }
    view.appendChild(scroll);
    if (lines.length > cap) {
      view.appendChild(el("div", "empty", `обрезано на ${cap} из ${lines.length} строк`));
    }
    setStatus(status, `строк: ${lines.length} · находок: ${(result.findings || []).length}`, "ok");
  } catch (error) {
    setStatus(status, error.message, "bad");
  }
}

$("#btn-list").addEventListener("click", () => listPath($("#path-input").value.trim() || "/"));
$("#btn-read").addEventListener("click", () => readFile($("#path-input").value.trim()));
$("#path-input").addEventListener("keydown", (event) => {
  if (event.key === "Enter") readFile($("#path-input").value.trim());
});

/* ---------- генератор ---------- */

function serviceFromPath(path) {
  const match = /\/(?:srv|opt|app|var\/www|data)\/([^/]+)\//.exec(path || "");
  if (match) return match[1];
  const services = (state.audit && state.audit.services) || [];
  const hit = services.find((service) => service.cwd && path && path.startsWith(service.cwd));
  return hit ? hit.service : "service";
}

function servicePort(name, path) {
  const services = (state.audit && state.audit.services) || [];
  const hit = services.find((service) => service.service === name)
    || services.find((service) => service.cwd && path && path.startsWith(service.cwd));
  return hit ? hit.port : 8080;
}

function endpointFor(finding) {
  const endpoints = (state.audit && state.audit.endpoints) || [];
  const sameFile = endpoints.filter((endpoint) => endpoint.file === finding.file);
  if (sameFile.length) {
    sameFile.sort((a, b) => Math.abs((a.line || 0) - finding.line) - Math.abs((b.line || 0) - finding.line));
    return sameFile[0].path;
  }
  if (endpoints.length) return endpoints[0].path;
  return "/";
}

function setGeneratorFinding(finding) {
  state.activeFinding = finding;
  $("#g-finding").value = `${finding.kind_ru || finding.kind} @ ${finding.file}:${finding.line}`;
  const service = serviceFromPath(finding.file);
  const port = servicePort(service, finding.file);
  $("#g-service").value = service;
  $("#g-port").value = port;
  $("#g-endpoint").value = endpointFor(finding);
  const host = (state.config.target && state.config.target.host) || "";
  $("#g-base").value = `http://${host || "127.0.0.1"}:${port}`;
  $("#g-lint-card").hidden = true;
  $("#g-requests-wrap").hidden = true;
  $("#g-result").hidden = true;
  $("#g-mode").hidden = true;
  $("#g-output").textContent = "";
  $("#g-output").appendChild(el("div", "empty", "нажмите «Сгенерировать»"));
}

$("#btn-generate").addEventListener("click", async () => {
  const finding = state.activeFinding;
  const status = $("#g-status");
  if (!finding) {
    setStatus(status, "сначала выберите находку", "bad");
    toast("Сначала выберите находку во вкладке «Находки»", "warn");
    return;
  }
  setStatus(status, "собираю…");
  try {
    const result = await api("/api/generate", {
      method: "POST",
      body: JSON.stringify({
        id: finding.id,
        service: $("#g-service").value.trim() || "service",
        endpoint: $("#g-endpoint").value.trim() || null,
        port: Number($("#g-port").value) || 80,
      }),
    });
    state.probe = result;
    $("#g-output").textContent = result.code;
    const mode = $("#g-mode");
    mode.hidden = false;
    mode.textContent = result.manual ? "заготовка · вручную" : "проба · GET";
    renderLint(result);
    renderRequests(result.requests || [], result);
    setStatus(status, result.manual ? "заготовка: только вручную" : `запросов: ${(result.requests || []).length}`,
      result.manual ? "warn" : "ok");
  } catch (error) {
    setStatus(status, error.message, "bad");
    toast(error.message, "bad");
  }
});

function renderLint(result) {
  const card = $("#g-lint-card");
  const lint = $("#g-lint");
  card.hidden = false;
  const errors = (result.lint && result.lint.errors) || [];
  const warnings = (result.lint && result.lint.warnings) || [];
  if (result.lint && result.lint.ok) {
    lint.className = "lint " + (warnings.length ? "warn" : "ok");
    lint.textContent = warnings.length
      ? `линтер (${result.lint.mode}): без ошибок, предупреждений ${warnings.length}\n` + warnings.join("\n")
      : `линтер (${result.lint.mode}): чисто`;
  } else {
    lint.className = "lint bad";
    lint.textContent = `линтер (${result.lint.mode}): отклонено\n` + errors.join("\n");
  }
}

function renderRequests(requests, result) {
  const wrap = $("#g-requests-wrap");
  const body = $("#g-requests tbody");
  body.textContent = "";
  if (!requests.length) {
    wrap.hidden = true;
    return;
  }
  const manual = Boolean(result && result.manual);
  $("#g-requests-summary").textContent = manual
    ? "Заготовка: один запрос, меняющий состояние. По умолчанию только печатается."
    : `Только GET. Максимум 14 запросов, пауза 0.15 с. Бюджет процесса — 30 запросов в минуту.`;
  requests.forEach((request) => {
    const row = el("tr");
    row.appendChild(el("td", "cell-mono", request.label || "—"));
    row.appendChild(el("td", "cell-mono", request.method ? `${request.method} ${request.path}` : request.path));
    row.appendChild(el("td", null, request.note || (request.marker ? "маркер в ответе" : "сравнение с базовым")));
    body.appendChild(row);
  });
  wrap.hidden = false;
}

$("#btn-run-probe").addEventListener("click", async () => {
  const finding = state.activeFinding;
  const status = $("#g-status");
  if (!finding) {
    setStatus(status, "сначала выберите находку", "bad");
    return;
  }
  const base = $("#g-base").value.trim();
  if (!base.startsWith("http")) {
    setStatus(status, "нужен базовый URL вида http://host:port", "bad");
    toast("Базовый URL должен начинаться с http://", "warn");
    return;
  }
  setStatus(status, "проба идёт…");
  $("#btn-run-probe").disabled = true;
  try {
    const result = await api("/api/probe", {
      method: "POST",
      body: JSON.stringify({
        id: finding.id,
        service: $("#g-service").value.trim(),
        endpoint: $("#g-endpoint").value.trim() || null,
        port: Number($("#g-port").value) || 80,
        base,
        post: $("#g-post").checked,
      }),
    });
    state.probeResult = result;
    renderBudget(result.budget);
    renderEvidence(result);
    renderSteps();
    const verdict = SUMMARY_RU[result.summary.verdict] || result.summary.verdict;
    setStatus(status, `вердикт: ${verdict}`, result.summary.verdict === "confirmed" ? "ok" : "");
    toast(`Проба: ${verdict}`, result.summary.verdict === "confirmed" ? "ok" : "warn");
    if (result.summary.verdict === "manual") {
      toast("Этот класс проверяется только заготовкой вручную", "warn");
    }
  } catch (error) {
    setStatus(status, error.message, "bad");
    toast(error.message, "bad");
  } finally {
    $("#btn-run-probe").disabled = false;
  }
});

function renderEvidence(result) {
  const holder = $("#g-result");
  const body = $("#g-evidence tbody");
  body.textContent = "";
  holder.hidden = false;
  const summary = result.summary || {};
  const budget = result.budget || null;
  $("#g-verdict").textContent = (SUMMARY_RU[summary.verdict] || summary.verdict || "") +
    ` · запросов ${summary.requests ?? 0}, сигналов ${summary.signals ?? 0}, отличий ${summary.diffs ?? 0}` +
    (summary.auth ? ` · авторизация: ${AUTH_RU[summary.auth] || summary.auth}` : "") +
    (budget ? ` · бюджет ${budget.used}/${budget.capacity}` : "");

  const auth = result.auth;
  if (auth) {
    const pillOf = (verdict) => {
      const bad = verdict === "open" || verdict === "shared";
      const warn = verdict === "other" || verdict === "unknown";
      return "pill verdict-" + (bad ? "signal" : warn ? "diff" : "clean");
    };
    const addRow = (label, status, bytes, ms, verdict, evidence) => {
      const tr = el("tr", "auth-row");
      tr.appendChild(el("td", "cell-mono", label));
      tr.appendChild(el("td", "cell-mono", status ?? "—"));
      tr.appendChild(el("td", "cell-mono", bytes ?? "—"));
      tr.appendChild(el("td", "cell-mono", ms ?? "—"));
      const verdictCell = el("td");
      verdictCell.appendChild(el("span", pillOf(verdict), AUTH_RU[verdict] || verdict));
      tr.appendChild(verdictCell);
      const text = el("td", "cell-mono", evidence || "");
      text.style.fontSize = "11.5px";
      text.style.color = "var(--muted)";
      tr.appendChild(text);
      body.appendChild(tr);
    };

    if (auth.a && auth.b) {
      const anon = auth.anonymous || {};
      addRow("аноним", anon.status, anon.bytes, anon.ms, auth.verdict, "");
      addRow("аккаунт A", auth.a.status, auth.a.bytes, auth.a.ms, auth.verdict, auth.evidence);
      addRow("аккаунт B", auth.b.status, auth.b.bytes, auth.b.ms, auth.verdict, "");
    } else {
      const anon = auth.anonymous || {};
      addRow("авторизация", anon.status, anon.bytes, anon.ms, auth.verdict,
        auth.evidence || auth.note || "");
    }
  }

  if (!(result.results || []).length) {
    const row = el("tr");
    const cell = el("td", "empty", result.reason || "проба не дала запросов");
    cell.colSpan = 6;
    row.appendChild(cell);
    body.appendChild(row);
    return;
  }

  result.results.forEach((row) => {
    const tr = el("tr");
    tr.appendChild(el("td", "cell-mono", row.label));
    tr.appendChild(el("td", "cell-mono", row.status));
    tr.appendChild(el("td", "cell-mono", row.bytes));
    tr.appendChild(el("td", "cell-mono", row.ms));
    const verdict = el("td");
    verdict.appendChild(el("span", "pill verdict-" + row.verdict, VERDICT_RU[row.verdict] || row.verdict));
    tr.appendChild(verdict);
    const evidence = el("td", "cell-mono", row.evidence || "");
    evidence.style.fontSize = "11.5px";
    evidence.style.color = "var(--muted)";
    tr.appendChild(evidence);
    body.appendChild(tr);
  });
}

$("#btn-copy-probe").addEventListener("click", async () => {
  if (!state.probe) { toast("Сначала сгенерируйте", "warn"); return; }
  await copyText(state.probe.code);
  toast("Код скопирован", "ok");
});

$("#btn-save-probe").addEventListener("click", () => {
  if (!state.probe) { toast("Сначала сгенерируйте", "warn"); return; }
  download(`${state.probe.name || "probe"}.py`, state.probe.code);
  toast("Файл скачан", "ok");
});

/* ---------- отчёт ---------- */

$("#btn-report").addEventListener("click", async () => {
  const status = $("#r-status");
  setStatus(status, "собираю…");
  try {
    const result = await api("/api/report", { method: "POST", body: "{}" });
    state.report = result.markdown;
    $("#r-output").textContent = result.markdown;
    setStatus(status, `строк: ${result.markdown.split("\n").length}`, "ok");
    toast("Отчёт собран", "ok");
  } catch (error) {
    setStatus(status, error.message, "bad");
    toast(error.message, "bad");
  }
});

$("#btn-copy-report").addEventListener("click", async () => {
  if (!state.report) { toast("Сначала соберите отчёт", "warn"); return; }
  await copyText(state.report);
  toast("Отчёт скопирован", "ok");
});

$("#btn-save-report").addEventListener("click", () => {
  if (!state.report) { toast("Сначала соберите отчёт", "warn"); return; }
  download("ad-audit-report.md", state.report);
  toast("Файл скачан", "ok");
});

/* ---------- трафик ---------- */

let trafficCache = null;

function renderTraffic(profile) {
  trafficCache = profile;
  const summary = profile.summary || {};
  const caps = profile.caps || {};
  $("#tr-total").textContent = summary.total ?? 0;
  $("#tr-minute").textContent = summary.last_minute ?? 0;
  $("#tr-bytes").textContent = summary.bytes ?? 0;
  $("#tr-avg").textContent = summary.avg_bytes ?? 0;
  $("#tr-ms").textContent = summary.avg_ms ?? 0;

  const claims = $("#traffic-claims");
  claims.textContent = "";
  const list = el("div", null);
  list.appendChild(el("b", null, "потолки: "));
  list.appendChild(document.createTextNode(
    `${caps.max_requests_per_probe} GET на пробу + ${caps.baseline_requests} базовый, ` +
    `пауза ${caps.min_delay_s} с, бюджет ${caps.budget_capacity} за ${caps.budget_window_s} с`
  ));
  claims.appendChild(list);
  const ul = el("ul", "fix-steps");
  ul.style.margin = "8px 0 0";
  (profile.claims || []).forEach((claim) => ul.appendChild(el("li", null, claim)));
  claims.appendChild(ul);

  const body = $("#traffic-table tbody");
  body.textContent = "";
  const events = (profile.events || []).slice().reverse();
  if (!events.length) {
    const row = el("tr");
    const cell = el("td", "empty", "проб ещё не было");
    cell.colSpan = 5;
    row.appendChild(cell);
    body.appendChild(row);
    return;
  }
  events.forEach((event) => {
    const row = el("tr");
    const when = new Date((event.at || 0) * 1000);
    row.appendChild(el("td", "cell-mono", when.toLocaleTimeString("ru-RU")));
    const url = el("td", "cell-mono", event.url || "");
    url.style.maxWidth = "520px";
    url.style.overflow = "hidden";
    url.style.textOverflow = "ellipsis";
    url.style.whiteSpace = "nowrap";
    row.appendChild(url);
    row.appendChild(el("td", "cell-mono", event.status ?? 0));
    row.appendChild(el("td", "cell-mono", event.bytes ?? 0));
    row.appendChild(el("td", "cell-mono", event.ms ?? 0));
    body.appendChild(row);
  });
  makeSortable($("#traffic-table"));
}

async function loadTraffic() {
  try {
    renderTraffic(await api("/api/traffic"));
  } catch (error) {
    toast("журнал трафика: " + error.message, "bad");
  }
}

$("#btn-traffic-refresh").addEventListener("click", loadTraffic);

$("#btn-traffic-csv").addEventListener("click", () => {
  if (!trafficCache) { toast("сначала обновите журнал", "warn"); return; }
  const lines = ["time,url,status,bytes,ms"];
  (trafficCache.events || []).forEach((event) => {
    lines.push([new Date((event.at || 0) * 1000).toISOString(), event.url, event.status, event.bytes, event.ms]
      .map((value) => `"${String(value ?? "").replace(/"/g, '""')}"`).join(","));
  });
  download("ad-audit-traffic.csv", lines.join("\n"));
  toast("Журнал выгружен", "ok");
});

/* ---------- правила ---------- */

let rulesCache = [];

function renderRules() {
  const body = $("#rules-table tbody");
  body.textContent = "";
  const needle = state.rulesFilter.trim().toLowerCase();
  const sev = state.rulesSev || "";
  const rules = rulesCache.filter((rule) => {
    if (sev && rule.severity !== sev) return false;
    if (!needle) return true;
    return `${rule.id} ${rule.kind} ${rule.kind_ru || ""} ${(rule.languages || []).join(" ")}`
      .toLowerCase().includes(needle);
  });
  if (!rules.length) {
    const row = el("tr");
    const cell = el("td", "empty",
      state.rulesFilter || sev ? "под фильтр ничего не попало — нажмите «сбросить»" : "правил нет");
    cell.colSpan = 7;
    row.appendChild(cell);
    body.appendChild(row);
    makeSortable($("#rules-table"));
    return;
  }
  rules.forEach((rule) => {
    const row = el("tr");
    row.appendChild(el("td", "cell-mono", rule.id));
    row.appendChild(el("td", null, rule.kind_ru || rule.kind));
    const sev = el("td");
    sev.appendChild(el("span", "pill " + rule.severity, rule.severity));
    row.appendChild(sev);
    row.appendChild(el("td", "cell-mono", (rule.languages || ["any"]).join(", ")));

    const why = el("td", "rule-why", rule.why_ru || rule.why);
    row.appendChild(why);

    const fix = el("td", "rule-fix");
    fix.appendChild(el("span", null, rule.patch_ru || rule.patch));
    if (rule.fix_hint) fix.appendChild(el("span", "rule-hint", rule.fix_hint));
    row.appendChild(fix);

    const treat = el("td");
    if (rule.fix && rule.fix.title) {
      treat.appendChild(el("div", "rule-family", rule.fix.title));
      const risk = el("div", `rule-family risk-${rule.fix.risk || "low"}`,
        `риск для раунда: ${rule.fix.risk === "high" ? "высокий" : rule.fix.risk === "medium" ? "средний" : "низкий"}`);
      treat.appendChild(risk);
      const codeButton = el("button", "ghost small", "код");
      codeButton.addEventListener("click", () => toggleRuleCode(row, rule, codeButton));
      treat.appendChild(codeButton);
    } else {
      treat.appendChild(el("span", "rule-family", "вручную"));
    }
    row.appendChild(treat);
    body.appendChild(row);
  });
  makeSortable($("#rules-table"));
}

async function toggleRuleCode(row, rule, button) {
  const next = row.nextElementSibling;
  if (next && next.classList.contains("rule-code-row")) {
    next.remove();
    button.textContent = "код";
    return;
  }
  button.disabled = true;
  try {
    const answer = await api(`/api/rulefix?rule=${encodeURIComponent(rule.id)}`);
    const fix = answer.fix || {};
    const cell = el("td");
    cell.colSpan = 7;
    if (!fix.available) {
      cell.appendChild(el("div", "rule-family", (fix.steps || []).join(" · ") || "готового семейства нет"));
    } else {
      const pre = el("pre", "rule-code");
      (fix.before || []).forEach((line) => pre.appendChild(el("div", "minus", `- ${line}`)));
      (fix.after || []).forEach((line) => pre.appendChild(el("div", "plus", `+ ${line}`)));
      cell.appendChild(pre);
      const meta = el("div", "rule-family", `${fix.title} · ${fix.language_label || fix.language || ""} · ${fix.breaks || ""}`);
      cell.appendChild(meta);
    }
    const codeRow = el("tr", "rule-code-row");
    codeRow.appendChild(cell);
    row.after(codeRow);
    button.textContent = "скрыть";
  } catch (error) {
    toast("код лечения: " + error.message, "bad");
  } finally {
    button.disabled = false;
  }
}

$("#rules-search").addEventListener("input", (event) => {
  state.rulesFilter = event.target.value;
  renderRules();
});

$$("#rules-sev .sev-chip").forEach((chip) => {
  chip.addEventListener("click", () => {
    state.rulesSev = chip.dataset.sev || "";
    $$("#rules-sev .sev-chip").forEach(
      (node) => node.classList.toggle("active", (node.dataset.sev || "") === state.rulesSev)
    );
    renderRules();
  });
});

function resetRulesFilters() {
  state.rulesFilter = "";
  state.rulesSev = "";
  $("#rules-search").value = "";
  $$("#rules-sev .sev-chip").forEach(
    (node) => node.classList.toggle("active", !(node.dataset.sev || ""))
  );
  resetSort($("#rules-table"));
  renderRules();
}

$("#btn-rules-reset").addEventListener("click", resetRulesFilters);

$("#rules-to-kb").addEventListener("click", (event) => {
  event.preventDefault();
  showTab("knowledge");
});

$("#kb-to-rules").addEventListener("click", (event) => {
  event.preventDefault();
  showTab("rules");
});

async function loadRules() {
  try {
    const result = await api("/api/patterns");
    rulesCache = result.rules || [];
    renderRules();
    const coverage = $("#coverage-table tbody");
    coverage.textContent = "";
    (result.coverage || []).forEach((entry) => {
      const row = el("tr");
      row.appendChild(el("td", "cell-mono", entry.language));
      row.appendChild(el("td", "cell-mono", entry.shown_as));
      row.appendChild(el("td", "cell-mono", entry.rules));
      row.appendChild(el("td", null, entry.depth));
      coverage.appendChild(row);
    });
  } catch (error) {
    console.error(error);
  }
}

/* ---------- база знаний ---------- */

async function loadKnowledge() {
  try {
    const result = await api("/api/knowledge");
    const list = $("#knowledge-list");
    const view = $("#knowledge-view");
    list.textContent = "";
    if (!result.items.length) {
      list.appendChild(el("div", "empty", "в knowledge/ пусто"));
      return;
    }
    result.items.forEach((item, index) => {
      const node = el("div", "item");
      const body = el("div", "body");
      body.appendChild(el("b", null, item.name));
      node.appendChild(body);
      node.addEventListener("click", () => {
        $$("#knowledge-list .item").forEach((other) => other.classList.remove("active"));
        node.classList.add("active");
        view.innerHTML = mdToHtml(item.text);
        view.scrollTop = 0;
      });
      list.appendChild(node);
      if (index === 0) node.click();
    });
  } catch (error) {
    console.error(error);
  }
}

/* ---------- горячие клавиши ---------- */

document.addEventListener("keydown", (event) => {
  const tag = (event.target.tagName || "").toLowerCase();
  const typing = tag === "input" || tag === "select" || tag === "textarea";

  if (event.key === "Escape") {
    if (typing) event.target.blur();
    return;
  }
  if (typing) return;

  if (event.key === "/") {
    event.preventDefault();
    const active = ORDER.find((name) => document.getElementById("panel-" + name).classList.contains("active"));
    if (active === "findings") $("#f-search").focus();
    else if (active === "services") $("#svc-search").focus();
    else if (active === "rules") $("#rules-search").focus();
    else { showTab("findings"); $("#f-search").focus(); }
    return;
  }
  if (/^[0-9]$/.test(event.key)) {
    const name = SHORTCUTS[event.key];
    if (name) showTab(name);
    return;
  }
  if (event.key.toLowerCase() === "g") { $("#btn-generate").click(); }
  if (event.key.toLowerCase() === "r") { $("#btn-run-probe").click(); }
  if (event.key.toLowerCase() === "m") { showTab("map"); }
  if (event.key.toLowerCase() === "j") { showTab("journal"); }
  if (event.key.toLowerCase() === "s") { showTab("stand"); }
});

/* ---------- остановка ---------- */

$("#btn-stop").addEventListener("click", async () => {
  const button = $("#btn-stop");
  button.disabled = true;
  try {
    await api("/api/shutdown", { method: "POST", body: "{}" });
    document.body.innerHTML =
      '<div style="display:grid;place-items:center;height:100vh;font:15px system-ui;color:#8b95a3;text-align:center">' +
      "<div><b style='color:#e6edf3'>Сервер остановлен.</b><br>Закройте вкладку — приложение завершило работу.</div></div>";
  } catch (error) {
    button.disabled = false;
    toast("не вышло остановить: " + error.message, "bad");
  }
});


/* ---------- тренажёр: восемь эксплойтов ---------- */

const drillState = { items: [], bases: {}, results: {} };

function renderDrills() {
  const box = $("#drill-list");
  box.textContent = "";
  if (!drillState.items.length) {
    box.appendChild(el("div", "empty", "список не загружен"));
    return;
  }
  drillState.items.forEach((item, index) => {
    const row = el("div", "drill");
    const head = el("div", "drill-head");
    head.appendChild(el("span", "drill-num", String(index + 1)));
    const titles = el("div", "drill-titles");
    titles.appendChild(el("b", null, item.title));
    titles.appendChild(el("span", "drill-class", `${item.class} · ${item.service}:${item.port}`));
    head.appendChild(titles);
    const result = drillState.results[item.id];
    if (result) {
      head.appendChild(el("span", `drill-badge ${result.hit ? "hit" : "miss"}`,
        result.hit ? "сработало" : "нет сигнала"));
    }
    const button = el("button", "ghost small", "прогнать");
    button.addEventListener("click", () => runDrill(item, button));
    head.appendChild(button);
    row.appendChild(head);

    const code = el("code", "drill-path", item.path);
    row.appendChild(code);

    const details = el("details", "drill-more");
    details.appendChild(el("summary", null, "как это работает и что дальше"));
    const body = el("div", "drill-body");
    body.appendChild(el("p", null, item.why));
    body.appendChild(el("p", "drill-next", item.next));
    if ((item.variants || []).length) {
      const variants = el("div", "drill-variants");
      variants.appendChild(el("span", "drill-label", "варианты: "));
      (item.variants || []).forEach((variant) => {
        const chip = el("code", "drill-variant", variant);
        chip.title = "скопировать";
        chip.addEventListener("click", async () => {
          await copyText(variant);
          toast("вариант скопирован", "ok");
        });
        variants.appendChild(chip);
      });
      body.appendChild(variants);
    }
    body.appendChild(el("p", "drill-label", `закрывается: правило ${item.fix}`));
    details.appendChild(body);
    row.appendChild(details);
    box.appendChild(row);
  });
}

async function runDrill(item, button) {
  const override = ($("#drill-base").value || "").trim();
  const base = override || drillState.bases[item.service] || "";
  button.disabled = true;
  button.textContent = "проверяю…";
  try {
    const result = await api("/api/drill/run", {
      method: "POST",
      body: JSON.stringify({ id: item.id, base }),
    });
    drillState.results[item.id] = result;
    renderDrills();
    showDrillResult(result);
    toast(result.hit ? `${item.title}: сработало` : `${item.title}: сигнала нет`, result.hit ? "ok" : "warn");
  } catch (error) {
    toast("упражнение: " + error.message, "bad");
    button.disabled = false;
    button.textContent = "прогнать";
  }
}

function showDrillResult(result) {
  const box = $("#drill-result");
  box.hidden = false;
  box.textContent = "";
  const head = el("div", "row");
  head.appendChild(el("b", null, result.title));
  head.appendChild(el("span", `drill-badge ${result.hit ? "hit" : "miss"}`, result.hit ? "сработало" : "нет сигнала"));
  const copy = el("button", "ghost small", "копировать запрос");
  copy.addEventListener("click", async () => {
    await copyText(`curl -sS '${result.url}'`);
    toast("curl скопирован", "ok");
  });
  head.appendChild(copy);
  box.appendChild(head);
  const facts = el("div", "drill-facts");
  facts.appendChild(el("span", null, `HTTP ${result.status ?? "—"}`));
  facts.appendChild(el("span", null, `${result.bytes} байт`));
  facts.appendChild(el("span", null, `${result.ms ?? "—"} мс`));
  facts.appendChild(el("span", null, `маркер: ${result.marker}`));
  box.appendChild(facts);
  if (result.flag) {
    const flagBox = el("div", "flag-hit");
    flagBox.appendChild(el("span", null, "в ответе флаг: "));
    flagBox.appendChild(el("code", null, result.flag));
    const copyFlag = el("button", "ghost small", "копировать");
    copyFlag.addEventListener("click", async () => {
      await copyText(result.flag);
      toast("флаг скопирован: отправляйте до конца раунда", "ok");
    });
    flagBox.appendChild(copyFlag);
    box.appendChild(flagBox);
  }
  box.appendChild(el("pre", "drill-evidence", result.evidence || "ответ без маркера — смотрите тело и статус"));
  box.appendChild(el("p", "drill-next", `${result.why} ${result.next}`));
}

async function loadDrills() {
  try {
    const payload = await api("/api/drill");
    drillState.items = payload.drills || [];
    drillState.bases = payload.bases || {};
    setStatus($("#drill-status"), `${drillState.items.length} упражнений`, "ok");
    renderDrills();
  } catch (error) {
    setStatus($("#drill-status"), error.message, "bad");
  }
}

$("#btn-drill-refresh").addEventListener("click", loadDrills);

/* ---------- стенд турнира ---------- */

const STAND_LAMP = { up: "не лежит", down: "лежит", sick: "ошибки", open: "порт", local: "loopback", unknown: "?" };

async function loadStand() {
  const status = $("#stand-status");
  setStatus(status, "читаю стенд…");
  try {
    const data = await api("/api/topology");
    state.stand = data.view;
    state.standPath = data.path;
    renderStand();
    setStatus(status, "");
  } catch (error) {
    setStatus(status, error.message, "bad");
  }
}

function renderStand() {
  const view = state.stand;
  if (!view) return;
  const sum = view.summary || {};
  $("#stand-teams").textContent = sum.teams_total || 0;
  $("#stand-members").textContent = sum.members || 0;
  $("#stand-services").textContent = sum.services || 0;
  $("#stand-findings").textContent = sum.findings || 0;
  $("#stand-open").textContent = sum.open || 0;
  $("#stand-unsure").textContent = sum.unsure || 0;
  $("#stand-round").textContent = (view.round && view.round.minutes) || 5;

  const lead = [];
  if (view.round && view.round.event) lead.push(view.round.event);
  if (view.model && view.model.team) lead.push("команда: " + view.model.team);
  if (view.server && view.server.host) lead.push("сервер: " + view.server.host);
  $("#stand-lead").textContent = lead.join(" · ")
    || "стенд пуст: нажмите «правка», чтобы завести сервисы, или «заполнить из аудита»";

  renderStandCanvas();
  renderStandSide();
  renderStandField();
}

function buildServiceCard(service) {
  const card = el("div", "stand-svc " + (service.worst || "info"));
  if (service.health === "down") card.classList.add("is-down");
  if (state.standSelected === service.id) card.classList.add("active");
  card.title = `${service.name} · порт ${service.port || "?"} · риск ${service.risk || 0}/100`;

  const head = el("div", "head");
  head.appendChild(el("span", "port", service.port ? String(service.port) : "—"));
  head.appendChild(el("span", "name", service.name));
  card.appendChild(head);
  card.appendChild(el("div", "lang", service.language || "язык не задан"));

  const counts = service.counts || {};
  const bars = el("div", "bars");
  let total = 0;
  [["high", counts.high], ["medium", counts.medium], ["low", counts.low]].forEach(([sev, value]) => {
    if (!value) return;
    total += value;
    const part = el("i", sev);
    part.style.flex = String(value);
    part.title = `${sev}: ${value}`;
    bars.appendChild(part);
  });
  if (!total) {
    const empty = el("i");
    empty.style.flex = "1";
    bars.appendChild(empty);
  }
  card.appendChild(bars);

  const meta = el("div", "meta");
  meta.appendChild(el("span", "lamp " + (service.health || "unknown"),
    STAND_LAMP[service.health] || "?"));
  meta.appendChild(el("span", null, `${total} находок · риск ${service.risk || 0}`));
  card.appendChild(meta);

  card.addEventListener("click", () => {
    state.standSelected = state.standSelected === service.id ? null : service.id;
    renderStandCanvas();
    renderStandSide();
  });
  return card;
}

function renderStandCanvas() {
  const canvas = $("#stand-canvas");
  const view = state.stand;
  if (!canvas || !view) return;

  const server = $("#stand-server");
  server.textContent = "";
  server.appendChild(el("div", "stand-server-name",
    (view.server && view.server.name) || "наш вулнбокс"));
  server.appendChild(el("div", "stand-server-host",
    (view.server && view.server.host) || "адрес не задан"));

  const sum = view.summary || {};
  const bar = el("div", "stand-server-bar");
  [["high", sum.high], ["medium", sum.medium], ["low", sum.low]].forEach(([sev, value]) => {
    if (!value) return;
    const part = el("span", "seg " + sev);
    part.style.flex = String(value);
    part.title = `${sev}: ${value}`;
    bar.appendChild(part);
  });
  if (bar.children.length) server.appendChild(bar);
  server.appendChild(el("div", "stand-server-note",
    `${sum.services || 0} сервисов · ${sum.findings || 0} находок`));

  canvas.querySelectorAll(".stand-svc").forEach((node) => node.remove());
  (view.services || []).forEach((service) => {
    const card = buildServiceCard(service);
    card.dataset.id = service.id;
    card.dataset.worst = service.worst || "info";
    canvas.appendChild(card);
  });
  layoutStand();
  // Панель могла быть скрыта в момент отрисовки: после показа размеры другие.
  requestAnimationFrame(layoutStand);
}

function layoutStand() {
  const canvas = $("#stand-canvas");
  const view = state.stand;
  if (!canvas || !view) return;
  const width = canvas.clientWidth || 800;
  const height = canvas.clientHeight || 540;
  const cards = Array.from(canvas.querySelectorAll(".stand-svc"));
  const cx = width / 2;
  const cy = height / 2;
  const rx = Math.max(110, width * 0.36);
  const ry = Math.max(100, height * 0.33);
  const svg = $("#stand-links");
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.textContent = "";
  cards.forEach((card, index) => {
    const angle = -Math.PI / 2 + (2 * Math.PI * index) / Math.max(1, cards.length);
    const x = cx + rx * Math.cos(angle);
    const y = cy + ry * Math.sin(angle);
    card.style.left = x + "px";
    card.style.top = y + "px";
    card.style.transform = "translate(-50%, -50%)";
    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    line.setAttribute("x1", String(cx));
    line.setAttribute("y1", String(cy));
    line.setAttribute("x2", String(x));
    line.setAttribute("y2", String(y));
    line.setAttribute("class", "stand-link " + (card.dataset.worst || "info"));
    svg.appendChild(line);
  });
}

function findingRow(finding) {
  const row = el("div", "srow");
  row.appendChild(el("span", "dot " + (finding.severity || "info")));
  row.appendChild(confPill(finding));
  if (finding.review) row.appendChild(el("span", "pill review", "проверить"));
  row.appendChild(el("span", "t", `${finding.kind_ru || finding.rule}`));
  row.appendChild(el("span", "ln", ":" + (finding.line || 0)));
  row.addEventListener("click", () => {
    const full = state.findings.find(
      (item) => (finding.fingerprint && item.fingerprint === finding.fingerprint)
        || (finding.id && item.id === finding.id)
    );
    if (full) {
      selectFinding(full);
      showTab("findings");
    } else {
      toast("эта находка не из текущего среза — нужен свежий аудит", "bad");
    }
  });
  return row;
}

function renderStandSide() {
  const body = $("#stand-side-body");
  if (!body) return;
  body.textContent = "";
  const view = state.stand;
  if (!view) return;

  const service = (view.services || []).find((item) => item.id === state.standSelected);
  if (!service) {
    body.appendChild(el("h3", null, "Обзор стенда"));
    body.appendChild(el("p", "lead",
      "Клик по карточке сервиса покажет его находки: класс, уверенность, строку. "
      + "Дальше клик по находке открывает её разбор и правку."));
    const risky = (view.services || [])
      .slice()
      .sort((a, b) => (b.risk || 0) - (a.risk || 0))
      .slice(0, 4);
    const list = el("div", "scroll");
    risky.forEach((item) => {
      const row = el("div", "srow");
      row.appendChild(el("span", "dot " + (item.worst || "info")));
      row.appendChild(el("span", "t", `${item.name} · ${item.port || "?"}`));
      row.appendChild(el("span", "ln", `риск ${item.risk || 0}`));
      row.addEventListener("click", () => {
        state.standSelected = item.id;
        renderStandCanvas();
        renderStandSide();
      });
      list.appendChild(row);
    });
    if (risky.length) body.appendChild(list);
    const loose = (view.loose || []).length;
    if (loose) {
      body.appendChild(el("p", "lead",
        `${loose} находок не привязаны к сервису: у сервиса не задан каталог. `
        + "Задайте каталог в «правке» или заполните стенд из аудита."));
    }
    return;
  }

  const head = el("div", "head");
  head.appendChild(el("h3", null, service.name));
  head.appendChild(el("span", "pill " + (service.worst || "info"), service.worst || "info"));
  body.appendChild(head);
  body.appendChild(el("div", "loc",
    `${service.port ? ":" + service.port : "порт не задан"} · ${service.language || "язык не задан"}`
    + (service.cwd ? ` · ${service.cwd}` : "")));
  if (service.url) body.appendChild(el("div", "loc", service.url));

  const grid = el("div", "grid3");
  const cell = (value, label) => {
    const box = el("div", "cell");
    box.appendChild(el("div", "n", String(value)));
    box.appendChild(el("div", "l", label));
    return box;
  };
  grid.appendChild(cell((service.counts || {}).high || 0, "high"));
  grid.appendChild(cell((service.confidence || {}).unsure || 0, "не уверен"));
  grid.appendChild(cell(service.risk || 0, "риск / 100"));
  body.appendChild(grid);

  const stateLine = el("p", "lead");
  stateLine.textContent = `живость: ${STAND_LAMP[service.health] || "?"} · `
    + `открыто: ${(service.status || {}).open || 0} · закрыто: ${(service.status || {}).fixed || 0}`;
  body.appendChild(stateLine);

  const findings = service.findings || [];
  body.appendChild(el("h3", null, `Находки: ${findings.length}`));
  if (!findings.length) {
    body.appendChild(el("div", "empty", "чисто — либо не сканировали, либо правда чисто"));
    return;
  }
  const list = el("div", "scroll");
  findings
    .slice()
    .sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9))
    .forEach((finding) => list.appendChild(findingRow(finding)));
  body.appendChild(list);
}

function renderStandField() {
  const view = state.stand;
  if (!view) return;
  const field = $("#stand-field");
  field.textContent = "";
  const total = Number((view.field || {}).teams_total || 0);
  const shown = Math.min(total, 64);
  for (let index = 0; index < shown; index += 1) {
    const dot = el("span", "team-dot" + (index === 0 ? " ours" : ""));
    dot.title = index === 0 ? "наша команда" : `команда ${index + 1}`;
    field.appendChild(dot);
  }
  if (total > shown) field.appendChild(el("span", "member-chip", `+${total - shown}`));
  if (!total) field.appendChild(el("span", "empty", "команд на поле не задано"));

  const roster = $("#stand-roster");
  roster.textContent = "";
  const members = (view.field || {}).members || [];
  members.forEach((name) => roster.appendChild(el("span", "member-chip", name)));
  if (!members.length) roster.appendChild(el("span", "empty", "состав не задан"));
  $("#stand-field-status").textContent = `${total} команд · ${members.length} в составе`;
}

/* ---------- правка стенда ---------- */

function openStandEditor() {
  const view = state.stand;
  if (!view) return;
  state.standEdit = true;
  const model = view.model || {};
  $("#edit-event").value = model.event || "";
  $("#edit-team").value = model.team || "";
  $("#edit-teams").value = model.teams_total || 0;
  $("#edit-round").value = model.round_minutes || 5;
  $("#edit-server").value = (model.server || {}).name || "";
  $("#edit-host").value = (model.server || {}).host || "";
  $("#edit-members").value = ((view.field || {}).members || []).join("\n");
  const table = $("#edit-services tbody");
  table.textContent = "";
  (model.services || []).forEach((service) => addServiceRow(service));
  if (!(model.services || []).length) addServiceRow(null);
  $("#stand-edit-card").hidden = false;
  $("#btn-stand-edit").textContent = "скрыть правку";
}

function closeStandEditor() {
  state.standEdit = false;
  $("#stand-edit-card").hidden = true;
  $("#btn-stand-edit").textContent = "правка";
}

function addServiceRow(service) {
  const table = $("#edit-services tbody");
  const row = el("tr");
  const field = (value, cls, placeholder) => {
    const cell = el("td");
    const input = el("input", cls || null);
    input.value = value || "";
    input.placeholder = placeholder || "";
    cell.appendChild(input);
    row.appendChild(cell);
    return input;
  };
  field((service || {}).name, "svc-name", "notes");
  field((service || {}).port, "svc-port port-input", "8081");
  field((service || {}).language, "svc-lang", "python");
  field((service || {}).cwd, "svc-cwd", "/srv/notes");
  field((service || {}).notes, "svc-notes", "заметка");
  const actions = el("td");
  const remove = el("button", "ghost small", "убрать");
  remove.addEventListener("click", () => row.remove());
  actions.appendChild(remove);
  row.appendChild(actions);
  table.appendChild(row);
}

function collectStandModel() {
  const services = [];
  Array.from($("#edit-services tbody").rows).forEach((row) => {
    const pick = (cls) => {
      const input = row.querySelector("." + cls);
      return input ? input.value.trim() : "";
    };
    const name = pick("svc-name");
    const port = parseInt(pick("svc-port"), 10) || 0;
    if (!name && !port) return;
    services.push({
      name, port,
      language: pick("svc-lang"),
      cwd: pick("svc-cwd"),
      notes: pick("svc-notes"),
    });
  });
  return {
    event: $("#edit-event").value.trim(),
    team: $("#edit-team").value.trim(),
    teams_total: parseInt($("#edit-teams").value, 10) || 0,
    round_minutes: parseInt($("#edit-round").value, 10) || 5,
    server: {
      name: $("#edit-server").value.trim(),
      host: $("#edit-host").value.trim(),
    },
    members: $("#edit-members").value.split("\n").map((line) => line.trim()).filter(Boolean),
    services,
  };
}

async function saveStand() {
  const status = $("#stand-edit-status");
  setStatus(status, "сохраняю…");
  try {
    const result = await api("/api/topology", {
      method: "POST",
      body: JSON.stringify({ model: collectStandModel() }),
    });
    state.stand = result.view;
    (result.view.notes || []).forEach((note) => toast(note, "warn"));
    closeStandEditor();
    renderStand();
    setStatus(status, "сохранено", "ok");
    toast("стенд сохранён", "ok");
  } catch (error) {
    setStatus(status, error.message, "bad");
    toast(error.message, "bad");
  }
}

async function importStand() {
  const status = $("#stand-status");
  setStatus(status, "дополняю из аудита…");
  try {
    const result = await api("/api/topology/import", { method: "POST", body: "{}" });
    state.stand = result.view;
    renderStand();
    const info = result.merge || {};
    setStatus(status, `сервисов в аудите: ${info.found || 0}, добавлено ${info.added || 0}`, "ok");
    toast(`стенд дополнен: добавлено ${info.added || 0}`, "ok");
    if (state.standEdit) openStandEditor();
  } catch (error) {
    setStatus(status, error.message, "bad");
    toast(error.message, "bad");
  }
}

$("#btn-stand-edit").addEventListener("click", () => {
  if (state.standEdit) closeStandEditor();
  else openStandEditor();
});
$("#btn-stand-cancel").addEventListener("click", closeStandEditor);
$("#btn-stand-save").addEventListener("click", saveStand);
$("#btn-stand-import").addEventListener("click", importStand);
$("#btn-stand-add").addEventListener("click", () => addServiceRow(null));

let standResize = null;
window.addEventListener("resize", () => {
  clearTimeout(standResize);
  standResize = setTimeout(layoutStand, 120);
});

/* ---------- глобальный поиск ---------- */

let searchTimer = null;

async function runGlobalSearch(raw) {
  const box = $("#search-results");
  const query = (raw || "").trim();
  if (query.length < 2) {
    box.hidden = true;
    box.textContent = "";
    return;
  }
  try {
    const result = await api("/api/search?q=" + encodeURIComponent(query));
    box.textContent = "";
    if (!result.total) {
      box.appendChild(el("div", "empty", "ничего не нашлось"));
      box.hidden = false;
      return;
    }
    const group = (title, items, render) => {
      if (!items.length) return;
      box.appendChild(el("div", "search-group", title + " · " + items.length));
      items.forEach(render);
    };
    group("находки", result.findings || [], (item) => {
      const hit = el("div", "search-hit");
      hit.appendChild(el("span", "dot " + (item.severity || "info")));
      hit.appendChild(el("span", "t", `${item.kind_ru || item.rule} · ${item.file}:${item.line}`));
      if (item.confidence) {
        hit.appendChild(el("span", "pill conf-" + item.confidence,
          { certain: "уверен", likely: "скорее да", unsure: "не уверен" }[item.confidence] || item.confidence));
      }
      hit.addEventListener("click", () => {
        const full = state.findings.find((entry) => entry.id === item.id);
        box.hidden = true;
        if (full) {
          selectFinding(full);
          showTab("findings");
        }
      });
      box.appendChild(hit);
    });
    group("правила", result.rules || [], (item) => {
      const hit = el("div", "search-hit");
      hit.appendChild(el("span", "t", `${item.id} · ${item.kind_ru || item.kind}`));
      hit.appendChild(el("span", "m", item.severity));
      hit.addEventListener("click", () => {
        box.hidden = true;
        showTab("rules");
        $("#rules-search").value = item.id;
        state.rulesFilter = item.id;
        // Поиск из шапки должен показать правило, а не спрятать его фильтром важности.
        state.rulesSev = "";
        $$("#rules-sev .sev-chip").forEach(
          (node) => node.classList.toggle("active", !(node.dataset.sev || ""))
        );
        renderRules();
      });
      box.appendChild(hit);
    });
    group("база знаний", result.knowledge || [], (item) => {
      const hit = el("div", "search-hit");
      hit.appendChild(el("span", "t", `${item.name}:${item.line} — ${item.preview}`));
      hit.addEventListener("click", () => {
        box.hidden = true;
        showTab("knowledge");
      });
      box.appendChild(hit);
    });
    box.hidden = false;
  } catch (error) {
    box.textContent = error.message;
    box.hidden = false;
  }
}

$("#global-search").addEventListener("input", (event) => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => runGlobalSearch(event.target.value), 180);
});
document.addEventListener("click", (event) => {
  const box = $("#search-results");
  if (!box || box.hidden) return;
  if (!event.target.closest(".global-search")) box.hidden = true;
});

/* ---------- старт ---------- */

async function boot() {
  try {
    const current = await api("/api/state");
    state.config = { target: current.target || {} };
    state.demo = Boolean(current.demo);
    state.version = current.version;
    renderBudget(current.budget);
    fillForm();
    renderBadges();
  } catch (error) {
    setStatus($("#connect-status"), "сервер не отвечает: " + error.message, "bad");
  }

  try {
    const last = await api("/api/last");
    if (last && last.findings) ingest(last);
  } catch (_) { /* аудита ещё нет */ }

  const hash = (location.hash || "").replace("#", "");
  showTab(TITLES[hash] ? hash : "connect", false);

  loadRules();
  loadKnowledge();
  loadDrills();
  makeAllSortable();

  $("#map-search").addEventListener("input", renderMap);
  $("#map-open-only").addEventListener("change", renderMap);
  $("#map-certain").addEventListener("change", renderMap);
  $("#map-unresolved").addEventListener("change", renderMap);
  $("#btn-journal-refresh").addEventListener("click", loadJournal);
  $("#btn-journal-diff").addEventListener("click", loadJournalDiff);
  $("#f-sort").value = state.sort;
}

boot();
