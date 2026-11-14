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
  rules: ["Правила сканера", "что находит аудит и как это закрыть"],
  knowledge: ["База знаний", "регламент A/D, патчи, оценка, тренажёр"],
};

const ORDER = ["connect", "audit", "services", "findings", "files", "generator", "report", "traffic", "rules", "knowledge"];

const SEV_ORDER = { high: 0, medium: 1, low: 2, info: 3 };

const VERDICT_RU = {
  signal: "сигнал",
  diff: "отличие",
  clean: "чисто",
  error: "ошибка",
  blocked: "заблокировано",
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
  filter: { q: "", sev: "", kind: "" },
  svcFilter: "",
  liveness: null,
  preflight: null,
  compare: null,
  logUnit: "",
  rulesFilter: "",
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
    const started = await api("/api/audit", { method: "POST", body: "{}" });
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
    (a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9)
  );
  renderBadges();
  renderSummary();
  renderServices();
  renderFindings();
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
  const { q, sev, kind } = state.filter;
  const needle = q.trim().toLowerCase();
  return state.findings.filter((item) => {
    if (sev && item.severity !== sev) return false;
    if (kind && item.kind !== kind) return false;
    if (!needle) return true;
    return `${item.kind} ${item.kind_ru || ""} ${item.file} ${item.snippet} ${item.rule} ${item.language}`.toLowerCase().includes(needle);
  });
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
    const body = el("div", "body");
    body.appendChild(el("b", null, finding.kind_ru || finding.kind));
    body.appendChild(el("small", null, `${finding.file}:${finding.line}`));
    item.appendChild(body);
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
  chips.appendChild(el("span", "pill soft", "риск для чекера: " + (finding.checker_risk || "low")));
  head.appendChild(chips);
  detail.appendChild(head);

  const body = el("div", "body");

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
    (budget ? ` · бюджет ${budget.used}/${budget.capacity}` : "");

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
  const rules = rulesCache.filter((rule) => {
    if (!needle) return true;
    return `${rule.id} ${rule.kind} ${rule.kind_ru || ""} ${(rule.languages || []).join(" ")}`
      .toLowerCase().includes(needle);
  });
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
  if (!rules.length) {
    const row = el("tr");
    const cell = el("td", "empty", "нет совпадений");
    cell.colSpan = 7;
    row.appendChild(cell);
    body.appendChild(row);
  }
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
  if (/^[1-9]$/.test(event.key)) {
    const name = ORDER[Number(event.key) - 1];
    if (name) showTab(name);
    return;
  }
  if (event.key.toLowerCase() === "g") { $("#btn-generate").click(); }
  if (event.key.toLowerCase() === "r") { $("#btn-run-probe").click(); }
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
  const base = drillState.bases[item.service] || "";
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
}

boot();
