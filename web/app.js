/* AD Audit — client. No dependencies, no build step. */
"use strict";

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

const state = {
  config: { target: {} },
  demo: false,
  audit: null,
  findings: [],
  filter: { q: "", sev: "", kind: "" },
  activeFinding: null,
  activeFile: null,
  probe: null,
  report: null,
};

const SEV_ORDER = { high: 0, medium: 1, low: 2, info: 3 };

/* ---------- helpers ---------- */

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function setStatus(node, text, kind) {
  node.textContent = text || "";
  node.className = "status" + (kind ? " " + kind : "");
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function api(path, options) {
  const response = await fetch(path, Object.assign({ headers: { "Content-Type": "application/json" } }, options || {}));
  const text = await response.text();
  let body = null;
  try { body = text ? JSON.parse(text) : null; } catch (_) { body = { raw: text }; }
  if (!response.ok) {
    const message = body && (body.error || body.raw) ? (body.error || body.raw) : response.statusText;
    throw new Error(message);
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

/* ---------- tabs ---------- */

function showTab(name) {
  $$("#tabs button").forEach((button) => button.classList.toggle("active", button.dataset.tab === name));
  $$(".panel").forEach((panel) => panel.classList.toggle("active", panel.id === "panel-" + name));
}

$$("#tabs button").forEach((button) => {
  button.addEventListener("click", () => showTab(button.dataset.tab));
});

/* ---------- connect ---------- */

function fillForm() {
  const target = (state.config && state.config.target) || {};
  $("#cfg-host").value = target.host || "";
  $("#cfg-port").value = target.port || 22;
  $("#cfg-user").value = target.user || "root";
  $("#cfg-auth").value = target.auth === "password" ? "password" : "key";
  $("#cfg-key").value = target.key_path || "";
  $("#password-row").hidden = $("#cfg-auth").value !== "password";
  const connected = Boolean(target.host && target.user);
  const badge = $("#badge-target");
  badge.textContent = connected ? `${target.user}@${target.host}:${target.port || 22}` : "not connected";
  badge.className = "badge" + (connected ? " on" : " off");
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
    fillForm();
    setStatus(status, "saved", "ok");
  } catch (error) {
    setStatus(status, error.message, "bad");
  }
});

$("#btn-test").addEventListener("click", async () => {
  const status = $("#connect-status");
  const log = $("#connect-log");
  setStatus(status, "connecting…");
  try {
    const result = await api("/api/test", { method: "POST", body: "{}" });
    log.hidden = false;
    log.textContent = `backend: ${result.backend}\n$ id\n${result.output}`;
    setStatus(status, "ok", "ok");
  } catch (error) {
    log.hidden = false;
    log.textContent = error.message;
    setStatus(status, "failed", "bad");
  }
});

/* ---------- audit ---------- */

async function pollJob(id, onLog) {
  const started = Date.now();
  for (;;) {
    const job = await api("/api/job?id=" + encodeURIComponent(id));
    if (onLog) onLog(job.log || []);
    if (job.status !== "running") return job;
    if (Date.now() - started > 15 * 60 * 1000) throw new Error("job timed out");
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
  setStatus(status, "starting…");
  try {
    const started = await api("/api/audit", { method: "POST", body: "{}" });
    const job = await pollJob(started.job, (lines) => {
      log.textContent = lines.join("\n");
      log.scrollTop = log.scrollHeight;
      setStatus(status, "running — " + lines.length + " steps");
    });
    if (job.status === "error") throw new Error(job.error || "audit failed");
    ingest(job.result);
    bar.className = "bar done";
    setStatus(status, "done", "ok");
    showTab("findings");
  } catch (error) {
    bar.className = "bar error";
    setStatus(status, error.message, "bad");
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
  renderGeneratorDefaults();
}

function renderBadges() {
  const counts = (state.audit && state.audit.counts) || {};
  const badge = $("#badge-counts");
  if (!state.audit) {
    badge.textContent = "no audit";
    return;
  }
  badge.textContent = `${counts.high || 0} high · ${counts.medium || 0} med · ${counts.low || 0} low`;
  badge.className = "badge" + (counts.high ? " off" : " on");
}

function renderSummary() {
  const audit = state.audit;
  if (!audit) return;
  const counts = audit.counts || {};
  $("#audit-summary").hidden = false;
  $("#sum-high").textContent = counts.high || 0;
  $("#sum-medium").textContent = counts.medium || 0;
  $("#sum-low").textContent = counts.low || 0;
  $("#sum-info").textContent = counts.info || 0;
  $("#sum-files").textContent = (audit.files || []).length;
  $("#sum-endpoints").textContent = (audit.endpoints || []).length;
  $("#sum-services").textContent = (audit.services || []).length;
  $("#sum-time").textContent = (audit.meta && audit.meta.duration_ms) || 0;
}

/* ---------- services ---------- */

function renderServices() {
  const body = $("#services-table tbody");
  body.textContent = "";
  const services = (state.audit && state.audit.services) || [];
  if (!services.length) {
    const row = el("tr");
    const cell = el("td", "empty", "no listening services found");
    cell.colSpan = 6;
    row.appendChild(cell);
    body.appendChild(row);
    return;
  }
  services.forEach((service) => {
    const row = el("tr");
    row.appendChild(el("td", "cell-mono", service.port));
    row.appendChild(el("td", "cell-mono", service.proto));
    row.appendChild(el("td", "cell-mono", service.service || service.process || "?"));
    row.appendChild(el("td", "cell-mono", service.pid ?? "—"));
    row.appendChild(el("td", "cell-mono", service.cwd || "—"));
    const cmd = el("td", "cell-mono", service.cmdline || "—");
    cmd.style.maxWidth = "420px";
    cmd.style.overflow = "hidden";
    cmd.style.textOverflow = "ellipsis";
    cmd.style.whiteSpace = "nowrap";
    row.appendChild(cmd);
    body.appendChild(row);
  });
}

/* ---------- findings ---------- */

function renderKindFilter() {
  const select = $("#f-kind");
  const current = select.value;
  select.textContent = "";
  select.appendChild(new Option("all kinds", ""));
  const kinds = Array.from(new Set(state.findings.map((item) => item.kind))).sort();
  kinds.forEach((kind) => select.appendChild(new Option(kind, kind)));
  select.value = kinds.includes(current) ? current : "";
  state.filter.kind = select.value;
}

function visibleFindings() {
  const { q, sev, kind } = state.filter;
  const needle = q.trim().toLowerCase();
  return state.findings.filter((item) => {
    if (sev && item.severity !== sev) return false;
    if (kind && item.kind !== kind) return false;
    if (!needle) return true;
    const haystack = `${item.kind} ${item.file} ${item.snippet} ${item.rule}`.toLowerCase();
    return haystack.includes(needle);
  });
}

function renderFindings() {
  const list = $("#findings-list");
  list.textContent = "";
  const items = visibleFindings();
  $("#f-count").textContent = `${items.length} / ${state.findings.length}`;
  if (!items.length) {
    list.appendChild(el("div", "empty", state.findings.length ? "no match" : "run an audit"));
    return;
  }
  items.forEach((finding) => {
    const item = el("div", "item");
    item.dataset.id = finding.id;
    if (state.activeFinding && state.activeFinding.id === finding.id) item.classList.add("active");
    item.appendChild(el("span", "pill " + finding.severity, finding.severity));
    const text = el("div", "t");
    text.appendChild(el("b", null, finding.kind));
    text.appendChild(el("small", null, `${finding.file}:${finding.line}`));
    item.appendChild(text);
    item.addEventListener("click", () => selectFinding(finding));
    list.appendChild(item);
  });
}

function selectFinding(finding) {
  state.activeFinding = finding;
  $$("#findings-list .item").forEach((node) => node.classList.toggle("active", node.dataset.id === finding.id));
  renderFindingDetail(finding);
}

function renderFindingDetail(finding) {
  const detail = $("#finding-detail");
  detail.textContent = "";
  const body = el("div", "body");

  const head = el("div");
  head.appendChild(el("h3", null, finding.kind));
  head.appendChild(el("div", "loc", `${finding.file}:${finding.line} · rule ${finding.rule} · ${finding.language || "text"}`));
  body.appendChild(head);

  const meta = el("div", "row");
  meta.appendChild(el("span", "pill " + finding.severity, finding.severity));
  meta.appendChild(el("span", "pill", "checker risk: " + (finding.checker_risk || "low")));
  body.appendChild(meta);

  const why = el("div", "block");
  why.appendChild(el("h4", null, "why it fired"));
  why.appendChild(el("p", null, finding.why));
  body.appendChild(why);

  const patch = el("div", "block");
  patch.appendChild(el("h4", null, "patch"));
  patch.appendChild(el("p", null, finding.patch));
  body.appendChild(patch);

  const ctx = el("div", "block");
  ctx.appendChild(el("h4", null, "context"));
  const box = el("div", "ctx");
  const start = finding.context_start || Math.max(1, finding.line - (finding.context ? finding.context.length : 1) + 1);
  (finding.context || []).forEach((line, index) => {
    const number = start + index;
    const row = el("div", number === finding.line ? "mark" : null, `${String(number).padStart(4)}  ${line}`);
    box.appendChild(row);
  });
  ctx.appendChild(box);
  body.appendChild(ctx);

  const actions = el("div", "row");
  const generate = el("button", "primary", "Generate probe");
  generate.addEventListener("click", () => {
    setGeneratorFinding(finding);
    showTab("generator");
  });
  actions.appendChild(generate);
  const open = el("button", null, "Open file");
  open.addEventListener("click", () => {
    showTab("files");
    readFile(finding.file);
  });
  actions.appendChild(open);
  body.appendChild(actions);

  detail.appendChild(body);
  detail.scrollIntoView({ block: "nearest" });
}

$("#f-search").addEventListener("input", (event) => {
  state.filter.q = event.target.value;
  renderFindings();
});
$("#f-sev").addEventListener("change", (event) => {
  state.filter.sev = event.target.value;
  renderFindings();
});
$("#f-kind").addEventListener("change", (event) => {
  state.filter.kind = event.target.value;
  renderFindings();
});

/* ---------- files ---------- */

async function listPath(path) {
  const status = $("#file-status");
  setStatus(status, "listing…");
  try {
    const result = await api("/api/files?path=" + encodeURIComponent(path));
    const list = $("#files-list");
    list.textContent = "";
    if (!result.entries.length) {
      list.appendChild(el("div", "empty", "empty or unreadable"));
    }
    result.entries.forEach((entry) => {
      const item = el("div", "item");
      item.appendChild(el("span", "pill", entry.type === "dir" ? "dir" : "file"));
      const text = el("div", "t");
      text.appendChild(el("b", null, entry.name));
      text.appendChild(el("small", null, entry.size === null || entry.size === undefined ? "" : entry.size + " B"));
      item.appendChild(text);
      item.addEventListener("click", () => {
        const next = path.replace(/\/+$/, "") + "/" + entry.name;
        $("#path-input").value = next;
        if (entry.type === "dir") listPath(next);
        else readFile(next);
      });
      list.appendChild(item);
    });
    setStatus(status, `${result.entries.length} entries`, "ok");
  } catch (error) {
    setStatus(status, error.message, "bad");
  }
}

async function readFile(path) {
  const view = $("#file-view");
  const status = $("#file-status");
  setStatus(status, "reading…");
  try {
    const result = await api("/api/file?path=" + encodeURIComponent(path));
    $("#path-input").value = path;
    $("#file-path").textContent = result.path || path;
    state.activeFile = result.path || path;
    view.textContent = "";
    if (result.binary) {
      view.appendChild(el("div", "empty", "binary file — not rendered"));
      setStatus(status, "binary", "bad");
      return;
    }
    const hits = new Map();
    (result.findings || []).forEach((finding) => {
      const current = hits.get(finding.line);
      if (!current || (SEV_ORDER[finding.severity] ?? 9) < (SEV_ORDER[current.severity] ?? 9)) {
        hits.set(finding.line, finding);
      }
    });
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
        row.title = `${hit.severity}: ${hit.kind}`;
        row.addEventListener("click", () => {
          selectFinding(hit);
          showTab("findings");
        });
      }
      scroll.appendChild(row);
    }
    view.appendChild(scroll);
    if (lines.length > cap) {
      view.appendChild(el("div", "empty", `truncated at ${cap} of ${lines.length} lines`));
    }
    setStatus(status, `${lines.length} lines · ${(result.findings || []).length} findings`, "ok");
  } catch (error) {
    setStatus(status, error.message, "bad");
  }
}

$("#btn-list").addEventListener("click", () => listPath($("#path-input").value.trim() || "/"));
$("#btn-read").addEventListener("click", () => readFile($("#path-input").value.trim()));
$("#path-input").addEventListener("keydown", (event) => {
  if (event.key === "Enter") readFile($("#path-input").value.trim());
});

/* ---------- generator ---------- */

function serviceFromPath(path) {
  const match = /\/(?:srv|opt|app|var\/www)\/([^/]+)\//.exec(path || "");
  if (match) return match[1];
  const services = (state.audit && state.audit.services) || [];
  const hit = services.find((service) => service.cwd && path && path.startsWith(service.cwd));
  return hit ? hit.service : "service";
}

function endpointFor(finding) {
  const endpoints = (state.audit && state.audit.endpoints) || [];
  const sameFile = endpoints.filter((endpoint) => endpoint.file === finding.file);
  if (sameFile.length) return sameFile[0].path;
  if (endpoints.length) return endpoints[0].path;
  return "/";
}

function renderGeneratorDefaults() {
  if (!state.activeFinding) return;
  setGeneratorFinding(state.activeFinding);
}

function setGeneratorFinding(finding) {
  state.activeFinding = finding;
  $("#g-finding").value = `${finding.kind} @ ${finding.file}:${finding.line}`;
  $("#g-service").value = serviceFromPath(finding.file);
  $("#g-endpoint").value = endpointFor(finding);
  $("#g-lint").hidden = true;
  $("#g-output").textContent = "";
  $("#g-output").appendChild(el("div", "empty", "press Generate probe"));
}

$("#btn-generate").addEventListener("click", async () => {
  const finding = state.activeFinding;
  const status = $("#g-status");
  if (!finding) {
    setStatus(status, "select a finding first", "bad");
    return;
  }
  setStatus(status, "generating…");
  try {
    const result = await api("/api/generate", {
      method: "POST",
      body: JSON.stringify({
        id: finding.id,
        service: $("#g-service").value.trim() || "service",
        endpoint: $("#g-endpoint").value.trim() || null,
      }),
    });
    state.probe = result;
    $("#g-output").textContent = result.code;
    const lint = $("#g-lint");
    lint.hidden = false;
    if (result.lint && result.lint.ok) {
      lint.className = "lint ok";
      lint.textContent = "lint: clean — read-only probe, no state change, no checker call";
    } else {
      lint.className = "lint";
      lint.textContent = "lint: rejected\n" + ((result.lint && result.lint.errors) || []).join("\n");
    }
    setStatus(status, result.manual ? "manual review required" : "read-only probe", result.manual ? "bad" : "ok");
  } catch (error) {
    setStatus(status, error.message, "bad");
  }
});

$("#btn-copy-probe").addEventListener("click", async () => {
  if (!state.probe) return;
  await copyText(state.probe.code);
  setStatus($("#g-status"), "copied", "ok");
});

$("#btn-save-probe").addEventListener("click", () => {
  if (!state.probe) return;
  download(`${state.probe.name || "probe"}.py`, state.probe.code);
});

/* ---------- report ---------- */

$("#btn-report").addEventListener("click", async () => {
  const status = $("#r-status");
  setStatus(status, "building…");
  try {
    const result = await api("/api/report", { method: "POST", body: "{}" });
    state.report = result.markdown;
    $("#r-output").textContent = result.markdown;
    setStatus(status, `${result.markdown.split("\n").length} lines`, "ok");
  } catch (error) {
    setStatus(status, error.message, "bad");
  }
});

$("#btn-copy-report").addEventListener("click", async () => {
  if (!state.report) return;
  await copyText(state.report);
  setStatus($("#r-status"), "copied", "ok");
});

$("#btn-save-report").addEventListener("click", () => {
  if (!state.report) return;
  download("ad-audit-report.md", state.report);
});

/* ---------- rules ---------- */

async function loadRules() {
  try {
    const result = await api("/api/patterns");
    const body = $("#rules-table tbody");
    body.textContent = "";
    result.rules.forEach((rule) => {
      const row = el("tr");
      row.appendChild(el("td", "cell-mono", rule.id));
      row.appendChild(el("td", null, rule.kind));
      const sev = el("td");
      sev.appendChild(el("span", "pill " + rule.severity, rule.severity));
      row.appendChild(sev);
      row.appendChild(el("td", null, rule.why));
      row.appendChild(el("td", null, rule.patch));
      body.appendChild(row);
    });
  } catch (error) {
    console.error(error);
  }
}

/* ---------- knowledge ---------- */

async function loadKnowledge() {
  try {
    const result = await api("/api/knowledge");
    const list = $("#knowledge-list");
    const view = $("#knowledge-view");
    list.textContent = "";
    if (!result.items.length) {
      list.appendChild(el("div", "empty", "no notes in knowledge/"));
      return;
    }
    result.items.forEach((item, index) => {
      const node = el("div", "item");
      node.appendChild(el("div", "t", item.name));
      node.addEventListener("click", () => {
        $$("#knowledge-list .item").forEach((other) => other.classList.remove("active"));
        node.classList.add("active");
        view.textContent = item.text;
      });
      list.appendChild(node);
      if (index === 0) node.click();
    });
  } catch (error) {
    console.error(error);
  }
}

/* ---------- boot ---------- */

async function boot() {
  try {
    const current = await api("/api/state");
    state.config = { target: current.target || {} };
    state.demo = Boolean(current.demo);
    $("#version").textContent = "v" + current.version;
    $("#badge-backend").textContent = "backend: " + current.backend;
    $("#badge-demo").hidden = !current.demo;
    fillForm();
  } catch (error) {
    setStatus($("#connect-status"), "server unreachable: " + error.message, "bad");
  }

  try {
    const last = await api("/api/last");
    if (last && last.findings) ingest(last);
  } catch (_) { /* no audit yet */ }

  loadRules();
  loadKnowledge();
}

boot();
