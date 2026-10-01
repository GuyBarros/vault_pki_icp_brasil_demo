const snapshots = {};
const tlsWarnSeconds = 10;
let tlsData = null;
let dbData = null;

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function paint(id, data, render) {
  const key = JSON.stringify(data);
  if (snapshots[id] === key) return false;
  const replaced = snapshots[id] !== undefined;
  snapshots[id] = key;
  const root = document.getElementById(id);
  root.replaceChildren();
  render(root, data);
  return replaced;
}

function renderCertificate(root, data) {
  root.append(el("h2", null, data.heading));
  if (!data.present) {
    root.append(el("p", "message", data.message));
    return;
  }
  if (data.summary) root.append(el("p", "summary", data.summary));
  if (data.checks && data.checks.length) {
    const list = el("ul", "check-list");
    for (const check of data.checks) {
      const item = el("li", check.passed ? "check" : "check fail");
      item.append(el("span", "mark"));
      const copy = el("span");
      copy.append(document.createTextNode(check.label));
      copy.append(el("small", null, " — " + check.detail));
      item.append(copy);
      list.append(item);
    }
    root.append(list);
  }
  root.append(fieldList(data.fields || []));
  if (data.chain && data.chain.length) {
    root.append(el("p", "chain-title", "Chain"));
    const list = el("ol", "chain-list");
    for (const subject of data.chain) list.append(el("li", "mono", subject));
    root.append(list);
  }
  if (data.ca_path) {
    const link = el("a", "download", "Download the issuing CA");
    link.href = data.ca_path;
    root.append(link);
  }
}

function renderDatabase(root, data) {
  root.append(el("h2", null, data.heading));
  if (!data.present) {
    root.append(el("p", "message", data.message));
    return;
  }
  root.append(el("p", "summary", "Vault's database secrets engine created this PostgreSQL role. The password is used for the query and is not sent to the browser."));
  const fields = [
    { label: "Username", value: data.username || "—", mono: true },
    { label: "Session user", value: data.current_user || "—", mono: true },
    { label: "Lease", value: data.lease_id || "not included in this render", mono: true },
    { label: "Lease remaining", value: formatRemaining(data.lease_remaining_seconds) },
    { label: "Rendered", value: data.modified_at || "—" },
  ];
  root.append(fieldList(fields));
  if (data.error) root.append(el("p", "error", data.error));
  if (data.rows && data.rows.length) {
    root.append(el("p", "table-title", "registros"));
    const table = document.createElement("table");
    const head = document.createElement("tr");
    for (const name of ["id", "titulo", "detalhe"]) head.append(el("th", null, name));
    table.append(head);
    for (const row of data.rows) {
      const line = document.createElement("tr");
      line.append(el("td", "mono", String(row.id)));
      line.append(el("td", null, row.titulo));
      line.append(el("td", null, row.detalhe));
      table.append(line);
    }
    root.append(table);
  }
}

function fieldList(fields) {
  const list = el("dl", "fields");
  for (const field of fields) {
    list.append(el("dt", null, field.label));
    list.append(el("dd", field.mono ? "mono" : null, field.value || "—"));
  }
  return list;
}

function formatRemaining(seconds) {
  if (seconds === null || seconds === undefined) return "rendered without a lease duration";
  if (seconds <= 0) return "due for a new credential";
  const minutes = Math.floor(seconds / 60);
  const rest = seconds % 60;
  if (minutes >= 60) {
    const hours = Math.floor(minutes / 60);
    return hours + "h " + (minutes % 60) + "m";
  }
  return minutes + "m " + rest + "s";
}

async function loadPage() {
  try {
    const response = await fetch("/api/status", { cache: "no-store" });
    if (!response.ok) throw new Error("HTTP " + response.status);
    const data = await response.json();
    document.getElementById("source-line").textContent = data.source.label;
    document.getElementById("checked").textContent = "Updated " + new Date(data.checked_at).toLocaleString();
    paint("card-icp", data.icp, renderCertificate);
    paint("card-tls", data.tls, renderCertificate);
    tlsData = data.tls;
    applyTlsColour();
    dbData = data.database;
    paint("card-db", data.database, renderDatabase);
    snapshots["card-db"] = dbIdentity(data.database);
    applyDbColour();
  } catch (error) {
    document.getElementById("source-line").textContent = "Could not read /api/status. " + error.message;
  }
}

async function refreshServiceCertificate() {
  try {
    const response = await fetch("/api/tls", { cache: "no-store" });
    if (!response.ok) throw new Error("HTTP " + response.status);
    const data = await response.json();
    const replaced = paint("card-tls", data, renderCertificate);
    tlsData = data;
    applyTlsColour();
    if (replaced) {
      const card = document.getElementById("card-tls");
      card.classList.remove("card-updated");
      void card.offsetWidth;
      card.classList.add("card-updated");
    }
  } catch (error) {
    return error;
  }
}

function applyTlsColour() {
  const card = document.getElementById("card-tls");
  if (!card) return;
  const soon = tlsIsClose(tlsData);
  card.classList.toggle("ttl-soon", soon);
  if (!tlsData || !tlsData.present) return;
  let badge = card.querySelector(".ttl-state");
  if (!badge) {
    badge = el("p", "ttl-state");
    const heading = card.querySelector("h2");
    if (heading) heading.after(badge);
    else card.prepend(badge);
  }
  badge.textContent = soon ? "Close to expiry" : "Current";
}

function tlsIsClose(data) {
  if (!data || !data.present) return false;
  const fields = {};
  for (const field of data.fields || []) fields[field.label] = field.value;
  const end = Date.parse(fields["Not after"] || "");
  if (!Number.isFinite(end)) return false;
  const remaining = end - Date.now();
  return remaining > 0 && remaining <= tlsWarnSeconds * 1000;
}

async function refreshDatabase() {
  try {
    const response = await fetch("/api/database", { cache: "no-store" });
    if (!response.ok) throw new Error("HTTP " + response.status);
    const data = await response.json();
    const replaced = paintDatabase(data);
    dbData = data;
    applyDbColour();
    if (replaced) flash(document.getElementById("card-db"));
  } catch (error) {
    return error;
  }
}

function paintDatabase(data) {
  const key = dbIdentity(data);
  if (snapshots["card-db"] === key) return false;
  const replaced = snapshots["card-db"] !== undefined;
  snapshots["card-db"] = key;
  const root = document.getElementById("card-db");
  root.replaceChildren();
  renderDatabase(root, data);
  return replaced;
}

function dbIdentity(data) {
  return JSON.stringify({
    present: data.present,
    message: data.message,
    username: data.username,
    lease_id: data.lease_id,
    current_user: data.current_user,
    error: data.error,
    rows: data.rows,
  });
}

function applyDbColour() {
  const card = document.getElementById("card-db");
  if (!card) return;
  const end = dbExpiry(dbData);
  const remaining = end === null ? null : end - Date.now();
  const soon = remaining !== null && remaining > 0 && remaining <= tlsWarnSeconds * 1000;
  card.classList.toggle("ttl-soon", soon);
  paintLeaseRemaining(card, remaining);
  if (!dbData || !dbData.present || end === null) return;
  let badge = card.querySelector(".ttl-state");
  if (!badge) {
    badge = el("p", "ttl-state");
    const heading = card.querySelector("h2");
    if (heading) heading.after(badge);
    else card.prepend(badge);
  }
  badge.textContent = soon ? "Close to expiry" : "Current";
}

function paintLeaseRemaining(card, remainingMs) {
  if (remainingMs === null) return;
  const labels = card.querySelectorAll("dt");
  const values = card.querySelectorAll("dd");
  for (let index = 0; index < labels.length; index += 1) {
    if (labels[index].textContent === "Lease remaining") {
      values[index].textContent = formatRemaining(Math.max(0, Math.round(remainingMs / 1000)));
    }
  }
}

function dbExpiry(data) {
  if (!data || !data.present) return null;
  const end = Date.parse(data.lease_expires_at || "");
  return Number.isFinite(end) ? end : null;
}

function flash(card) {
  if (!card) return;
  card.classList.remove("card-updated");
  void card.offsetWidth;
  card.classList.add("card-updated");
}

loadPage();
setInterval(() => {
  if (document.hidden) return;
  refreshServiceCertificate();
  refreshDatabase();
}, 1000);
setInterval(() => {
  applyTlsColour();
  applyDbColour();
}, 1000);
