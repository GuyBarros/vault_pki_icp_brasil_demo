const snapshots = {};

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function paint(id, data, render) {
  const key = JSON.stringify(data);
  if (snapshots[id] === key) return;
  snapshots[id] = key;
  const root = document.getElementById(id);
  root.replaceChildren();
  render(root, data);
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

async function tick() {
  try {
    const response = await fetch("/api/status", { cache: "no-store" });
    if (!response.ok) throw new Error("HTTP " + response.status);
    const data = await response.json();
    document.getElementById("source-line").textContent = data.source.label;
    document.getElementById("checked").textContent = "Updated " + new Date(data.checked_at).toLocaleString();
    paint("card-icp", data.icp, renderCertificate);
    paint("card-tls", data.tls, renderCertificate);
    paint("card-db", data.database, renderDatabase);
  } catch (error) {
    document.getElementById("source-line").textContent = "Could not read /api/status. " + error.message;
  }
}

tick();
setInterval(() => {
  if (!document.hidden) tick();
}, 3000);
