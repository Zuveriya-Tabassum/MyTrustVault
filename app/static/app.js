"use strict";
// All user-controlled text is inserted with textContent/createTextNode, never innerHTML (stored-XSS defence).
const S = { csrf: null, me: null, tab: "docs", sel: null, msg: "" };
const root = document.getElementById("app");

function h(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) e.setAttribute(k, v);
  }
  for (const c of kids.flat()) e.append(c instanceof Node ? c : document.createTextNode(c ?? ""));
  return e;
}
async function api(method, url, body, form) {
  const o = { method, headers: {}, credentials: "same-origin" };
  if (S.csrf) o.headers["X-CSRF-Token"] = S.csrf;
  if (form) o.body = form;
  else if (body !== undefined) { o.headers["Content-Type"] = "application/json"; o.body = JSON.stringify(body); }
  const r = await fetch(url, o);
  let d = null; try { d = await r.json(); } catch (_) {}
  if (!r.ok) {
    const m = d && typeof d.detail === "string" ? d.detail : (d && d.detail ? "Invalid input" : r.statusText);
    throw Object.assign(new Error(m), { status: r.status });
  }
  return d;
}
const flash = (m, bad) => { S.msg = m ? { m, bad } : ""; };
async function guard(fn) { try { await fn(); } catch (e) { if (e.status === 401) { S.me = null; } flash(e.message, true); } render(); }

async function boot() {
  try { const m = await api("GET", "/me"); S.me = m; S.csrf = m.csrf; } catch (_) { S.me = null; }
  render();
}

function render() {
  root.replaceChildren(S.me ? shell() : loginView());
}

function loginView() {
  const email = h("input", { type: "email", placeholder: "Email", autocomplete: "username" });
  const pw = h("input", { type: "password", placeholder: "Password", autocomplete: "current-password" });
  const go = async () => {
    try {
      const r = await api("POST", "/auth/login", { email: email.value, password: pw.value });
      S.csrf = r.csrf; S.me = { email: r.email, role: r.role }; flash(""); S.sel = null; S.tab = "docs";
    } catch (e) { flash(e.message, true); }
    render();
  };
  pw.addEventListener("keydown", (e) => e.key === "Enter" && go());
  return h("div", { class: "card login" }, h("h2", {}, "TrustVault sign in"),
    email, pw, h("button", { onclick: go }, "Sign in"),
    S.msg ? h("p", { class: "err" }, S.msg.m) : "",
    h("p", { class: "mut" }, "Every access to a document is decided by the server and recorded."));
}

function shell() {
  const tabs = [["docs", "Documents"]].concat(S.me.role === "admin" ? [["admin", "Admin"]] : []);
  return h("div", {},
    h("header", {}, h("h1", {}, "TrustVault"),
      h("div", { class: "tabs" }, tabs.map(([k, l]) => h("button", { class: S.tab === k ? "on" : "", onclick: () => { S.tab = k; S.sel = null; render(); } }, l))),
      h("span", { class: "tag" }, `${S.me.email} · ${S.me.role}`),
      h("button", { class: "sec", onclick: () => guard(async () => { await api("POST", "/auth/logout"); S.me = null; S.csrf = null; }) }, "Sign out")),
    h("main", {}, S.msg ? h("div", { class: "card " + (S.msg.bad ? "err" : "okc") }, S.msg.m) : "",
      S.tab === "docs" ? docsView() : adminView()));
}

// ---------- documents ----------
const F = { q: "", owner: "", category: "", date_from: "", date_to: "" };
let docs = null, grants = null, sugg = null;

function docsView() {
  if (docs === null) { loadDocs(); }
  const box = h("div", { class: "card" }, h("h2", {}, "Documents"));
  const inp = (k, ph, type) => h("input", { type: type || "text", placeholder: ph, value: F[k], oninput: (e) => (F[k] = e.target.value) });
  box.append(h("div", { class: "row" }, inp("q", "Name contains"), inp("owner", "Owner email"), inp("category", "Category"),
    inp("date_from", "From", "date"), inp("date_to", "To", "date"), h("button", { onclick: loadDocs }, "Search")));
  if (S.me.role === "owner") box.append(uploadForm());
  if (docs) {
    box.append(h("table", {}, h("thead", {}, h("tr", {}, ["Name", "Category", "Owner", "Size", "Uploaded"].map((x) => h("th", {}, x)))),
      h("tbody", {}, docs.length ? docs.map((d) => h("tr", { class: "click", onclick: () => select(d) },
        h("td", {}, d.name), h("td", {}, d.category), h("td", {}, d.owner), h("td", {}, fmt(d.size)), h("td", {}, d.created_at.slice(0, 10))))
        : h("tr", {}, h("td", { colspan: 5, class: "mut" }, "Nothing here. You only see documents you own or were granted.")))));
  }
  return h("div", { class: "grid" }, box, S.sel ? detail() : "");
}
const fmt = (n) => (n > 1048576 ? (n / 1048576).toFixed(1) + " MB" : Math.ceil(n / 1024) + " KB");
function loadDocs() {
  const p = new URLSearchParams(); Object.entries(F).forEach(([k, v]) => v && p.set(k, v));
  guard(async () => { docs = await api("GET", "/documents?" + p); });
}
function uploadForm() {
  const f = h("input", { type: "file" }), c = h("input", { placeholder: "Category", value: "general" });
  return h("div", { class: "row" }, h("strong", {}, "Upload:"), f, c, h("button", { onclick: () => guard(async () => {
    if (!f.files[0]) throw new Error("Choose a file");
    const fd = new FormData(); fd.append("file", f.files[0]); fd.append("category", c.value);
    await api("POST", "/documents", undefined, fd); flash("Uploaded", false); docs = null;
  }) }, "Upload"), h("span", { class: "mut" }, "pdf, png, jpg, docx, txt · max 10 MB"));
}
function select(d) {
  S.sel = d; grants = null; sugg = null;
  if (d.owner === S.me.email) guard(async () => {
    grants = await api("GET", `/documents/${d.id}/grants`);
    sugg = await api("GET", `/documents/${d.id}/suggestions`);
  }); else render();
}
function detail() {
  const d = S.sel, mine = d.owner === S.me.email;
  const name = h("input", { value: d.name }), cat = h("input", { value: d.category });
  const card = h("div", { class: "card" }, h("h2", {}, d.name),
    h("p", { class: "mut" }, `Owner ${d.owner} · ${fmt(d.size)} · SHA-256 ${d.sha256.slice(0, 16)}…`),
    h("div", { class: "row" }, h("a", { href: `/documents/${d.id}/download` }, h("button", {}, "Download")),
      mine ? h("button", { class: "bad", onclick: () => guard(async () => { if (!confirm("Delete this document? Access for everyone ends.")) return; await api("DELETE", `/documents/${d.id}`); S.sel = null; docs = null; flash("Deleted", false); }) }, "Delete") : ""),
    h("h3", {}, "Rename / recategorise (needs edit access)"),
    h("div", { class: "row" }, name, cat, h("button", { class: "sec", onclick: () => guard(async () => {
      S.sel = await api("PATCH", `/documents/${d.id}`, { name: name.value, category: cat.value }); docs = null; flash("Saved", false);
    }) }, "Save")));
  if (mine) card.append(sharePanel(d));
  else card.append(h("p", { class: "mut" }, "Only the owner can see or change who has access."));
  return card;
}
function sharePanel(d) {
  const email = h("input", { type: "email", placeholder: "person@company.com" });
  const lvl = h("select", {}, h("option", { value: "read" }, "read"), h("option", { value: "edit" }, "edit"));
  const give = (em, l, fromS) => guard(async () => {
    await api("PUT", `/documents/${d.id}/grants`, { email: em, level: l, from_suggestion: !!fromS });
    flash("Access granted", false); select(d);
  });
  const sec = h("div", {}, h("h3", {}, "Who has access"),
    h("table", {}, h("tbody", {}, (grants || []).length ? grants.map((g) => h("tr", {}, h("td", {}, g.email), h("td", {}, g.level),
      h("td", {}, h("button", { class: "sec", onclick: () => guard(async () => { await api("DELETE", `/documents/${d.id}/grants/${g.user_id}`); flash("Access revoked, effective immediately", false); select(d); }) }, "Revoke"))))
      : h("tr", {}, h("td", { class: "mut" }, "Only you.")))),
    h("div", { class: "row" }, email, lvl, h("button", { onclick: () => give(email.value, lvl.value, false) }, "Grant")));
  if (sugg && sugg.length) {
    sec.append(h("h3", {}, "Suggestions (advice only. Nothing happens until you confirm)"));
    sugg.forEach((s) => sec.append(h("div", { class: "sug" }, h("strong", {}, s.email), h("div", { class: "mut" }, s.reason),
      h("div", { class: "row" },
        h("button", { onclick: () => give(s.email, "read", true) }, "Grant read"),
        h("button", { class: "sec", onclick: () => guard(async () => { await api("POST", `/documents/${d.id}/suggestions/reject`, { email: s.email }); sugg = sugg.filter((x) => x !== s); }) }, "Dismiss")))));
  }
  return sec;
}

// ---------- admin ----------
const A = { users: null, docs: null, audit: null, flags: null, verify: null, outcome: "" };
function adminView() {
  const load = (k, path) => A[k] === null && (A[k] = [], guard(async () => { A[k] = await api("GET", path); }));
  load("users", "/admin/users"); load("docs", "/admin/documents"); load("flags", "/admin/flags");
  load("audit", "/admin/audit?limit=100" + (A.outcome ? "&outcome=" + A.outcome : ""));
  const em = h("input", { type: "email", placeholder: "email" }), pw = h("input", { type: "password", placeholder: "password (12+ chars)" });
  const role = h("select", {}, ["viewer", "owner", "admin"].map((r) => h("option", { value: r }, r)));
  const users = h("div", { class: "card" }, h("h2", {}, "Users"),
    h("table", {}, h("tbody", {}, (A.users || []).map((u) => h("tr", {}, h("td", {}, u.email), h("td", {}, u.role), h("td", {}, u.active ? "active" : "disabled"),
      h("td", {}, u.active && u.email !== S.me.email ? h("button", { class: "bad", onclick: () => guard(async () => { await api("POST", `/admin/users/${u.id}/disable`); A.users = null; flash("User disabled. Sessions and grants ended.", false); }) }, "Disable") : ""))))),
    h("div", { class: "row" }, em, pw, role, h("button", { onclick: () => guard(async () => { await api("POST", "/admin/users", { email: em.value, password: pw.value, role: role.value }); A.users = null; flash("User created", false); }) }, "Create")));
  const flags = h("div", { class: "card" }, h("h2", {}, "Worth noticing"),
    (A.flags || []).length ? h("ul", {}, A.flags.map((f) => h("li", {}, f.type === "repeated_denials" ? `User #${f.actor_id} had ${f.count} refused attempts in 24h` : `User #${f.actor_id} tried document ${f.doc_id} ${f.count}× after access was revoked`))) : h("p", { class: "mut" }, "Nothing flagged."));
  const ver = h("div", { class: "row" }, h("button", { onclick: () => guard(async () => { A.verify = await api("GET", "/admin/audit/verify"); }) }, "Verify audit chain"),
    A.verify ? h("span", { class: A.verify.ok ? "okc" : "err" }, A.verify.ok ? `Intact · ${A.verify.rows} rows · head ${A.verify.head.slice(0, 16)}… (record this off-system)` : `TAMPERED at row ${A.verify.first_bad_id}`) : "");
  const oc = h("select", { onchange: (e) => { A.outcome = e.target.value; A.audit = null; render(); } }, [["", "all"], ["denied", "denied"], ["ok", "ok"]].map(([v, l]) => h("option", { value: v, selected: A.outcome === v }, l)));
  const audit = h("div", { class: "card" }, h("h2", {}, "Audit trail"), h("div", { class: "row" }, "Outcome:", oc), ver,
    h("table", {}, h("thead", {}, h("tr", {}, ["#", "Time", "Actor", "Action", "Result", "Target", "Reason", "Detail"].map((x) => h("th", {}, x)))),
      h("tbody", {}, (A.audit || []).map((a) => h("tr", {}, h("td", {}, a.id), h("td", {}, a.ts.replace("T", " ").slice(0, 19)), h("td", {}, a.actor_id ?? "—"), h("td", {}, a.action),
        h("td", { class: a.outcome === "denied" ? "err" : "" }, a.outcome), h("td", {}, (a.target || "").slice(0, 8)), h("td", {}, a.reason), h("td", { class: "mut" }, a.detail))))));
  const dt = h("div", { class: "card" }, h("h2", {}, "All documents (metadata only. Admins cannot open content)"),
    h("table", {}, h("tbody", {}, (A.docs || []).map((d) => h("tr", {}, h("td", {}, d.name), h("td", {}, d.owner), h("td", {}, d.category), h("td", {}, d.deleted ? "deleted" : ""))))));
  return h("div", { class: "grid" }, flags, audit, users, dt);
}
boot();
