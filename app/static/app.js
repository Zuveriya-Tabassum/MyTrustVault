"use strict";
// SECURITY: user-controlled text is only ever inserted via textContent/createTextNode, never innerHTML.
// CSP forbids inline styles/scripts, so animation is driven by CSS classes and CSSOM custom properties.
const NS = "http://www.w3.org/2000/svg";
const ICONS = {
  shield: "M12 2l8 3v6c0 5-3.5 9.3-8 11-4.5-1.7-8-6-8-11V5z M9 12l2 2 4-4", file: "M6 2h8l5 5v15H6z M14 2v5h5",
  upload: "M12 16V4 M7 9l5-5 5 5 M4 20h16", download: "M12 4v12 M7 11l5 5 5-5 M4 20h16", trash: "M4 7h16 M9 7V4h6v3 M6 7l1 13h10l1-13",
  x: "M6 6l12 12 M18 6L6 18", check: "M5 13l4 4L19 7", alert: "M12 3l10 18H2z M12 10v5 M12 18v.5", user: "M12 12a4 4 0 100-8 4 4 0 000 8 M4 21c0-4 4-6 8-6s8 2 8 6",
  search: "M11 4a7 7 0 100 14 7 7 0 000-14 M21 21l-5-5", share: "M18 8a3 3 0 100-6 3 3 0 000 6 M6 15a3 3 0 100-6 3 3 0 000 6 M18 22a3 3 0 100-6 3 3 0 000 6 M8.6 13.5l6.8 4 M15.4 6.5l-6.8 4",
  eye: "M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z M12 9a3 3 0 100 6 3 3 0 000-6",
  spark: "M12 3l2 6 6 2-6 2-2 6-2-6-6-2 6-2z", logout: "M10 4H5v16h5 M15 8l4 4-4 4 M19 12H9", lock: "M6 11h12v10H6z M8 11V7a4 4 0 018 0v4",
  chart: "M4 20V10 M10 20V4 M16 20v-8 M22 20H2", folder: "M3 6h7l2 2h9v11H3z",
};
function icon(n) {
  const s = document.createElementNS(NS, "svg"); s.setAttribute("viewBox", "0 0 24 24"); s.setAttribute("class", "ic"); s.setAttribute("aria-hidden", "true");
  for (const d of ICONS[n].split(" M")) { const p = document.createElementNS(NS, "path"); p.setAttribute("d", (d[0] === "M" ? "" : "M") + d); s.append(p); }
  return s;
}
function h(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (k === "vars") for (const [a, b] of Object.entries(v)) e.style.setProperty(a, b);   // CSSOM: allowed by CSP
    else if (v !== false && v != null) e.setAttribute(k, v);
  }
  for (const c of kids.flat()) e.append(c instanceof Node ? c : document.createTextNode(c ?? ""));
  return e;
}
const sv = (tag, attrs, ...kids) => { const e = document.createElementNS(NS, tag); for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v); kids.flat().forEach((c) => e.append(c)); return e; };
const raf2 = (f) => requestAnimationFrame(() => requestAnimationFrame(f));

let inflight = 0; const bar = h("div", { class: "topbar" }); document.body.append(bar);
async function api(method, url, body, form) {
  inflight++; bar.classList.add("on");
  try { return await api0(method, url, body, form); } finally { if (--inflight === 0) bar.classList.remove("on"); }
}
async function api0(method, url, body, form) {
  const o = { method, headers: {}, credentials: "same-origin" };
  if (S.csrf) o.headers["X-CSRF-Token"] = S.csrf;
  if (form) o.body = form; else if (body !== undefined) { o.headers["Content-Type"] = "application/json"; o.body = JSON.stringify(body); }
  const r = await fetch(url, o); let d = null; try { d = await r.json(); } catch (_) {}
  if (!r.ok) throw Object.assign(new Error(d && typeof d.detail === "string" ? d.detail : d && d.detail ? "Invalid input" : r.statusText), { status: r.status });
  return d;
}

const S = { me: null, csrf: null, tab: "docs", sel: null, grants: null, sugg: null };
const root = document.getElementById("app");
let view, drawer, overlay, toasts;

function toast(msg, bad) {
  if (!toasts) return;
  const t = h("div", { class: "toast" + (bad ? " bad" : ""), role: "status" }, icon(bad ? "alert" : "check"), h("span", {}, msg));
  toasts.append(t); setTimeout(() => { t.classList.add("out"); setTimeout(() => t.remove(), 320); }, 3800);
}
async function guard(fn, btn) {
  if (btn) { btn.disabled = true; }
  try { await fn(); } catch (e) {
    if (e.status === 401 && S.me) { S.me = null; S.csrf = null; showLogin(); setTimeout(() => toast("Session ended. Please sign in again.", true), 50); return; }
    toast(e.message, true);
  } finally { if (btn) btn.disabled = false; }
}
function countUp(el, n) {
  const t0 = performance.now(), dur = 900;
  const step = (t) => { const p = Math.min(1, (t - t0) / dur), e = 1 - Math.pow(1 - p, 3); el.textContent = Math.round(n * e).toLocaleString(); if (p < 1) requestAnimationFrame(step); };
  requestAnimationFrame(step);
}

// ---------------- login ----------------
function showLogin() {
  const email = h("input", { type: "email", placeholder: "Email", autocomplete: "username", "aria-label": "Email" });
  const pw = h("input", { type: "password", placeholder: "Password", autocomplete: "current-password", "aria-label": "Password" });
  const eye = h("button", { class: "eye", type: "button", "aria-label": "Show password", onclick: () => { pw.type = pw.type === "password" ? "text" : "password"; } }, icon("eye"));
  const err = h("p", { class: "err", role: "alert" });
  const btn = h("button", { class: "btn" }, "Sign in");
  const go = async () => {
    err.textContent = ""; btn.disabled = true; btn.replaceChildren(h("span", { class: "spin" }), "Signing in…");
    try {
      const r = await api("POST", "/auth/login", { email: email.value, password: pw.value });
      S.csrf = r.csrf; S.me = { email: r.email, role: r.role }; S.tab = "docs"; mountShell();
    } catch (e) { err.textContent = e.message; btn.disabled = false; btn.replaceChildren("Sign in"); }
  };
  btn.addEventListener("click", go); pw.addEventListener("keydown", (e) => e.key === "Enter" && go());
  const fill = (e) => { email.value = e + "@trustvault.test"; pw.value = "ChangeMe-Demo-2026!"; pw.focus(); };
  toasts = h("div", { id: "toasts", "aria-live": "polite" });
  root.replaceChildren(toasts, h("div", { class: "hero" }, h("i", { class: "blob b1" }), h("i", { class: "blob b2" }), h("i", { class: "blob b3" }),
    h("div", { class: "login" }, h("div", { class: "logo" }, icon("shield")), h("h1", {}, "TrustVault"),
      h("p", {}, "The wrong person can never read the file. You can prove who did."), email, h("div", { class: "pwrow" }, pw, eye), btn, err,
      h("div", { class: "demo" }, "Demo: ", ["admin", "owner", "viewer"].map((r) => h("button", { onclick: () => fill(r) }, r))))));
}

// ---------------- shell ----------------
function mountShell() {
  const tabs = [["docs", "Documents", "folder"]].concat(S.me.role === "admin" ? [["admin", "Admin", "chart"]] : []);
  const tabEls = tabs.map(([k, l, ic]) => h("button", { class: "tab" + (S.tab === k ? " on" : ""), onclick: () => { S.tab = k; closeDrawer(); tabEls.forEach((t, i) => t.classList.toggle("on", tabs[i][0] === k)); route(); } }, icon(ic), " ", l));
  view = h("main", {}); overlay = h("div", { class: "overlay", onclick: closeDrawer });
  drawer = h("aside", { class: "drawer", role: "dialog", "aria-modal": "true", "aria-label": "Document details" }); toasts = h("div", { id: "toasts", "aria-live": "polite" });
  root.replaceChildren(h("header", {}, h("div", { class: "brand" }, h("span", { class: "mark" }, icon("shield")), "TrustVault"),
    h("div", { class: "tabs" }, tabEls),
    h("div", { class: "who" }, icon("user"), h("span", { class: "em" }, S.me.email), h("span", { class: "chip" }, S.me.role)),
    h("button", { class: "btn sec sm", onclick: () => guard(async () => { await api("POST", "/auth/logout"); S.me = null; S.csrf = null; showLogin(); }) }, icon("logout"), "Sign out")),
    view, overlay, drawer, toasts);
  route();
}
document.addEventListener("keydown", (e) => e.key === "Escape" && closeDrawer());
function route() { const n = S.tab === "admin" ? adminView() : docsView(); n.classList.add("enter"); view.replaceChildren(n); }

// ---------------- documents ----------------
const F = { q: "", owner: "", category: "", date_from: "", date_to: "" };
let list, debounce;
const fmt = (n) => (n > 1048576 ? (n / 1048576).toFixed(1) + " MB" : Math.max(1, Math.ceil(n / 1024)) + " KB");
const ext = (n) => (n.includes(".") ? n.split(".").pop().toLowerCase() : "file");

function docsView() {
  const inp = (k, ph, type) => h("input", { type: type || "text", placeholder: ph, value: F[k], "aria-label": ph, oninput: (e) => { F[k] = e.target.value; clearTimeout(debounce); debounce = setTimeout(loadDocs, 280); } });
  list = h("div", { class: "grid" });
  const wrap = h("div", {}, h("div", { class: "toolbar" }, inp("q", "Search by name…"), inp("owner", "Owner email"), inp("category", "Category"), inp("date_from", "From", "date"), inp("date_to", "To", "date")));
  if (S.me.role === "owner") wrap.append(uploader());
  wrap.append(list); loadDocs(); return wrap;
}
function loadDocs() {
  list.replaceChildren(...[0, 1, 2].map(() => h("div", { class: "sk" })));
  const p = new URLSearchParams(); Object.entries(F).forEach(([k, v]) => v && p.set(k, v));
  guard(async () => {
    const docs = await api("GET", "/documents?" + p);
    list.replaceChildren(...(docs.length ? docs.map((d, i) => h("button", { class: "dcard" + (S.sel && S.sel.id === d.id ? " sel" : ""), vars: { "--i": Math.min(i, 12) }, onclick: () => openDoc(d) },
      h("div", { class: "row" }, h("div", { class: "ft " + ext(d.name) }, ext(d.name).slice(0, 4).toUpperCase()), h("div", { class: "grow" }, h("div", { class: "dname" }, d.name), h("div", { class: "mut" }, d.owner))),
      h("div", { class: "meta" }, h("span", { class: "chip" }, d.category), fmt(d.size), "·", d.created_at.slice(0, 10))))
      : [h("div", { class: "empty" }, sv("svg", { viewBox: "0 0 24 24", class: "ic" }, sv("path", { d: "M3 6h7l2 2h9v11H3z" })), h("div", {}, "Nothing here yet."), h("small", {}, "You only ever see documents you own or were granted."))]));
  });
}
function uploader() {
  const f = h("input", { type: "file", class: "sr", id: "fi" }), cat = h("input", { value: "general", placeholder: "Category", "aria-label": "Category" });
  const box = h("div", { class: "drop", tabindex: "0", role: "button", onclick: (e) => e.target === cat || f.click() },
    icon("upload"), h("div", { class: "grow" }, h("b", {}, "Drop a file or click to upload"), h("div", { class: "mut" }, "pdf, png, jpg, docx, txt · max 10 MB · type is verified by content")), cat, f);
  const send = (file) => guard(async () => {
    const fd = new FormData(); fd.append("file", file); fd.append("category", cat.value || "general");
    box.classList.add("over"); await api("POST", "/documents", undefined, fd); toast("Uploaded and logged"); loadDocs();
  }).finally(() => box.classList.remove("over"));
  f.addEventListener("change", () => f.files[0] && send(f.files[0]));
  box.addEventListener("dragover", (e) => { e.preventDefault(); box.classList.add("over"); }); box.addEventListener("dragleave", () => box.classList.remove("over"));
  box.addEventListener("drop", (e) => { e.preventDefault(); e.dataTransfer.files[0] && send(e.dataTransfer.files[0]); });
  return box;
}

// ---------------- drawer ----------------
function closeDrawer() { if (!drawer) return; drawer.classList.remove("open"); overlay.classList.remove("show"); S.sel = null; document.querySelectorAll(".dcard.sel").forEach((c) => c.classList.remove("sel")); }
function openDoc(d) {
  S.sel = d; S.grants = null; S.sugg = null; S.act = null; fillDrawer(); overlay.classList.add("show"); raf2(() => drawer.classList.add("open"));
  if (d.owner === S.me.email) refreshShare();
}
function refreshShare() {
  const d = S.sel; guard(async () => {
    const [g, s, a] = await Promise.all([api("GET", `/documents/${d.id}/grants`), api("GET", `/documents/${d.id}/suggestions`), api("GET", `/documents/${d.id}/activity`)]);
    if (S.sel && S.sel.id === d.id) { S.grants = g; S.sugg = s; S.act = a; fillDrawer(); }
  });
}
function fillDrawer() {
  const d = S.sel, mine = d.owner === S.me.email;
  const name = h("input", { value: d.name, "aria-label": "Name" }), cat = h("input", { value: d.category, "aria-label": "Category" });
  const close = h("button", { class: "btn sec sm", onclick: closeDrawer, "aria-label": "Close" }, icon("x"));
  const nodes = [h("div", { class: "head" }, h("div", { class: "ft " + ext(d.name) }, ext(d.name).slice(0, 4).toUpperCase()), h("h2", {}, d.name), close),
    h("dl", { class: "kv" }, h("dt", {}, "Owner"), h("dd", {}, d.owner), h("dt", {}, "Size"), h("dd", {}, fmt(d.size)), h("dt", {}, "Uploaded"), h("dd", {}, d.created_at.replace("T", " ").slice(0, 16)), h("dt", {}, "SHA-256"), h("dd", {}, d.sha256)),
    h("div", { class: "row", }, h("a", { class: "btn", href: `/documents/${d.id}/download` }, icon("download"), "Download"),
      mine ? h("button", { class: "btn bad", onclick: (e) => confirm("Delete this document? Everyone's access ends.") && guard(async () => { await api("DELETE", `/documents/${d.id}`); closeDrawer(); toast("Deleted. All access closed."); loadDocs(); }, e.currentTarget) }, icon("trash"), "Delete") : ""),
    h("h3", {}, "Rename (needs edit access)"),
    h("div", { class: "row" }, h("div", { class: "grow" }, name), cat, h("button", { class: "btn sec", onclick: (e) => guard(async () => { S.sel = await api("PATCH", `/documents/${d.id}`, { name: name.value, category: cat.value }); toast("Saved and logged"); fillDrawer(); loadDocs(); }, e.currentTarget) }, "Save"))];
  nodes.push(mine ? [sharePanel(d), timeline()] : h("p", { class: "mut" }, icon("lock"), " Only the owner can see or change who has access."));
  drawer.replaceChildren(...nodes.flat());
  drawer.querySelectorAll(".meter i").forEach((m) => raf2(() => m.style.setProperty("width", m.dataset.w + "%")));
}
const AVERB = { download: "downloaded", upload: "uploaded", update: "edited", delete: "deleted", grant: "was given access", grant_change: "access level changed", revoke: "access revoked", ai_suggest: "asked for suggestions", ai_reject: "dismissed a suggestion", read: "opened" };
function ago(ts) { const s = Math.max(1, Math.round((Date.now() - new Date(ts + "Z")) / 1000)); return s < 60 ? s + "s ago" : s < 3600 ? Math.round(s / 60) + " min ago" : s < 86400 ? Math.round(s / 3600) + " h ago" : Math.round(s / 86400) + " d ago"; }
function timeline() {
  const box = h("div", {}, h("h3", {}, "Access history · who touched this, and when"));
  if (S.act === null) return box.append(h("div", { class: "sk" })) || box;
  if (!S.act.length) return box.append(h("div", { class: "mut" }, "No activity yet.")) || box;
  box.append(h("ol", { class: "tl" }, S.act.map((a, i) => h("li", { class: a.outcome === "denied" ? "bad" : "ok", vars: { "--i": Math.min(i, 10) } },
    h("i", {}, icon(a.outcome === "denied" ? "x" : "check")),
    h("div", {}, h("div", {}, h("b", {}, a.actor), " ", a.outcome === "denied" ? "was refused: " + (a.action) : (AVERB[a.action] || a.action)),
      h("small", { class: "mut", title: a.ts }, ago(a.ts) + (a.reason ? " · " + a.reason : "")))))));
  return box;
}
function sharePanel(d) {
  const email = h("input", { type: "email", placeholder: "person@company.com", "aria-label": "Email to share with" });
  const lvl = h("select", { "aria-label": "Access level" }, h("option", { value: "read" }, "can read"), h("option", { value: "edit" }, "can edit"));
  const give = (em, l, fromS, btn) => guard(async () => { await api("PUT", `/documents/${d.id}/grants`, { email: em, level: l, from_suggestion: !!fromS }); toast("Access granted and logged"); refreshShare(); }, btn);
  const box = h("div", {}, h("h3", {}, "Who has access"),
    h("div", { class: "glist" }, S.grants === null ? h("div", { class: "sk" }) : S.grants.length ? S.grants.map((g) => h("div", { class: "grow-item" }, h("span", { class: "avatar" }, g.email[0].toUpperCase()), h("div", { class: "grow" }, g.email), h("span", { class: "chip" }, g.level),
      h("button", { class: "btn sec sm", onclick: (e) => guard(async () => { await api("DELETE", `/documents/${d.id}/grants/${g.user_id}`); toast("Revoked. Effective immediately."); refreshShare(); }, e.currentTarget) }, "Revoke")))
      : h("div", { class: "mut" }, "Only you.")),
    h("div", { class: "row" }, h("div", { class: "grow" }, email), lvl, h("button", { class: "btn", onclick: (e) => give(email.value, lvl.value, false, e.currentTarget) }, icon("share"), "Grant")));
  if (S.sugg && S.sugg.length) {
    box.append(h("h3", {}, "Suggested people · advice only"));
    S.sugg.forEach((s) => box.append(h("div", { class: "sug" }, h("div", { class: "row" }, icon("spark"), h("b", { class: "grow" }, s.email), h("span", { class: "chip" }, s.source === "llm" ? "AI re-ranked" : "similarity")),
      h("div", { class: "mut" }, s.reason), h("div", { class: "meter" }, h("i", { "data-w": Math.round(s.score * 100) })),
      h("div", { class: "row" }, h("span", { class: "mut grow" }, Math.round(s.score * 100) + "% match. Nothing happens until you confirm."),
        h("button", { class: "btn sm", onclick: (e) => give(s.email, "read", true, e.currentTarget) }, "Grant read"),
        h("button", { class: "btn sec sm", onclick: (e) => guard(async () => { await api("POST", `/documents/${d.id}/suggestions/reject`, { email: s.email }); S.sugg = S.sugg.filter((x) => x !== s); fillDrawer(); }, e.currentTarget) }, "Dismiss")))));
  }
  return box;
}

// ---------------- admin ----------------
function adminView() {
  const out = h("div", { class: "stack" }, h("div", { class: "stats" }, [0, 1, 2, 3, 4].map(() => h("div", { class: "sk" }))));
  Promise.all([api("GET", "/admin/stats"), api("GET", "/admin/flags"), api("GET", "/admin/users"), api("GET", "/admin/documents"), api("GET", "/admin/audit?limit=150")])
    .then(([st, fl, us, dc, au]) => { if (S.tab !== "admin") return; out.replaceChildren(...adminParts(st, fl, us, dc, au)); out.querySelectorAll(".chart").forEach((c) => raf2(() => c.classList.add("go"))); out.querySelectorAll(".donut circle.v").forEach((c) => raf2(() => c.style.setProperty("stroke-dasharray", c.dataset.da))); out.querySelectorAll("[data-n]").forEach((e) => countUp(e, +e.dataset.n)); })
    .catch((e) => toast(e.message, true));
  return out;
}
function barChart(days) {
  const W = 560, H = 190, pad = 22, bw = (W - pad * 2) / days.length, mx = Math.max(4, ...days.map((d) => d.ok + d.denied));
  const svg = sv("svg", { viewBox: `0 0 ${W} ${H}`, class: "chart", role: "img", "aria-label": "Activity over the last 14 days" });
  [0, .5, 1].forEach((t) => svg.append(sv("line", { class: "gl", x1: pad, x2: W - pad, y1: H - 22 - t * (H - 40), y2: H - 22 - t * (H - 40) })));
  days.forEach((d, i) => {
    const x = pad + i * bw + 4, w = bw - 8, ho = (d.ok / mx) * (H - 40), hd = (d.denied / mx) * (H - 40);
    const r1 = sv("rect", { class: "bar ok", x, y: H - 22 - ho, width: w, height: Math.max(0, ho), rx: 3 }); r1.style.setProperty("--i", i);
    const r2 = sv("rect", { class: "bar den", x, y: H - 22 - ho - hd, width: w, height: Math.max(0, hd), rx: 3 }); r2.style.setProperty("--i", i);
    const t = sv("title", {}); t.textContent = `${d.d}: ${d.ok} allowed/logged, ${d.denied} refused`; r1.append(t);
    svg.append(r1, r2); if (i % 2 === 0) { const l = sv("text", { x: x + w / 2, y: H - 6, "text-anchor": "middle" }); l.textContent = d.d.slice(5); svg.append(l); }
  });
  return svg;
}
function donut(ok, den) {
  const C = 2 * Math.PI * 52, tot = Math.max(1, ok + den), a = (ok / tot) * C, b = (den / tot) * C;
  const svg = sv("svg", { viewBox: "0 0 140 140", class: "donut", role: "img", "aria-label": `${ok} allowed, ${den} refused`, width: 170, height: 170 });
  const g = sv("g", { transform: "rotate(-90 70 70)" });
  g.append(sv("circle", { class: "trk", cx: 70, cy: 70, r: 52 }),
    Object.assign(sv("circle", { class: "v a", cx: 70, cy: 70, r: 52, "stroke-dasharray": `0 ${C}`, "data-da": `${a} ${C}` })),
    Object.assign(sv("circle", { class: "v b", cx: 70, cy: 70, r: 52, "stroke-dasharray": `0 ${C}`, "data-da": `${b} ${C}`, "stroke-dashoffset": -a })));
  const t = sv("text", { x: 70, y: 76, "text-anchor": "middle" }); t.textContent = Math.round((den / tot) * 100) + "% refused"; t.setAttribute("font-size", "13"); t.setAttribute("fill", "currentColor");
  svg.append(g, t); return svg;
}
function flagText(f) {
  if (f.type === "repeated_denials") return ["bad", `User #${f.actor_id} had ${f.count} refused attempts in 24h`, "Possible probing"];
  if (f.type === "access_attempt_after_revoke") return ["bad", `User #${f.actor_id} tried document ${f.doc_id.slice(0, 8)}… ${f.count}× after access was revoked`, "Stale link or bookmark?"];
  if (f.type === "download_burst") return ["warn", `User #${f.actor_id} downloaded ${f.count} files in one hour (robust z = ${f.z})`, "Statistical outlier vs the organisation's norm"];
  return ["warn", `User #${f.actor_id} made ${f.count} downloads between 00:00 and 05:00 UTC`, "Off-hours access"];
}
function adminParts(st, fl, us, dc, au) {
  const T = st.totals, ok = st.days.reduce((a, d) => a + d.ok, 0), den = st.days.reduce((a, d) => a + d.denied, 0);
  const stat = (label, n, i) => h("div", { class: "stat", vars: { "--i": i } }, h("b", { "data-n": n }, "0"), h("span", {}, label));
  const cards = h("div", { class: "stats" }, stat("Users", T.users, 0), stat("Live documents", T.documents, 1), stat("Active grants", T.grants, 2), stat("Audit events", T.audit, 3), stat("Refused attempts", T.denied, 4));
  const charts = h("div", { class: "two" }, h("div", { class: "card" }, h("h2", {}, icon("chart"), "Activity, last 14 days"), barChart(st.days),
    h("div", { class: "legend" }, h("span", {}, h("i", { class: "lg1" }), "Succeeded"), h("span", {}, h("i", { class: "lg2" }), "Refused"))),
    h("div", { class: "card", }, h("h2", {}, icon("shield"), "Allowed vs refused"), h("div", { class: "row" }, donut(ok, den))));
  const flags = h("div", { class: "card" }, h("h2", {}, icon("alert"), "Worth noticing ", h("span", { class: "chip warn" }, "advisory")),
    fl.length ? fl.map((f, i) => { const [sev, msg, why] = flagText(f); return h("div", { class: "flag " + sev, vars: { "animation-delay": i * 60 + "ms" } }, icon("alert"), h("div", {}, h("div", {}, msg), h("small", { class: "mut" }, why))); }) : h("div", { class: "mut" }, icon("check"), " Nothing unusual. Detectors: refused-attempt count, access after revoke, download-burst outlier (median/MAD), off-hours access."));
  const verify = h("span"); const vb = h("button", { class: "btn sm", onclick: (e) => guard(async () => { const v = await api("GET", "/admin/audit/verify"); verify.replaceChildren(h("span", { class: "verify chip " + (v.ok ? "ok" : "bad") }, icon(v.ok ? "check" : "alert"), v.ok ? `Chain intact · ${v.rows} rows` : `TAMPERED at row ${v.first_bad_id}`), v.ok ? h("small", { class: "mut" }, ` head ${v.head.slice(0, 16)}… (record off-system)`) : ""); }, e.currentTarget) }, icon("shield"), "Verify audit chain");
  const audit = h("div", { class: "card" }, h("h2", {}, "Audit trail"), h("div", { class: "row" }, vb, verify), h("div", { class: "tw" }, h("table", {}, h("thead", {}, h("tr", {}, ["#", "Time (UTC)", "Actor", "Action", "Result", "Target", "Reason", "Detail"].map((x) => h("th", {}, x)))),
    h("tbody", {}, au.map((a, i) => h("tr", { vars: { "animation-delay": Math.min(i, 15) * 25 + "ms" } }, h("td", {}, a.id), h("td", {}, a.ts.replace("T", " ").slice(0, 19)), h("td", {}, a.actor_id ?? "—"), h("td", {}, a.action),
      h("td", {}, h("span", { class: "chip " + (a.outcome === "denied" ? "bad" : "ok") }, a.outcome)), h("td", {}, (a.target || "").slice(0, 8)), h("td", {}, a.reason), h("td", { class: "wrap mut" }, a.detail)))))));
  const em = h("input", { type: "email", placeholder: "email", "aria-label": "New user email" }), pw = h("input", { type: "password", placeholder: "password (12+ chars)", "aria-label": "New user password" });
  const role = h("select", { "aria-label": "Role" }, ["viewer", "owner", "admin"].map((r) => h("option", { value: r }, r)));
  const users = h("div", { class: "card" }, h("h2", {}, icon("user"), "Users"), h("div", { class: "glist" }, us.map((u) => h("div", { class: "grow-item" }, h("span", { class: "avatar" }, u.email[0].toUpperCase()), h("div", { class: "grow" }, u.email), h("span", { class: "chip" }, u.role),
    u.active ? (u.email !== S.me.email ? h("button", { class: "btn bad sm", onclick: (e) => confirm("Disable " + u.email + "? Their sessions and grants end now.") && guard(async () => { await api("POST", `/admin/users/${u.id}/disable`); toast("User disabled. Sessions and grants ended."); route(); }, e.currentTarget) }, "Disable") : "") : h("span", { class: "chip bad" }, "disabled")))),
    h("h3", {}, "Create user"), h("div", { class: "row" }, h("div", { class: "grow" }, em), pw, role, h("button", { class: "btn", onclick: (e) => guard(async () => { await api("POST", "/admin/users", { email: em.value, password: pw.value, role: role.value }); toast("User created"); route(); }, e.currentTarget) }, "Create")));
  const docs = h("div", { class: "card" }, h("h2", {}, icon("folder"), "All documents ", h("span", { class: "chip" }, "metadata only")), h("div", { class: "tw" }, h("table", {}, h("tbody", {}, dc.map((d) => h("tr", {}, h("td", {}, d.name), h("td", {}, d.owner), h("td", {}, d.category), h("td", {}, d.deleted ? h("span", { class: "chip bad" }, "deleted") : "")))))));
  return [cards, charts, flags, audit, h("div", { class: "two" }, users, docs)];
}

(async function boot() {
  try { const m = await api("GET", "/me"); S.me = m; S.csrf = m.csrf; mountShell(); } catch (_) { showLogin(); }
})();
