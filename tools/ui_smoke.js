const { JSDOM } = require("/tmp/node_modules/jsdom");
const BASE = "http://localhost:8766";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function session(email) {
  const html = await (await fetch(BASE + "/")).text();
  const jar = {}; const errors = [];
  const dom = new JSDOM(html, { url: BASE + "/", runScripts: "outside-only", pretendToBeVisual: true });
  const w = dom.window;
  w.fetch = async (url, o = {}) => {
    const headers = { ...(o.headers || {}) }; const c = Object.entries(jar).map(([k, v]) => k + "=" + v).join("; "); if (c) headers.cookie = c;
    const r = await fetch(new URL(url, BASE), { ...o, headers, redirect: "manual" });
    for (const sc of r.headers.getSetCookie()) { const [kv] = sc.split(";"); const [k, v] = kv.split("="); jar[k] = v; }
    return r;
  };
  w.confirm = () => true; w.addEventListener("error", (e) => errors.push(e.message));
  w.eval(await (await fetch(BASE + "/static/app.js")).text());
  await sleep(300);
  const $ = (s) => w.document.querySelector(s), $$ = (s) => [...w.document.querySelectorAll(s)];
  return { w, $, $$, errors, async login(pass) { $("input[type=email]").value = email; $("input[type=password]").value = pass; $(".login .btn").click(); await sleep(900); } };
}
const ok = (c, m) => { console.log((c ? "PASS " : "FAIL ") + m); if (!c) process.exitCode = 1; };
(async () => {
  const PW = "ChangeMe-Demo-2026!";
  let s = await session("owner@trustvault.test");
  ok(!!s.$(".login"), "login screen renders"); await s.login("wrong-password"); ok(/Invalid/.test(s.$(".err").textContent), "bad password shows error, stays on login");
  await s.login(PW); ok(!!s.$("header") && s.$(".chip").textContent === "owner", "owner signs in, shell renders");
  ok(!s.$$(".tab").some((t) => /Admin/.test(t.textContent)), "owner has no Admin tab"); await sleep(400);
  ok(s.$$(".dcard").length === 2, "owner sees exactly their 2 document cards");
  ok(!!s.$(".drop"), "owner sees upload dropzone");
  s.$$(".dcard")[0].click(); await sleep(1200);
  ok(s.$(".drawer").classList.contains("open"), "drawer opens on card click");
  ok(/Who has access/.test(s.$(".drawer").textContent), "owner sees sharing panel");
  ok(s.$$(".sug").length >= 1 || s.$$(".grow-item").length >= 1, "grants/suggestions rendered");
  const sug = s.$(".sug"); console.log("   suggestion:", sug ? sug.textContent.slice(0, 120) : "(none for this doc)");
  s.w.document.dispatchEvent(new s.w.KeyboardEvent("keydown", { key: "Escape" })); await sleep(100); ok(!s.$(".drawer").classList.contains("open"), "Escape closes drawer");
  s.$$(".btn").find((b) => /Sign out/.test(b.textContent)).click(); await sleep(500); ok(!!s.$(".login"), "sign out returns to login");

  s = await session("viewer@trustvault.test"); await s.login(PW); await sleep(400);
  ok(s.$$(".dcard").length === 1, "viewer sees only the 1 granted document");
  ok(!s.$(".drop"), "viewer has no upload box"); s.$(".dcard").click(); await sleep(500);
  ok(/Only the owner can see/.test(s.$(".drawer").textContent), "viewer cannot see sharing panel");

  s = await session("admin@trustvault.test"); await s.login(PW);
  s.$$(".tab").find((t) => /Admin/.test(t.textContent)).click(); await sleep(2200);
  ok(s.$$(".stat").length === 5, "admin dashboard: 5 stat cards");
  ok(s.$$("rect.bar").length >= 14, "bar chart rendered (" + s.$$("rect.bar").length + " bars)");
  ok(s.$$(".donut circle.v").length === 2, "donut rendered");
  ok(s.$$(".stat b").every((b) => +b.textContent.replace(/,/g, "") >= 0) && s.$$(".stat b")[0].textContent !== "0", "count-up animation ran");
  ok(s.$$(".flag").length >= 1, "flags shown: " + (s.$(".flag") ? s.$(".flag").textContent.slice(0, 70) : ""));
  ok(s.$$("tbody tr").length > 5, "audit table populated");
  const vb = s.$$(".btn").find((b) => /Verify/.test(b.textContent)); vb.click(); await sleep(800); ok(/Chain intact/.test(s.$(".verify").textContent), "verify chain shows intact");
  console.log("JS runtime errors:", s.errors.length ? s.errors : "none"); process.exit(process.exitCode || 0);
})();
