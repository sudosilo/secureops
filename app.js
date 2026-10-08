// RED PHONE: SecureOps client. Vanilla JS, no outside scripts, runs under a strict CSP.
// RED PHONE: every piece of user data is escaped before it touches innerHTML.
"use strict";

const $ = (s) => document.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
const CRED = ["Passwords", "Password hints", "Auth tokens", "Security questions and answers"];
const HIGH = [...CRED, "Credit cards", "Partial credit card data", "Credit card CVV", "Bank account numbers", "Government issued IDs", "Social security numbers", "Private messages"];
const MED = ["Phone numbers", "Physical addresses", "Dates of birth", "IP addresses", "Geographic locations", "Employers", "Job titles", "Usernames"];

const S = { data: null, tab: "people", peopleFilter: "All", breachView: "Events", day: DAYS[(new Date().getDay() + 6) % 7], sheet: null, checking: false, status: "" };

// ── API ──
async function api(path, opts = {}) {
  const r = await fetch(path, {
    method: opts.method || "GET",
    headers: opts.body ? { "Content-Type": "application/json" } : {},
    body: opts.body ? JSON.stringify(opts.body) : undefined,
    credentials: "same-origin",
  });
  let j = {};
  try { j = await r.json(); } catch {}
  if (r.status === 401 && path !== "/api/login") { S.data = null; renderLogin(); const e = new Error("Signed out"); e.status = 401; throw e; }
  if (!r.ok) { const e = new Error(j.error || `Request failed (${r.status})`); e.status = r.status; e.body = j; throw e; }
  return j;
}

// ── DERIVED DATA ──
const emailsOf = (e) => [e.email, ...(e.altEmails || [])].filter(Boolean);
const empById = (id) => S.data.employees.find((e) => e.id === id);

function sevOf(b, e) {
  const dc = b.dataClasses || [];
  if (dc.some((x) => CRED.includes(x))) return e.admin ? "critical" : "high";
  if (dc.some((x) => HIGH.includes(x))) return "high";
  if (dc.some((x) => MED.includes(x))) return "medium";
  return "low";
}
function noteOf(b, e) {
  const dc = b.dataClasses || [];
  const sys = (e.systems || []).slice(0, 3).join(", ");
  if (dc.some((x) => CRED.includes(x))) {
    return e.admin
      ? `Login credentials exposed for someone with admin access${sys ? " to " + sys : ""}. Confirm this password is not reused anywhere and that MFA is on.`
      : "Login credentials exposed. Confirm this password is not reused on any work account.";
  }
  if (dc.some((x) => HIGH.includes(x))) return "Financial or identity data exposed. Higher risk of targeted fraud and social engineering.";
  if (dc.some((x) => MED.includes(x))) return "Contact or personal details exposed. Useful to phishers building a profile of this person.";
  return "Limited data exposed.";
}
function breachesOf(e) {
  const out = [];
  for (const em of emailsOf(e)) {
    const r = S.data.results[em];
    if (r) for (const b of r.breaches) out.push({ ...b, email: em, emp: e, sev: sevOf(b, e) });
  }
  return out.sort((a, b) => ORDER[a.sev] - ORDER[b.sev] || (b.date || "").localeCompare(a.date || ""));
}
const allEvents = () => S.data.employees.flatMap(breachesOf).sort((a, b) => ORDER[a.sev] - ORDER[b.sev]);
function worst(list) { for (const s of ["critical", "high", "medium", "low"]) if (list.some((b) => b.sev === s)) return s; return null; }
const checkedCount = (e) => emailsOf(e).filter((x) => S.data.results[x]).length;
const flaggedAdmins = () => S.data.employees.filter((e) => e.admin && ["critical", "high"].includes(worst(breachesOf(e))));
function lastChecked(e) {
  const t = emailsOf(e).map((x) => S.data.results[x]?.checkedAt).filter(Boolean).sort().pop();
  return t ? new Date(t).toLocaleDateString() : null;
}

// ── SMALL PIECES ──
function initials(n) { return n.split(/\s+/).filter(Boolean).slice(0, 2).map((x) => x[0].toUpperCase()).join("") || "?"; }
function avIdx(id) { let h = 0; for (const c of id) h = (h * 31 + c.charCodeAt(0)) >>> 0; return h % 6; }
const av = (e, size = "md") => `<div class="av av${avIdx(e.id)} av-${size}">${esc(initials(e.name))}</div>`;
const sevPill = (s) => `<span class="sev sev-${s}">${SEV_LABEL[s]}</span>`;
function personPill(e) {
  const w = worst(breachesOf(e));
  if (w) return sevPill(w);
  if (checkedCount(e) === 0) return `<span class="sev sev-none">Not checked</span>`;
  return `<span class="sev sev-clean">Clean</span>`;
}
const chips = (opts, cur, key) => `<div class="chips">${opts.map((o) => `<button class="chip${cur === o ? " on" : ""}" data-chip="${key}" data-val="${esc(o)}">${esc(o)}</button>`).join("")}</div>`;
const empty = (msg) => `<div class="empty">${msg}</div>`;

const ICON = {
  people: `<svg viewBox="0 0 24 24"><circle cx="9" cy="8" r="3.5"/><path d="M2.5 20c0-3.6 2.9-6 6.5-6s6.5 2.4 6.5 6"/><path d="M16 4.5a3.5 3.5 0 0 1 0 7M21.5 20c0-3-1.8-5.2-4.5-5.8"/></svg>`,
  breaches: `<svg viewBox="0 0 24 24"><path d="M12 3l8 3v6c0 4.5-3.4 8-8 9-4.6-1-8-4.5-8-9V6l8-3z"/><path d="M12 8v5M12 16.5v.5"/></svg>`,
  schedule: `<svg viewBox="0 0 24 24"><rect x="3.5" y="5" width="17" height="15" rx="2"/><path d="M3.5 10h17M8 3v4M16 3v4"/></svg>`,
  threats: `<svg viewBox="0 0 24 24"><path d="M12 3.5l9 16H3l9-16z"/><path d="M12 10v4M12 17v.5"/></svg>`,
};
const TABS = [
  { id: "people", label: "People" },
  { id: "breaches", label: "Breaches" },
  { id: "schedule", label: "Schedule" },
  { id: "threats", label: "Threats" },
];

// ── VIEWS ──
const VIEWS = {
  people() {
    const E = S.data.employees;
    const list = E.filter((e) => S.peopleFilter === "All" || (S.peopleFilter === "Admins" ? e.admin : breachesOf(e).length > 0))
      .sort((a, b) => a.name.localeCompare(b.name));
    const admins = E.filter((e) => e.admin).length;
    const exposed = E.filter((e) => breachesOf(e).length).length;
    return `
      <div class="title-row"><h1 class="page-title">People</h1><button class="btn" data-act="add-person">Add person</button></div>
      <p class="page-sub">${E.length} people · ${admins} admins · ${exposed} with known exposure</p>
      ${E.length ? chips(["All", "Admins", "Exposed"], S.peopleFilter, "people") : ""}
      ${E.length === 0 ? empty("No people yet. Tap Add person to start tracking access and exposure.")
        : list.length === 0 ? empty("Nobody matches this filter.")
        : `<div class="list">${list.map((e) => `
          <div class="row" data-person="${e.id}">
            ${av(e)}
            <div class="row-main">
              <div class="row-title">${esc(e.name)}${e.admin ? '<span class="tag tag-admin">Admin</span>' : ""}${e.status === "leave" ? '<span class="tag tag-leave">Leave</span>' : ""}</div>
              <div class="row-sub">${esc(e.role || e.email)}</div>
            </div>
            ${personPill(e)}
          </div>`).join("")}</div>`}`;
  },

  breaches() {
    const events = allEvents();
    const companies = Object.values(events.reduce((acc, b) => {
      (acc[b.name] ||= { name: b.name, title: b.title, date: b.date, items: [] }).items.push(b);
      return acc;
    }, {})).sort((a, b) => ORDER[worst(a.items)] - ORDER[worst(b.items)]);
    const unchecked = S.data.employees.filter((e) => checkedCount(e) < emailsOf(e).length).length;
    return `
      <div class="title-row"><h1 class="page-title">Breaches</h1>
        <button class="btn" data-act="check-all" ${S.checking || !S.data.hibp || !S.data.employees.length ? "disabled" : ""}>Check everyone</button></div>
      <p class="page-sub">${events.length} exposures from ${companies.length} compromised companies${unchecked ? ` · ${unchecked} not fully checked` : ""}</p>
      ${!S.data.hibp ? `<div class="notice">Breach lookups are off until the breach service key is added to the server.</div>` : ""}
      <div class="status" id="status">${esc(S.status)}</div>
      ${events.length ? chips(["Events", "By company"], S.breachView, "breach") : ""}
      ${events.length === 0 ? empty(S.data.employees.length ? "No known breaches yet. Run a check to look up everyone's emails." : "Add people first, then check their emails here.")
        : S.breachView === "Events"
        ? `<div class="list">${events.map((b) => `
            <div class="row" data-person="${b.emp.id}">
              ${av(b.emp, "sm")}
              <div class="row-main">
                <div class="row-title">${esc(b.title)}</div>
                <div class="row-sub">${esc(b.emp.name)}${b.emp.admin ? " (admin)" : ""} · ${esc((b.date || "").slice(0, 4))}</div>
              </div>
              ${sevPill(b.sev)}
            </div>`).join("")}</div>`
        : `<div class="list">${companies.map((c) => `
            <div class="row" data-company="${esc(c.name)}">
              <div class="row-main">
                <div class="row-title">${esc(c.title)}</div>
                <div class="row-sub">${c.items.length} ${c.items.length === 1 ? "exposure" : "exposures"} · ${esc((c.date || "").slice(0, 4))}</div>
              </div>
              ${sevPill(worst(c.items))}<span class="chev">›</span>
            </div>`).join("")}</div>`}`;
  },

  schedule() {
    const shifts = S.data.shifts.filter((s) => s.day === S.day && empById(s.employeeId)).sort((a, b) => a.start.localeCompare(b.start));
    const working = new Set(shifts.map((s) => s.employeeId));
    const off = S.data.employees.filter((e) => !working.has(e.id));
    const where = ["HQ", "Remote", "Field"].map((l) => [l, shifts.filter((s) => s.location === l).length]).filter(([, n]) => n);
    return `
      <div class="title-row"><h1 class="page-title">Schedule</h1>
        <button class="btn" data-act="add-shift" ${S.data.employees.length ? "" : "disabled"}>Add shift</button></div>
      <p class="page-sub">${shifts.length} working${where.map(([l, n]) => ` · ${n} ${l === "HQ" ? "at HQ" : l.toLowerCase()}`).join("")}</p>
      ${chips(DAYS, S.day, "day")}
      ${shifts.length === 0 ? empty(S.data.employees.length ? `Nobody scheduled on ${S.day}.` : "Add people first, then build their schedule.")
        : `<div class="list">${shifts.map((s) => { const e = empById(s.employeeId); return `
          <div class="row" data-shift="${s.id}">
            ${av(e, "sm")}
            <div class="row-main">
              <div class="row-title">${esc(e.name)}</div>
              <div class="row-sub">${esc(s.task || e.role || "")}</div>
              <span class="loc loc-${s.location}">${s.location}</span>
            </div>
            <div class="shift-time">${s.start}<br>${s.end}</div>
          </div>`; }).join("")}</div>`}
      ${shifts.length && off.length ? `<div class="off-line">Off: ${off.map((e) => esc(e.name.split(" ")[0])).join(", ")}</div>` : ""}`;
  },

  threats() {
    const flagged = flaggedAdmins().sort((a, b) => ORDER[worst(breachesOf(a))] - ORDER[worst(breachesOf(b))]);
    const systems = [...new Set(S.data.employees.flatMap((e) => e.systems || []))].map((sys) => {
      const owners = S.data.employees.filter((e) => (e.systems || []).includes(sys));
      const exposed = owners.filter((o) => breachesOf(o).length);
      return { sys, owners, exposed, w: worst(owners.flatMap(breachesOf)) };
    }).sort((a, b) => (a.w ? ORDER[a.w] : 9) - (b.w ? ORDER[b.w] : 9) || a.sys.localeCompare(b.sys));
    return `
      <h1 class="page-title">Threats</h1>
      <p class="page-sub">Admins with serious exposure and the systems they can reach</p>
      <div class="list-label">Flagged admins (${flagged.length})</div>
      ${flagged.length === 0 ? empty("No admins with high or critical exposure.")
        : `<div class="list">${flagged.map((e) => `
          <div class="row" data-person="${e.id}">
            ${av(e)}
            <div class="row-main">
              <div class="row-title">${esc(e.name)}</div>
              <div class="row-sub">${(e.systems || []).length} systems · ${esc([...new Set(breachesOf(e).map((b) => b.title))].join(", "))}</div>
            </div>
            ${sevPill(worst(breachesOf(e)))}
          </div>`).join("")}</div>`}
      <div class="list-label">Systems</div>
      ${systems.length === 0 ? empty("Add systems to people's profiles to see which ones are at risk.")
        : `<div class="list">${systems.map((x) => `
          <div class="row static">
            <div class="row-main">
              <div class="row-title">${esc(x.sys)}</div>
              <div class="row-sub">${x.exposed.length} of ${x.owners.length} with access exposed</div>
            </div>
            ${x.w ? sevPill(x.w) : `<span class="sev sev-clean">Clean</span>`}
          </div>`).join("")}</div>`}`;
  },
};

// ── SHELL ──
function render() {
  if (!S.data) return renderLogin();
  const flagged = flaggedAdmins().length;
  const serious = allEvents().filter((b) => b.sev === "critical" || b.sev === "high").length;
  const badge = { breaches: serious, threats: flagged };
  $("#app").innerHTML = `
    <header class="hdr">
      <div class="brand">Secure<span>Ops</span></div>
      ${flagged ? `<button class="alert-btn" data-go="threats"><span class="alert-dot"></span>${flagged} flagged</button>` : ""}
      <button class="ghost" data-act="logout">Sign out</button>
    </header>
    <main class="page">${VIEWS[S.tab]()}</main>
    <nav class="nav">${TABS.map((t) => `
      <button class="nav-btn${S.tab === t.id ? " on" : ""}" data-go="${t.id}">${ICON[t.id]}<span>${t.label}</span>
        ${badge[t.id] ? `<span class="nav-badge">${badge[t.id]}</span>` : ""}</button>`).join("")}
    </nav>`;
}

function renderLogin(msg = "") {
  closeSheet();
  $("#app").innerHTML = `
    <div class="login">
      <div class="brand big">Secure<span>Ops</span></div>
      <form id="loginForm" class="login-card">
        <label>Password<input type="password" name="password" autocomplete="current-password" required></label>
        <button class="btn wide" type="submit">Sign in</button>
        <p class="err" id="loginErr">${esc(msg)}</p>
      </form>
    </div>`;
}

function renderError(msg) {
  $("#app").innerHTML = `<div class="login"><div class="brand big">Secure<span>Ops</span></div>
    <div class="login-card"><p class="err">${esc(msg)}</p><div class="actions"><button class="btn wide" data-act="reload">Try again</button></div></div></div>`;
}

// ── SHEET ──
function openSheet(ctx) { S.sheet = ctx; drawSheet(); $("#overlay").classList.add("open"); $("#sheet").classList.add("open"); document.body.classList.add("locked"); }
function closeSheet() { S.sheet = null; $("#overlay").classList.remove("open"); $("#sheet").classList.remove("open"); document.body.classList.remove("locked"); }
function drawSheet() {
  if (!S.sheet) return;
  const fn = SHEETS[S.sheet.type];
  const html = fn ? fn(S.sheet) : null;
  if (html == null) return closeSheet();
  $("#sheetBody").innerHTML = html;
  $("#sheetBody").scrollTop = 0;
}

const SHEETS = {
  person({ id }) {
    const e = empById(id);
    if (!e) return null;
    const bs = breachesOf(e);
    const lc = lastChecked(e);
    return `
      <div class="s-head">${av(e, "lg")}
        <div><div class="s-name">${esc(e.name)}</div>
          <div class="s-sub">${esc([e.role, e.dept].filter(Boolean).join(" · "))}</div>
          <div class="s-sub">${e.admin ? "Admin access" : "Standard user"}${e.clearance ? " · Clearance " + esc(e.clearance) : ""}${e.startDate ? " · Since " + esc(e.startDate.slice(0, 4)) : ""}</div>
        </div></div>
      <div class="actions">
        <button class="btn" data-act="check-person" data-id="${e.id}" ${S.checking || !S.data.hibp ? "disabled" : ""}>Check breaches</button>
        <button class="btn secondary" data-act="edit-person" data-id="${e.id}">Edit</button>
      </div>
      <div class="status" id="status">${esc(S.status) || (lc ? "Last checked " + esc(lc) : "Never checked")}</div>
      <div class="s-sec"><div class="s-label">Breaches (${bs.length})</div>
        ${bs.length === 0 ? `<div class="s-sub">${checkedCount(e) ? "No known exposure." : "Not checked yet."}</div>` : bs.map((b) => `
          <div class="bcard bl-${b.sev}">
            <div class="b-top"><span class="b-co">${esc(b.title)}</span>${sevPill(b.sev)}</div>
            <div class="b-meta">${esc(b.email)} · ${esc(b.date)}</div>
            <div class="b-note">${esc(noteOf(b, e))}</div>
            <div class="b-types">Exposed: ${esc(b.dataClasses.join(", "))}</div>
          </div>`).join("")}
      </div>
      <div class="s-sec"><div class="s-label">Email addresses</div>
        ${emailsOf(e).map((em) => {
          const r = S.data.results[em];
          const w = r ? worst(r.breaches.map((b) => ({ sev: sevOf(b, e) }))) : null;
          return `<div class="kv"><span class="mono">${esc(em)}</span>${!r ? `<span class="sev sev-none">Not checked</span>` : w ? sevPill(w) : `<span class="sev sev-clean">Clean</span>`}</div>`;
        }).join("")}
      </div>
      ${(e.systems || []).length ? `<div class="s-sec"><div class="s-label">System access</div><div class="pills">${e.systems.map((s) => `<span class="pill">${esc(s)}</span>`).join("")}</div></div>` : ""}`;
  },

  company({ name }) {
    const items = allEvents().filter((b) => b.name === name);
    if (!items.length) return null;
    const b0 = items[0];
    return `
      <div class="s-name">${esc(b0.title)}</div>
      <div class="s-sub">${esc(b0.domain || "")}${b0.domain ? " · " : ""}Breached ${esc(b0.date)}${b0.count ? " · " + Number(b0.count).toLocaleString() + " accounts" : ""}</div>
      ${b0.description ? `<p class="desc">${esc(b0.description)}</p>` : ""}
      <div class="s-sec"><div class="s-label">Your people affected (${items.length})</div>
        ${items.map((b) => `
          <div class="bcard bl-${b.sev}">
            <div class="b-top"><span class="b-co">${esc(b.emp.name)}</span>${sevPill(b.sev)}</div>
            <div class="b-meta">${esc(b.email)}</div>
            <div class="b-note">${esc(noteOf(b, b.emp))}</div>
          </div>`).join("")}
      </div>
      <div class="s-sec"><div class="s-label">Data exposed</div><div class="pills">${b0.dataClasses.map((d) => `<span class="pill">${esc(d)}</span>`).join("")}</div></div>`;
  },

  personForm({ id }) {
    const e = id ? empById(id) : { name: "", role: "", dept: "", email: "", altEmails: [], admin: false, systems: [], clearance: "", status: "active", startDate: "" };
    if (!e) return null;
    return `
      <div class="s-name">${id ? "Edit person" : "Add person"}</div>
      <form id="personForm" data-id="${id || ""}" class="s-sec">
        <label>Name<input name="name" required maxlength="80" value="${esc(e.name)}"></label>
        <div class="grid2">
          <label>Role<input name="role" maxlength="80" value="${esc(e.role)}"></label>
          <label>Department<input name="dept" maxlength="60" value="${esc(e.dept)}"></label>
        </div>
        <label>Work email<input name="email" type="email" required maxlength="254" value="${esc(e.email)}"></label>
        <label>Other emails <span class="hint">one per line, personal or old accounts</span><textarea name="altEmails">${esc((e.altEmails || []).join("\n"))}</textarea></label>
        <label>Systems they can access <span class="hint">separate with commas</span><input name="systems" value="${esc((e.systems || []).join(", "))}"></label>
        <div class="grid2">
          <label>Clearance<input name="clearance" maxlength="10" value="${esc(e.clearance)}"></label>
          <label>Start date<input name="startDate" type="date" value="${esc(e.startDate)}"></label>
        </div>
        <label>Status<select name="status"><option value="active"${e.status !== "leave" ? " selected" : ""}>Active</option><option value="leave"${e.status === "leave" ? " selected" : ""}>On leave</option></select></label>
        <label class="inline"><input type="checkbox" name="admin"${e.admin ? " checked" : ""}> Has admin privileges</label>
        <p class="err" id="formErr"></p>
        <div class="actions">
          <button class="btn" type="submit">Save</button>
          ${id ? `<button class="btn danger" type="button" data-act="delete-person" data-id="${id}">Delete</button>` : ""}
        </div>
      </form>`;
  },

  shiftForm({ id }) {
    const s = id ? S.data.shifts.find((x) => x.id === id) : { employeeId: "", day: S.day, start: "09:00", end: "17:00", location: "HQ", task: "" };
    if (!s) return null;
    const people = [...S.data.employees].sort((a, b) => a.name.localeCompare(b.name));
    return `
      <div class="s-name">${id ? "Edit shift" : "Add shift"}</div>
      <form id="shiftForm" data-id="${id || ""}" class="s-sec">
        <label>Person<select name="employeeId" required>${people.map((e) => `<option value="${e.id}"${e.id === s.employeeId ? " selected" : ""}>${esc(e.name)}</option>`).join("")}</select></label>
        <label>Day<select name="day">${DAYS.map((d) => `<option${d === s.day ? " selected" : ""}>${d}</option>`).join("")}</select></label>
        <div class="grid2">
          <label>Start<input name="start" type="time" required value="${esc(s.start)}"></label>
          <label>End<input name="end" type="time" required value="${esc(s.end)}"></label>
        </div>
        <label>Location<select name="location">${["HQ", "Remote", "Field"].map((l) => `<option${l === s.location ? " selected" : ""}>${l}</option>`).join("")}</select></label>
        <label>Task <span class="hint">optional</span><input name="task" maxlength="60" value="${esc(s.task)}"></label>
        <p class="err" id="formErr"></p>
        <div class="actions">
          <button class="btn" type="submit">Save</button>
          ${id ? `<button class="btn danger" type="button" data-act="delete-shift" data-id="${id}">Delete</button>` : ""}
        </div>
      </form>`;
  },
};

// ── BREACH CHECKS ──
function setStatus(t) { S.status = t; const el = $("#status"); if (el) el.textContent = t; }

async function runChecks(emails) {
  if (S.checking || !emails.length) return;
  S.checking = true; render(); drawSheet();
  let ok = true;
  for (let i = 0; i < emails.length; i++) {
    const email = emails[i];
    setStatus(`Checking ${i + 1} of ${emails.length}: ${email}`);
    for (;;) {
      try {
        const r = await api("/api/check", { method: "POST", body: { email } });
        S.data.results[email] = r.result;
        break;
      } catch (err) {
        if (err.status === 429) {
          const wait = Math.max(2, Number(err.body?.retryAfter) || 7);
          setStatus(`Rate limited by the breach service, waiting ${wait} seconds`);
          await sleep(wait * 1000 + 300);
          continue;
        }
        if (err.status === 401) { S.checking = false; return; }
        ok = false; setStatus(err.message); break;
      }
    }
    if (!ok) break;
    if (i < emails.length - 1) await sleep(1500);
  }
  S.checking = false;
  if (ok) setStatus(`Done. Checked ${emails.length} ${emails.length === 1 ? "email" : "emails"}.`);
  const keep = S.status;
  render(); drawSheet(); setStatus(keep);
}

// ── EVENTS ──
document.addEventListener("click", async (ev) => {
  const t = ev.target.closest("[data-go],[data-act],[data-chip],[data-person],[data-company],[data-shift]");
  if (!t) return;
  if (t.dataset.go) { S.tab = t.dataset.go; S.status = ""; render(); window.scrollTo(0, 0); return; }
  if (t.dataset.chip) {
    const k = t.dataset.chip, v = t.dataset.val;
    if (k === "people") S.peopleFilter = v; else if (k === "breach") S.breachView = v; else if (k === "day") S.day = v;
    render(); return;
  }
  if (t.dataset.person) { S.status = ""; openSheet({ type: "person", id: t.dataset.person }); return; }
  if (t.dataset.company) { openSheet({ type: "company", name: t.dataset.company }); return; }
  if (t.dataset.shift) { openSheet({ type: "shiftForm", id: t.dataset.shift }); return; }

  const act = t.dataset.act;
  if (act === "reload") return boot();
  if (act === "logout") { try { await api("/api/logout", { method: "POST" }); } catch {} S.data = null; renderLogin(); return; }
  if (act === "add-person") return openSheet({ type: "personForm" });
  if (act === "edit-person") return openSheet({ type: "personForm", id: t.dataset.id });
  if (act === "add-shift") return openSheet({ type: "shiftForm" });
  if (act === "check-person") { const e = empById(t.dataset.id); if (e) runChecks(emailsOf(e)); return; }
  if (act === "check-all") { runChecks([...new Set(S.data.employees.flatMap(emailsOf))]); return; }
  if (act === "delete-person" || act === "delete-shift") {
    const isP = act === "delete-person";
    if (!confirm(isP ? "Delete this person, their shifts, and their breach results?" : "Delete this shift?")) return;
    try {
      S.data = await api("/api/save", { method: "POST", body: { kind: isP ? "employee" : "shift", op: "delete", id: t.dataset.id } });
      closeSheet(); render();
    } catch (err) { const el = $("#formErr"); if (el) el.textContent = err.message; }
  }
});

$("#overlay").addEventListener("click", closeSheet);
$("#sheetClose").addEventListener("click", closeSheet);

document.addEventListener("submit", async (ev) => {
  const f = ev.target;
  ev.preventDefault();
  const fd = new FormData(f);
  const btn = f.querySelector('button[type="submit"]');

  if (f.id === "loginForm") {
    btn.disabled = true;
    try { await api("/api/login", { method: "POST", body: { password: fd.get("password") } }); await boot(); }
    catch (err) { $("#loginErr").textContent = err.message; btn.disabled = false; }
    return;
  }

  let body;
  if (f.id === "personForm") {
    body = { kind: "employee", op: "upsert", item: {
      id: f.dataset.id || undefined,
      name: fd.get("name"), role: fd.get("role"), dept: fd.get("dept"), email: fd.get("email"),
      altEmails: String(fd.get("altEmails") || "").split(/[\n,]+/).map((x) => x.trim()).filter(Boolean),
      systems: String(fd.get("systems") || "").split(",").map((x) => x.trim()).filter(Boolean),
      clearance: fd.get("clearance"), startDate: fd.get("startDate"), status: fd.get("status"), admin: fd.get("admin") === "on",
    } };
  } else if (f.id === "shiftForm") {
    body = { kind: "shift", op: "upsert", item: {
      id: f.dataset.id || undefined,
      employeeId: fd.get("employeeId"), day: fd.get("day"), start: fd.get("start"), end: fd.get("end"),
      location: fd.get("location"), task: fd.get("task"),
    } };
  } else return;

  btn.disabled = true;
  try {
    S.data = await api("/api/save", { method: "POST", body });
    if (f.id === "shiftForm") { S.day = body.item.day; closeSheet(); }
    else {
      const saved = S.data.employees.find((e) => e.email === String(body.item.email).trim().toLowerCase());
      if (saved) openSheet({ type: "person", id: saved.id }); else closeSheet();
    }
    render();
  } catch (err) { const el = $("#formErr"); if (el) el.textContent = err.message; btn.disabled = false; }
});

// ── BOOT ──
async function boot() {
  try { S.data = await api("/api/state"); render(); }
  catch (err) { if (err.status !== 401) renderError(err.message); }
}
boot();
