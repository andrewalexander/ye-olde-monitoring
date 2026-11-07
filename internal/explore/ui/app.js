// dnscount explorer. Every value shown here can come from the internet
// (paths, user agents, domains), so nothing is ever inserted as HTML: cells,
// labels and tooltips are built with textContent only.
"use strict";

// ---------- small DOM helpers ----------
function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") e.className = v;
    else if (k === "text") e.textContent = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  for (const k of kids.flat()) {
    if (k == null || k === false) continue;
    e.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
  return e;
}
const svgNS = "http://www.w3.org/2000/svg";
function svg(tag, attrs) {
  const e = document.createElementNS(svgNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v);
  return e;
}
const $main = () => document.getElementById("main");

// ---------- formatting ----------
function fmtTime(s) {
  if (!s || s.startsWith("0001-")) return "";
  const d = new Date(s);
  if (isNaN(d)) return String(s);
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}
function fmtNum(n) { return n == null ? "" : Number(n).toLocaleString(); }
function fmtBytes(n) {
  if (n == null) return "";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (Math.abs(n) >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(n < 10 && i ? 1 : 0)} ${u[i]}`;
}
function fmtAge(s) {
  if (s == null || s < 0) return "never";
  if (s < 90) return `${Math.round(s)}s`;
  if (s < 5400) return `${Math.round(s / 60)}m`;
  if (s < 172800) return `${(s / 3600).toFixed(1)}h`;
  return `${(s / 86400).toFixed(1)}d`;
}
function fmtDur(ns) {
  if (!ns) return "";
  return fmtAge(ns / 1e9);
}

// ---------- state & routing ----------
const state = {
  since: localStorageGet("since") || "7d",
  limits: {},
};
function localStorageGet(k) { try { return localStorage.getItem("dnscount." + k); } catch { return null; } }
function localStorageSet(k, v) { try { localStorage.setItem("dnscount." + k, v); } catch { /* private window */ } }

function parseHash() {
  const h = location.hash.replace(/^#\/?/, "");
  const [path, query] = h.split("?");
  const parts = path.split("/").filter(Boolean).map(decodeURIComponent);
  return { view: parts[0] || "overview", arg: parts.slice(1).join("/"), q: new URLSearchParams(query || "") };
}
function href(view, arg, q) {
  let h = "#/" + view;
  if (arg) h += "/" + encodeURIComponent(arg);
  if (q) { const s = new URLSearchParams(q).toString(); if (s) h += "?" + s; }
  return h;
}

async function api(path, params) {
  const u = new URL(path, location.origin);
  for (const [k, v] of Object.entries(params || {})) if (v !== "" && v != null && v !== false) u.searchParams.set(k, v);
  const r = await fetch(u, { headers: { Accept: "application/json" } });
  if (!r.ok) throw new Error(`${r.status}: ${(await r.text()).trim()}`);
  return r.json();
}

// ---------- cell renderers (all text) ----------
function link(view, value, text) {
  if (!value) return document.createTextNode("");
  return el("a", { href: href(view, value), text: text ?? value, title: value });
}
function ipLink(ip) { return link("ip", ip); }
// A LAN client with its lookup count, named when we know the device.
function clientLink(x) {
  const a = link("ip", x.ip, `${x.name || x.ip} (${x.count})`);
  a.title = x.name ? `${x.name}: ${x.ip}` : x.ip;
  return a;
}
function domainLink(d) { return link("domain", d); }
function indicatorLink(ind, kind) { return kind === "domain" ? domainLink(ind) : ipLink(ind); }
function badge(verdict) {
  if (!verdict) return document.createTextNode("");
  return el("span", { class: `badge v-${verdict}`, text: verdict });
}
function tags(list) {
  if (!list || !list.length) return document.createTextNode("");
  return el("span", { class: "tags" }, list.map((t) => el("span", { class: "tag", text: String(t).replace(/^feed:/, "") })));
}
function asnText(r) {
  if (!r || !r.asn) return "";
  return `AS${r.asn}`;
}

// Tabulator formatters: always return a Node, never an HTML string.
const F = {
  text: (c) => { const v = c.getValue(); const s = v == null ? "" : String(v); const sp = el("span", { text: s }); if (s.length > 40) sp.title = s; return sp; },
  num: (c) => document.createTextNode(fmtNum(c.getValue())),
  time: (c) => document.createTextNode(fmtTime(c.getValue())),
  ip: (c) => ipLink(c.getValue()),
  domain: (c) => domainLink(c.getValue()),
  client: (c) => ipLink(c.getValue()),
  verdict: (c) => badge(c.getValue()),
  tags: (c) => tags(c.getValue()),
  list: (c) => document.createTextNode((c.getValue() || []).join(", ")),
  bool: (c) => document.createTextNode(c.getValue() ? "yes" : ""),
  dur: (c) => document.createTextNode(fmtDur(c.getValue())),
  bytes: (c) => document.createTextNode(fmtBytes(c.getValue())),
  leak: (c) => { const v = c.getValue() || 0; return el("span", { class: v > 0 ? "leak" : "", text: v > 0 ? `${v} LEAK` : "0" }); },
};
const sorterTime = (a, b) => String(a || "").localeCompare(String(b || ""));

function col(title, field, kind, extra) {
  const c = { title, field, formatter: F[kind || "text"], headerFilter: false, ...extra };
  if (!kind || kind === "text" || kind === "ip" || kind === "domain" || kind === "client") {
    c.headerFilter = "input";
    c.headerFilterPlaceholder = "filter";
  }
  if (kind === "num" || kind === "leak" || kind === "bytes" || kind === "dur") { c.sorter = "number"; c.hozAlign = "right"; }
  if (kind === "time") c.sorter = sorterTime;
  if (kind === "tags" || kind === "list") {
    c.headerFilter = "input";
    c.headerFilterPlaceholder = "filter";
    c.headerFilterFunc = (term, value) => (value || []).join(" ").toLowerCase().includes(String(term).toLowerCase());
    c.sorter = (a, b) => (a || []).length - (b || []).length;
  }
  if (kind === "verdict") {
    c.sorter = (a, b) => rank(a) - rank(b);
    c.headerFilter = "list";
    c.headerFilterParams = { values: { "": "any", malicious: "malicious", suspicious: "suspicious", info: "info", reserved: "reserved" } };
  }
  return c;
}
// How often fail2ban banned the address in the last 30 days (all jails, not
// counting restores across restarts): the window it doubles repeat bans over.
// Queried providers' columns: abuse score (AbuseIPDB) and open ports (InternetDB and Censys).
function abuseCol() {
  return col("Abuse score", "queried", "text", {
    formatter: (c) => document.createTextNode(abuseText(c.getRow().getData())), headerFilter: false,
    sorter: (a, b, ra, rb) => ((factsOf(ra.getData(), "abuseipdb") || {}).score ?? -1) - ((factsOf(rb.getData(), "abuseipdb") || {}).score ?? -1),
    headerTooltip: "AbuseIPDB: how confident other admins' reports are that this address is abusive (context, not a verdict)",
  });
}
function portsCol() {
  return col("Ports", "queried", "text", {
    formatter: (c) => document.createTextNode(portsText(c.getRow().getData())), headerFilter: "input", headerFilterPlaceholder: "filter",
    headerFilterFunc: (t, v, row) => portsText(row).includes(t), sorter: (a, b, ra, rb) => portsText(ra.getData()).localeCompare(portsText(rb.getData())),
    headerTooltip: "Open ports, from Shodan InternetDB and Censys",
  });
}
function censysWebCol() {
  return col("Censys", "queried", "text", {
    formatter: (c) => document.createTextNode(censysWebText(c.getRow().getData())), headerFilter: false, sorter: undefined,
    headerTooltip: "Censys web property on :443: labels, software, certificate issuer",
  });
}

function bans30() {
  return col("Bans 30d", "bans_30d", "num", { headerTooltip: "Times fail2ban banned this address in the last 30 days, all jails, not counting restarts" });
}
function rank(v) { return { malicious: 3, suspicious: 2, info: 1 }[v] || 0; }

function table(container, rows, columns, opts) {
  const wrap = el("div", { class: "table-wrap" });
  const holder = el("div");
  wrap.append(holder);
  container.append(wrap);
  if (!rows || !rows.length) {
    holder.append(el("p", { class: "muted", style: "padding:8px 12px;margin:0", text: "Nothing here for this window." }));
    return null;
  }
  const t = new Tabulator(holder, {
    data: rows,
    columns,
    layout: "fitDataStretch",
    pagination: rows.length > 50,
    paginationSize: 50,
    paginationSizeSelector: [25, 50, 100, 250],
    placeholder: "Nothing matches the filters",
    movableColumns: true,
    ...opts,
  });
  tablesBuilding.push(new Promise((done) => t.on("tableBuilt", done)));
  return t;
}

// Tables lay themselves out a moment after they're created; a quiet refresh
// waits for them before putting the scroll position back.
let tablesBuilding = [];

// ---------- views ----------
const LIST_VIEWS = {
  ips: {
    title: "Inbound IPs",
    lede: "Public addresses that hit our sites, were banned, raised IDS alerts or tripped a breaker. Flagged ones first.",
    url: "/api/ips", options: ["order"],
    columns: () => [
      col("Verdict", "verdict", "verdict"), col("IP", "ip", "ip"), col("Feeds", "feeds", "tags"),
      col("AS", "asn", "text", { formatter: (c) => document.createTextNode(asnText(c.getRow().getData())) }),
      col("Owner", "as_owner"), col("CC", "country"),
      col("Hits", "hits", "num"), col("4xx", "errors_4xx", "num"), col("Bans", "bans", "num"), bans30(), abuseCol(), portsCol(),
      col("Leaks", "leaks", "leak"), col("Alerts", "alerts_allowed", "num"), col("Blocked", "alerts_blocked", "num"),
      col("Trips", "trips", "num"), col("Refused logins", "auth_failures", "num"), col("Sites", "sites", "list"), col("First", "first", "time"), col("Last", "last", "time"),
    ],
  },
  domains: {
    title: "Domains",
    lede: "What the LAN looked up. A verdict comes from the domain itself (or a parent) being listed, or from an address it resolved to.",
    url: "/api/domains", options: ["order"], defaultOrder: "recent",
    columns: () => [
      col("Verdict", "verdict", "verdict", { mutator: (v, d) => worst(v, d.answers && d.answers.verdict) }),
      col("Domain", "domain", "domain"), col("Feeds", "feeds", "tags"),
      col("Answer feeds", "answers", "tags", { formatter: (c) => tags((c.getValue() || {}).feeds), headerFilter: false, sorter: undefined }),
      col("Lookups", "lookups", "num"), col("Clients", "clients", "num"), col("Blocked", "blocked", "num"), censysWebCol(),
      col("New", "new", "bool"), col("First", "first", "time"), col("Last", "last", "time"),
    ],
  },
  clients: {
    title: "LAN clients",
    lede: "Each device that used the router's DNS, and how many of the names it looked up are flagged. Names come from DHCP, UniFi's client events and the router's neighbour table (which is how IPv6 addresses get one).",
    url: "/api/clients", options: [],
    columns: () => [
      col("Client", "ip", "client"), col("Name", "name"), col("MAC", "mac"), col("Network", "network"),
      col("Flagged", "flagged_domains", "num"),
      col("Flagged examples", "flagged_samples", "list", {
        formatter: (c) => el("span", { class: "tags" }, (c.getValue() || []).map((d) => domainLink(d))),
      }),
      col("Lookups", "lookups", "num"), col("Domains", "domains", "num"), col("New domains", "new_domains", "num"),
      col("First", "first", "time"), col("Last", "last", "time"),
    ],
  },
  flagged: {
    title: "Flagged",
    lede: "Every listed indicator seen in the window: incoming (it reached us), outgoing (the LAN reached it) or both. Choose \"reserved\" to see special-purpose addresses and names instead, such as ipv4only.arpa (NAT64 discovery), which are never flagged.",
    url: "/api/flagged", options: ["verdict"],
    columns: () => [
      col("Verdict", "verdict", "verdict"),
      col("Indicator", "indicator", "text", { formatter: (c) => indicatorLink(c.getValue(), c.getRow().getData().kind) }),
      col("Kind", "kind"), col("Dir", "direction"), col("Feeds", "feeds", "tags"),
      col("AS", "asn", "text", { formatter: (c) => document.createTextNode(asnText(c.getRow().getData())) }),
      col("Owner", "as_owner"), col("CC", "country"),
      col("Hits", "hits", "num"), col("Alerts", "alerts", "num"), col("Bans", "bans", "num"), bans30(), abuseCol(), portsCol(),
      col("LAN clients", "clients", "list", {
        formatter: (c) => el("span", { class: "tags" }, (c.getValue() || []).map(clientLink)),
        headerFilterFunc: (t, v) => (v || []).some((x) => x.ip.includes(t) || (x.name || "").toLowerCase().includes(String(t).toLowerCase())),
      }),
      col("Via", "via_domains", "list", {
        formatter: (c) => el("span", { class: "tags" }, (c.getValue() || []).map((d) => domainLink(d))),
      }),
      col("First", "first_seen", "time"), col("Last", "last_seen", "time"),
    ],
  },
  hits: {
    title: "Hits",
    lede: "Requests to our sites, newest first.",
    url: "/api/hits", options: ["status"],
    columns: () => [
      col("Time", "ts", "time"), col("Site", "site"), col("Client", "client_ip", "ip"), col("Method", "method"),
      col("Host", "host"), col("Path", "path", "text", { maxWidth: 420 }), col("Query", "query", "text", { maxWidth: 240 }),
      col("Status", "status", "num"), col("Bytes", "bytes", "bytes"), col("User agent", "user_agent", "text", { maxWidth: 320 }),
      col("Referer", "referer", "text", { maxWidth: 240 }), bans30(), col("Feeds", "feeds", "tags"),
    ],
  },
  bans: {
    title: "Bans",
    lede: "fail2ban bans paired with their unbans. Any request that got through while a ban was in force is a LEAK.",
    url: "/api/bans", options: [],
    columns: () => [
      col("Banned", "banned_at", "time"), col("Jail", "jail"), col("IP", "ip", "ip"), col("Verdict", "verdict", "verdict"),
      col("Feeds", "feeds", "tags"), col("CC", "country"), col("Failures", "failures", "num"), col("For", "bantime_ns", "dur"),
      col("Unbanned", "unbanned_at", "time", { formatter: (c) => document.createTextNode(fmtTime(c.getValue()) || "still banned") }),
      col("Hits 24h before", "hits_24h_before", "num"), col("Hits during", "hits_during", "leak"), bans30(),
      col("Restart", "restored", "bool", { headerTooltip: "fail2ban re-applying this ban after a restart: the ban before it continuing, not a new one", formatter: (c) => document.createTextNode(c.getValue() ? "restored" : "") }),
    ],
  },
  alerts: {
    title: "IDS/IPS alerts",
    lede: "The router's IPS alerts. allowed = detected only; blocked = dropped by the router. UniFi's events name the LAN device (and its MAC) but often give no address for it; older rows get those fields from the raw-file backfill.",
    url: "/api/alerts", options: ["action"],
    columns: () => [
      col("Time", "ts", "time"), col("Action", "action"), col("Direction", "direction"),
      col("From", "src_ip", "ip"), col("Port", "src_port", "num"), col("From device", "src_name"),
      col("To", "dst_ip", "ip"), col("Port", "dst_port", "num"), col("To device", "dst_name"), col("Proto", "proto"),
      col("Policy", "policy"),
      col("Verdict", "verdict", "verdict"), col("Feeds", "feeds", "tags"), col("CC", "country"),
      col("Signature", "signature", "text", { maxWidth: 380 }), col("Category", "category"),
      col("Severity", "severity", "num"), col("Source hits", "src_hits", "num"), bans30(),
    ],
  },
  trips: {
    title: "Breaker trips",
    lede: "Clients that tripped dnscount's own rate limits.",
    url: "/api/trips", options: [],
    columns: () => [
      col("Trip", "id", "num", { formatter: (c) => link("trip", String(c.getValue()), `#${c.getValue()}`) }),
      col("Tripped", "tripped_at", "time"), col("Breaker", "breaker"), col("Who", "key", "ip"), col("Reason", "reason"),
      col("Events", "window_events", "num"), col("Bad", "window_bad", "num"),
      col("Suppressed", "suppressed_during_cooldown", "num"), col("Ended", "ended_at", "time"), bans30(),
    ],
  },
};
function worst(a, b) { return rank(a) >= rank(b) ? a : b; }

const NAV = [
  ["overview", "Overview"], ["health", "Health"], ["flagged", "Flagged"], ["ips", "Inbound IPs"],
  ["domains", "Domains"], ["clients", "LAN clients"], ["hits", "Hits"], ["bans", "Bans"],
  ["alerts", "Alerts"], ["trips", "Trips"],
];

function renderNav(view) {
  const nav = document.getElementById("nav");
  const parent = { ip: "ips", domain: "domains", trip: "trips" }[view];
  nav.replaceChildren(...NAV.map(([v, t]) => el("a", { href: href(v), class: v === view || v === parent ? "on" : "", text: t })));
}

function optionControls(view, def, q) {
  const box = el("div", { class: "controls" });
  const set = (k, v) => { const nq = new URLSearchParams(q); if (v) nq.set(k, v); else nq.delete(k); location.hash = href(view, "", nq); };
  for (const o of def.options) {
    if (o === "order") {
      const s = el("select", { onchange: (e) => set("order", e.target.value) },
        ["recent", "flagged", "top", "bottom", "new"].map((v) => el("option", { value: v, text: { recent: "latest first", flagged: "worst first", top: "busiest first", bottom: "quietest first", new: "new in window" }[v] })));
      s.value = q.get("order") || def.defaultOrder || "flagged";
      box.append(el("label", {}, "order ", s));
    } else if (o === "verdict") {
      const s = el("select", { onchange: (e) => set("verdict", e.target.value) },
        [["", "malicious + suspicious"], ["malicious", "malicious"], ["all", "all, including info"], ["reserved", "reserved (special-purpose)"]].map(([v, t]) => el("option", { value: v, text: t })));
      s.value = q.get("verdict") || "";
      box.append(el("label", {}, "verdicts ", s));
    } else if (o === "action") {
      const s = el("select", { onchange: (e) => set("action", e.target.value) },
        [["", "any"], ["allowed", "allowed"], ["blocked", "blocked"]].map(([v, t]) => el("option", { value: v, text: t })));
      s.value = q.get("action") || "";
      box.append(el("label", {}, "action ", s));
    } else if (o === "status") {
      const i = el("input", { type: "text", size: 6, placeholder: "404, 4xx", value: q.get("status") || "" });
      i.addEventListener("change", () => set("status", i.value.trim()));
      box.append(el("label", {}, "status ", i));
    }
  }
  return box;
}

async function renderList(view, q) {
  const def = LIST_VIEWS[view];
  const main = $main();
  const limit = state.limits[view] || 200;
  main.replaceChildren(el("h1", { text: def.title }), el("p", { class: "lede", text: def.lede }), optionControls(view, def, q));
  const status = el("p", { class: "muted", text: "Loading…" });
  main.append(status);
  const params = { since: state.since, limit };
  for (const o of def.options) if (q.get(o)) params[o] = q.get(o);
  if (def.defaultOrder && !params.order) params.order = def.defaultOrder;
  const rows = (await api(def.url, params)) || [];
  status.replaceChildren(`${fmtNum(rows.length)} rows (limit ${fmtNum(limit)}). Sort by any column; filter in the headers.`);
  if (rows.length >= limit) {
    status.append(" ", el("button", { text: "Show more", onclick: () => { state.limits[view] = limit * 2; route(); } }));
  }
  table(main, rows, def.columns());
}

function kv(pairs) {
  return el("dl", { class: "kv" }, pairs.filter(([, v]) => v !== undefined).flatMap(([k, v]) => [el("dt", { text: k }), el("dd", {}, v instanceof Node ? v : String(v ?? ""))]));
}

// ---------- queried providers (cached answers: context, not verdicts) ----------
const PROVIDERS = {
  internetdb: { title: "Shodan InternetDB", kinds: ["ip"], auto: true },
  abuseipdb: { title: "AbuseIPDB", kinds: ["ip"], auto: true },
  censys: { title: "Censys", kinds: ["ip", "domain"], auto: false },
};
function lookupOf(row, name) { return row && row.queried && row.queried[name]; }
function factsOf(row, name) { const l = lookupOf(row, name); return (l && l.found && l.facts) || null; }

// One line per provider, for table cells.
function abuseText(row) {
  const f = factsOf(row, "abuseipdb");
  if (!f) return lookupOf(row, "abuseipdb") ? "0% (no reports)" : "";
  return `${f.score}% (${fmtNum(f.reports)} reports)`;
}
function portsText(row) {
  const ports = new Set();
  for (const p of (factsOf(row, "internetdb") || {}).ports || []) ports.add(p);
  for (const s of (factsOf(row, "censys") || {}).services || []) ports.add(s.port);
  return [...ports].sort((a, b) => a - b).join(", ");
}
function censysWebText(row) {
  const f = factsOf(row, "censys");
  if (!f) return lookupOf(row, "censys") ? "nothing found" : "";
  return [...(f.labels || []), ...(f.software || []), f.cert_issuer ? `cert: ${f.cert_issuer}` : ""].filter(Boolean).join(" · ");
}

// The card for one provider's answer about an indicator.
function lookupCard(name, intel, ind, kind) {
  const pv = PROVIDERS[name];
  const l = lookupOf(intel, name);
  const card = el("div", { class: "card lookup" }, el("div", { class: "label", text: pv.title }));
  if (!l) {
    card.append(el("p", { class: "muted" }, pv.auto
      ? "Not asked yet. The hourly run asks about addresses that are listed, banned or alerting."
      : el("span", {}, "Not looked up. To spend a credit on it, on the server: ",
          el("code", { text: `dnscount-admin enrich -provider ${name} -ip ${ind} -limit 1` }),
          " (NixOS; elsewhere ", el("code", { text: "dnscount enrich" }), ")")));
    return card;
  }
  const asOf = `as of ${fmtTime(l.as_of)}`;
  if (!l.found) {
    card.append(el("p", { class: "muted", text: `Nothing known (${asOf}).` }));
    return card;
  }
  const f = l.facts || {};
  let rows = [];
  if (name === "internetdb") {
    rows = [["Ports", (f.ports || []).join(", ") || "none"], ["Hostnames", (f.hostnames || []).join(", ") || undefined],
      ["Software", (f.cpes || []).join(", ") || undefined], ["CVEs", (f.vulns || []).length ? tags(f.vulns) : undefined],
      ["Tags", (f.tags || []).length ? tags(f.tags) : undefined]];
  } else if (name === "abuseipdb") {
    rows = [["Abuse score", `${f.score}%`], ["Reports", `${fmtNum(f.reports)} from ${fmtNum(f.users)} users`],
      ["Last reported", f.last_reported ? fmtTime(f.last_reported) : undefined], ["Usage", f.usage || undefined],
      ["ISP", f.isp || undefined], ["Tor", f.tor ? "yes" : undefined]];
  } else if (kind === "domain") {
    rows = [["Labels", (f.labels || []).length ? tags(f.labels) : undefined], ["Software", (f.software || []).join(", ") || undefined],
      ["Certificate", (f.cert_names || []).join(", ") || undefined], ["Issuer", f.cert_issuer || undefined],
      ["Threats", (f.threats || []).length ? tags(f.threats) : undefined]];
  } else {
    rows = [["Services", (f.services || []).map((s) => `${s.port}/${s.protocol}${(s.software || []).length ? " " + s.software.join(", ") : ""}`).join("; ") || "none"],
      ["Names", (f.dns_names || []).join(", ") || undefined], ["AS", f.asn ? `AS${f.asn} ${f.as_name || ""}` : undefined],
      ["Location", [f.city, f.country].filter(Boolean).join(", ") || undefined],
      ["Labels", (f.labels || []).length ? tags(f.labels) : undefined], ["Threats", (f.threats || []).length ? tags(f.threats) : undefined],
      ["CVEs", (f.vulns || []).length ? tags(f.vulns) : undefined], ["Reputation", f.reputation || undefined], ["GreyNoise", f.greynoise || undefined]];
  }
  card.append(kv(rows), el("p", { class: "muted", style: "margin:6px 0 0;font-size:12px", text: asOf }));
  return card;
}

function lookupCards(intel, ind, kind) {
  return Object.keys(PROVIDERS).filter((n) => PROVIDERS[n].kinds.includes(kind)).map((n) => lookupCard(n, intel, ind, kind));
}

function intelCard(intel) {
  const card = el("div", { class: "card intel" });
  if (!intel || (!intel.asn && !intel.special && !(intel.matches || []).length)) {
    card.append(el("p", { class: "muted", style: "margin:0", text: "Not on any list, and no AS known." }));
    return card;
  }
  const sp = intel.special;
  card.append(kv([
    ["Verdict", intel.verdict ? badge(intel.verdict) : "none"],
    ["Special-purpose", sp ? `${sp.name} (${sp.rfc})${sp.note ? ": " + sp.note : ""}` : undefined],
    ["", sp && sp.reserved && (intel.feeds || []).length ? "Not a real host, so lists that include it (FireHOL lists every reserved range) don't count." : undefined],
    ["On lists", tags(intel.feeds)],
    ["AS", intel.asn ? `AS${intel.asn} ${intel.as_owner || ""}` : "unknown"],
    ["Country", intel.country || ""],
    ["Banned (30 days)", intel.bans_30d ? `${intel.bans_30d} time${intel.bans_30d === 1 ? "" : "s"}` : undefined],
  ]));
  return card;
}

function matchesTable(main, matches) {
  table(main, matches || [], [
    col("List", "provider", "text", { formatter: (c) => document.createTextNode(String(c.getValue()).replace(/^feed:/, "")) }),
    col("Verdict", "verdict", "verdict"),
    col("Now", "listed", "bool", { formatter: (c) => document.createTextNode(c.getValue() ? "listed" : "removed") }),
    col("Matched", "matched_via"), col("Detail", "detail"),
    col("First listed", "first_listed", "time"), col("Last listed", "last_listed", "time"), col("Removed", "removed_at", "time"),
  ]);
}

// On an IP's own page its intel is in the card at the top, not on every row.
const perIP = (c) => !["verdict", "feeds", "country", "bans_30d"].includes(c.field);

async function renderIP(ip) {
  const main = $main();
  main.replaceChildren(el("h1", { text: ip }), el("p", { class: "muted", text: "Loading…" }));
  const p = await api(`/api/ip/${encodeURIComponent(ip)}`, { since: state.since });
  const h = p.history || {};
  const devName = p.device && p.device.name;
  main.replaceChildren(
    el("h1", { text: devName ? `${devName} (${ip})` : ip }),
    el("p", { class: "lede" }, p.lan ? "A LAN address. " : "", "Counts below are all-time; the tables cover the selected window."),
    el("div", { class: "grid" }, p.lan ? deviceCard(p.device) : null, intelCard(p.intel), el("div", { class: "card" }, kv([
      ["Hits", h.hits?.count ? `${fmtNum(h.hits.count)} (${fmtTime(h.hits.first)} – ${fmtTime(h.hits.last)})` : "0"],
      ["DNS lookups", fmtNum(h.dns_queries?.count)],
      ["Connections", fmtNum(h.connections?.count)],
      ["Breaker trips", fmtNum(h.previous_trips)],
    ])), p.lan ? [] : lookupCards(p.intel, ip, "ip")),
  );
  if (p.intel && (p.intel.matches || []).length) { main.append(el("h2", { text: "Lists" })); matchesTable(main, p.intel.matches); }
  if (p.lan) {
    const rows = p.lookups || [];
    main.append(el("h2", { text: `What it looked up (${fmtNum(rows.length)}, ${rows.filter((r) => r.flagged).length} flagged)` }));
    table(main, rows, [col("Flagged", "flagged", "bool", { sorter: "boolean" }), col("Domain", "domain", "domain"), col("Lookups", "count", "num"),
      col("First", "first", "time"), col("Last", "last", "time")]);
  }
  main.append(el("h2", { text: "Names that resolved to it (outgoing)" }));
  table(main, p.resolved_from, [col("Domain", "domain", "domain"), col("Answers", "count", "num"), col("Last", "last", "time"),
    col("LAN clients", "clients", "list", { formatter: (c) => el("span", { class: "tags" }, (c.getValue() || []).map(clientLink)) })]);
  main.append(el("h2", { text: "Requests to our sites (incoming)" }));
  table(main, p.hits, LIST_VIEWS.hits.columns().filter(perIP));
  main.append(el("h2", { text: "Bans" }));
  table(main, p.bans, LIST_VIEWS.bans.columns().filter(perIP));
  main.append(el("h2", { text: "IDS alerts" }));
  table(main, p.alerts, LIST_VIEWS.alerts.columns().filter(perIP));
  main.append(el("h2", { text: "Breaker trips" }));
  table(main, p.trips, LIST_VIEWS.trips.columns().filter(perIP));
  main.append(el("h2", { text: "Refused logins" }));
  table(main, p.auth_failures, [col("When", "ts", "time"), col("App", "source"), col("Name tried", "user")]);
  main.append(el("h2", { text: "Logged connections (router firewall)" }));
  table(main, p.connections, [col("From", "client_ip", "ip"), col("To", "dst_ip", "ip"), col("Port", "dst_port", "num"), col("Proto", "proto"),
    col("Rule", "rule"), col("Action", "action"), col("Count", "count", "num"), col("First", "first", "time"), col("Last", "last", "time")]);
  if ((p.sightings || []).length) sightingsTable(main, p.sightings);
  if ((p.asn_changes || []).length) {
    main.append(el("h2", { text: "AS changes" }));
    table(main, p.asn_changes, [col("When", "ts", "time"), col("Old AS", "old_asn", "num"), col("Old owner", "old_owner"),
      col("New AS", "new_asn", "num"), col("New owner", "new_owner")]);
  }
}

async function renderDomain(d) {
  const main = $main();
  main.replaceChildren(el("h1", { text: d }), el("p", { class: "muted", text: "Loading…" }));
  const p = await api(`/api/domain/${encodeURIComponent(d)}`, { since: state.since });
  main.replaceChildren(el("h1", { text: d }),
    el("p", { class: "lede", text: "Lookups include subdomains. Answers are the addresses this exact name resolved to." }),
    el("div", { class: "grid" }, intelCard(p.intel), lookupCards(p.intel, d, "domain")));
  if (p.intel && (p.intel.matches || []).length) { main.append(el("h2", { text: "Lists" })); matchesTable(main, p.intel.matches); }
  main.append(el("h2", { text: "Who looked it up" }));
  table(main, p.lookups, [col("Client", "client_ip", "client"), col("Name", "client_name"), col("Lookups", "count", "num"),
    col("First", "first", "time"), col("Last", "last", "time")]);
  main.append(el("h2", { text: "What it resolved to" }));
  table(main, p.answers, [col("Answer", "answer", "text", { formatter: (c) => /^[0-9a-f.:]+$/i.test(c.getValue()) ? ipLink(c.getValue()) : document.createTextNode(c.getValue()) }),
    col("Status", "status"), col("Verdict", "verdict", "verdict"), col("Feeds", "feeds", "tags"),
    col("Special-purpose", "special", "text", { formatter: (c) => document.createTextNode(c.getValue() ? c.getValue().name : "") }),
    col("AS", "asn", "text", { formatter: (c) => document.createTextNode(asnText(c.getRow().getData())) }), col("Owner", "as_owner"), col("CC", "country"),
    bans30(), col("Count", "count", "num"), col("Last", "last", "time")]);
  main.append(el("h2", { text: "Logged connections to those addresses" }));
  table(main, p.connections, connColumns());
}

function connColumns() {
  return [col("Client", "client_ip", "client"), col("To", "dst_ip", "ip"), col("Port", "dst_port", "num"), col("Proto", "proto"),
    col("Action", "action"), col("Count", "count", "num"), col("First", "first", "time"), col("Last", "last", "time")];
}

// What's known about the LAN device at an address, and how it was seen.
function deviceCard(d) {
  const card = el("div", { class: "card intel" });
  if (!d) {
    card.append(el("p", { class: "muted", style: "margin:0", text: "No DHCP lease, UniFi client event or neighbour-table entry for this address yet." }));
    return card;
  }
  card.append(kv([
    ["Name", d.name || "unknown"],
    ["Hostname", d.hostname || undefined],
    ["UniFi alias", d.alias && d.alias !== d.name ? d.alias : undefined],
    ["MAC", d.mac],
    ["Network", d.network || undefined],
    ["Address tied to MAC", `${fmtTime(d.seen)} (${d.source})`],
  ]));
  return card;
}

function sightingsTable(main, rows) {
  main.append(el("h2", { text: "Sightings (this address and every address its MAC used)" }));
  table(main, rows, [col("Time", "ts", "time"), col("Address", "ip", "ip"), col("MAC", "mac"), col("Hostname", "hostname"),
    col("Alias", "alias"), col("Network", "network"), col("Interface", "iface"), col("Event", "event"), col("Source", "source")]);
}

async function renderOverview() {
  const main = $main();
  main.replaceChildren(el("h1", { text: "Overview" }), el("p", { class: "muted", text: "Loading…" }));
  const [o, h] = await Promise.all([api("/api/overview"), api("/api/health").catch((e) => ({ error: e.message }))]);
  main.replaceChildren(el("h1", { text: "Overview" }),
    el("p", { class: "lede", text: "A read-only view of dnscount's live database, joined with free threat feeds matched on this box." }));
  if (!h.error) {
    main.append(el("div", { class: "grid" }, healthTiles(h)), el("p", {}, el("a", { href: href("health"), text: "Health details →" })));
  }
  main.append(el("h2", { text: "Data" }),
    el("div", { class: "grid" },
      el("div", { class: "card tile" }, el("div", { class: "label", text: "Indicators indexed" }), el("div", { class: "value", text: fmtNum(o.indicators) })),
      el("div", { class: "card tile" }, el("div", { class: "label", text: "Flagged (malicious or suspicious)" }),
        el("div", { class: "value" }, el("a", { href: href("flagged"), text: fmtNum(o.flagged) }))),
      el("div", { class: "card tile" }, el("div", { class: "label", text: "Last index / match" }),
        el("div", { class: "state", text: `${fmtTime(o.loops?.last_index)} · ${fmtNum(o.loops?.last_index_rows)} rows · ${fmtNum(o.loops?.last_matched)} matched` }),
        o.loops?.last_error ? el("div", { class: "error", text: o.loops.last_error }) : null),
    ));
}

// One breaker trip: what was recorded about the client when it tripped.
async function renderTrip(id) {
  const main = $main();
  main.replaceChildren(el("h1", { text: `Trip #${id}` }), el("p", { class: "muted", text: "Loading…" }));
  const t = await api(`/api/trips/${encodeURIComponent(id)}`);
  main.replaceChildren(el("h1", { text: `Trip #${t.id}: ${t.breaker}` }),
    el("p", { class: "lede", text: "Everything recorded about the client when it tripped: headers (secrets hashed), body samples, recent events, the rate curve and reverse DNS." }),
    el("div", { class: "grid" }, el("div", { class: "card" }, kv([
      ["Who", ipLink(t.key)], ["Reason", t.reason], ["Tripped", fmtTime(t.tripped_at)], ["Cooldown until", fmtTime(t.cooldown_until)],
      ["Ended", fmtTime(t.ended_at) || "still cooling down"], ["Events in window", fmtNum(t.window_events)], ["Bad in window", fmtNum(t.window_bad)],
      ["Suppressed during cooldown", fmtNum(t.suppressed_during_cooldown)], ["First seen in window", fmtTime(t.first_seen_in_window)],
    ]))));
  main.append(el("h2", { text: "Detail" }), el("pre", { class: "detail", text: JSON.stringify(t.detail ?? null, null, 2) }));
}

// ---------- health ----------
function statusOf(value, warn, crit) {
  if (value == null || Number.isNaN(value)) return "unknown";
  if (value >= crit) return "critical";
  if (value >= warn) return "warning";
  return "good";
}
const STATE_WORD = { good: "OK", warning: "Watch", critical: "Problem", unknown: "No data" };
function tile(label, value, st, note) {
  return el("div", { class: `card tile s-${st}` }, el("div", { class: "label", text: label }), el("div", { class: "value", text: value }),
    el("div", { class: "state" }, el("span", { class: "dot", "aria-hidden": "true" }), `${STATE_WORD[st]}${note ? " · " + note : ""}`));
}

function healthTiles(h) {
  const t = h.thresholds || {};
  const n = h.now || {};
  const psi = n.psi || {};
  const psiMax = Math.max(psi.cpu ?? -1, psi.memory ?? -1, psi.io ?? -1);
  const stale = (h.feeds || []).filter((f) => f.stale);
  const problems = h.data_problems || [];
  return [
    tile("Live DB write-ahead log", n.wal_bytes != null ? fmtBytes(n.wal_bytes) : "?", statusOf(n.wal_bytes, t.wal_bytes, t.wal_bytes * 4), `limit ${fmtBytes(t.wal_bytes)}`),
    tile("Pressure (worst of cpu/mem/io)", psiMax >= 0 ? `${psiMax.toFixed(1)}%` : "?", psiMax >= 0 ? statusOf(psiMax, t.psi_pct, t.psi_pct * 3) : "unknown", "time stalled, last 10s"),
    tile("Newest DNS lookup", fmtAge(n.dns_age_s), n.dns_age_s >= 0 ? statusOf(n.dns_age_s, t.dns_age_s, t.dns_age_s * 3) : "unknown", "ago"),
    tile("Data problems", String(problems.length), problems.length ? "critical" : "good", h.checked_at ? `checked ${fmtTime(h.checked_at)}` : ""),
    tile("Stale feeds", String(stale.length), stale.length ? "warning" : "good", stale.map((f) => f.name).join(", ")),
  ];
}

// A small line chart: one y axis, crosshair + tooltip, legend, table view.
const tip = (() => { let t; return () => (t ||= document.body.appendChild(el("div", { class: "tip", role: "status" }))); })();

function lineChart({ title, sub, series, fmt, threshold, yMin = 0 }) {
  const card = el("div", { class: "card chart" });
  const toggle = el("button", { class: "toggle", text: "Table" });
  card.append(el("h3", {}, toggle, title, sub ? el("span", { class: "sub", text: " · " + sub }) : null));
  const body = el("div");
  card.append(body);
  let showTable = false;
  toggle.addEventListener("click", () => { showTable = !showTable; toggle.textContent = showTable ? "Chart" : "Table"; draw(); });
  const live = series.filter((s) => s.points.length);
  const legend = el("div", { class: "legend" }, live.length > 1 ? live.map((s) => el("span", {}, el("i", { class: "swatch", style: `background:var(${s.color})` }), s.name)) : []);
  function draw() {
    body.replaceChildren();
    if (!live.length) { body.append(el("p", { class: "muted", text: "No samples yet." })); return; }
    if (showTable) { body.append(chartTable()); return; }
    const W = Math.max(280, body.clientWidth || card.clientWidth - 28), H = 170, L = 52, R = 8, T = 8, B = 22;
    const xs = live.flatMap((s) => s.points.map((p) => p[0]));
    const x0 = Math.min(...xs), x1 = Math.max(...xs);
    let yMax = Math.max(...live.flatMap((s) => s.points.map((p) => p[1])), threshold ?? 0);
    if (!(yMax > yMin)) yMax = yMin + 1;
    yMax = niceMax(yMax);
    const X = (v) => L + (x1 === x0 ? 0 : ((v - x0) / (x1 - x0)) * (W - L - R));
    const Y = (v) => T + (1 - (v - yMin) / (yMax - yMin)) * (H - T - B);
    const s = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": title });
    for (let i = 0; i <= 3; i++) {
      const v = yMin + ((yMax - yMin) * i) / 3, y = Y(v);
      s.append(svg("line", { class: i ? "gridline" : "baseline", x1: L, x2: W - R, y1: y, y2: y }));
      const tx = svg("text", { class: "tick", x: L - 6, y: y + 4, "text-anchor": "end" });
      tx.textContent = fmt(v);
      s.append(tx);
    }
    for (const [v, anchor] of (x1 === x0 ? [[x0, "start"]] : [[x0, "start"], [x1, "end"]])) {
      const tx = svg("text", { class: "tick", x: X(v), y: H - 6, "text-anchor": anchor });
      tx.textContent = new Date(v).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      s.append(tx);
    }
    if (threshold != null && threshold <= yMax) s.append(svg("line", { class: "threshold", x1: L, x2: W - R, y1: Y(threshold), y2: Y(threshold) }));
    for (const se of live) {
      const d = se.points.map((p, i) => `${i ? "L" : "M"}${X(p[0]).toFixed(1)},${Y(p[1]).toFixed(1)}`).join("");
      s.append(svg("path", { class: "line", d, stroke: `var(${se.color})` }));
      const lp = se.points[se.points.length - 1];
      s.append(svg("circle", { class: "marker", cx: X(lp[0]), cy: Y(lp[1]), r: 4, fill: `var(${se.color})` }));
    }
    const cross = svg("line", { class: "cross", y1: T, y2: H - B, x1: -10, x2: -10 });
    const hit = svg("rect", { x: L, y: 0, width: W - L - R, height: H, fill: "transparent" });
    s.append(cross, hit);
    const times = [...new Set(xs)].sort((a, b) => a - b);
    const move = (ev) => {
      const r = s.getBoundingClientRect();
      const px = ((ev.clientX - r.left) / r.width) * W;
      let best = times[0];
      for (const t of times) if (Math.abs(X(t) - px) < Math.abs(X(best) - px)) best = t;
      cross.setAttribute("x1", X(best)); cross.setAttribute("x2", X(best));
      const box = tip();
      box.replaceChildren(el("div", { class: "t", text: fmtTime(new Date(best).toISOString()) }),
        ...live.map((se) => { const p = se.points.find((q) => q[0] === best); return el("div", { class: "r" }, el("span", {}, live.length > 1 ? el("i", { class: "swatch", style: `background:var(${se.color});display:inline-block;width:10px;height:3px;margin-right:4px` }) : null, se.name), el("b", { text: p ? fmt(p[1]) : "–" })); }));
      box.style.display = "block";
      const bx = Math.min(ev.clientX + 14, window.innerWidth - box.offsetWidth - 8);
      box.style.left = bx + "px"; box.style.top = (ev.clientY + 14) + "px";
    };
    hit.addEventListener("pointermove", move);
    hit.addEventListener("pointerleave", () => { tip().style.display = "none"; cross.setAttribute("x1", -10); cross.setAttribute("x2", -10); });
    body.append(s, legend);
  }
  function chartTable() {
    const times = [...new Set(live.flatMap((s) => s.points.map((p) => p[0])))].sort((a, b) => b - a);
    return el("div", { class: "scroll" }, el("table", {},
      el("thead", {}, el("tr", {}, el("th", { text: "Time" }), live.map((s) => el("th", { text: s.name })))),
      el("tbody", {}, times.map((t) => el("tr", {}, el("td", { text: fmtTime(new Date(t).toISOString()) }),
        live.map((s) => { const p = s.points.find((q) => q[0] === t); return el("td", { text: p ? fmt(p[1]) : "" }); }))))));
  }
  card._draw = draw;
  return card;
}
function niceMax(v) {
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}

let healthTimer = null;
async function renderHealth() {
  const main = $main();
  const range = state.healthRange || "6h";
  const head = [el("h1", { text: "Health" }),
    el("p", { class: "lede", text: "Whether reads here ever get in the way of ingest. The explorer opens the live database read-only; these show if that stays true. Refreshes every 15s." })];
  const pick = el("select", { onchange: (e) => { state.healthRange = e.target.value; route(); } },
    [["1h", "last hour"], ["6h", "last 6 hours"], ["24h", "last 24 hours"]].map(([v, t]) => el("option", { value: v, text: t })));
  pick.value = range;
  const [h, series, o] = await Promise.all([api("/api/health"), api("/api/health/series", { since: range, points: 240 }),
    api("/api/overview").catch(() => ({}))]);
  const t = h.thresholds || {};
  const pts = (f) => (series || []).map((s) => [Date.parse(s.ts), f(s)]).filter((p) => p[1] != null && !Number.isNaN(p[1]));
  const units = Object.keys((h.now || {}).units || {});
  const short = (u) => u.replace(/^dnscount-/, "");
  const colors = ["--series-1", "--series-2", "--series-3", "--series-4", "--series-5"];
  const charts = [
    lineChart({ title: "Write-ahead log", sub: "live DB", fmt: fmtBytes, threshold: t.wal_bytes,
      series: [{ name: "WAL", color: "--series-1", points: pts((s) => s.wal_bytes) }] }),
    lineChart({ title: "System pressure", sub: "% of time stalled", fmt: (v) => `${v.toFixed(1)}%`, threshold: t.psi_pct,
      series: [["cpu", "--series-1"], ["memory", "--series-2"], ["io", "--series-3"]].map(([k, c]) => ({ name: k, color: c, points: pts((s) => s.psi?.[k]) })) }),
    lineChart({ title: "CPU by unit", sub: "% of one core", fmt: (v) => `${v.toFixed(0)}%`,
      series: units.map((u, i) => ({ name: short(u), color: colors[i % colors.length], points: pts((s) => s.units?.[u]?.present ? s.units[u].cpu_pct : null) })) }),
    lineChart({ title: "Memory by unit", fmt: fmtBytes,
      series: units.map((u, i) => ({ name: short(u), color: colors[i % colors.length], points: pts((s) => s.units?.[u]?.present ? s.units[u].mem_bytes : null) })) }),
    lineChart({ title: "Explorer query time", sub: "p95 per sample", fmt: (v) => `${v.toFixed(0)} ms`, threshold: t.query_p95_ms,
      series: [{ name: "p95", color: "--series-1", points: pts((s) => (s.requests ? s.query_p95_ms : null)) }] }),
    lineChart({ title: "Newest DNS lookup age", fmt: fmtAge, threshold: t.dns_age_s,
      series: [{ name: "age", color: "--series-1", points: pts((s) => (s.dns_age_s >= 0 ? s.dns_age_s : null)) }] }),
  ];
  main.replaceChildren(...head, el("div", { class: "grid" }, healthTiles(h)), el("div", { class: "controls", style: "margin-top:12px" }, el("label", {}, "charts ", pick)),
    el("div", { class: "charts" }, charts));
  charts.forEach((c) => c._draw());
  main.append(el("h2", { text: "Units now" }));
  table(main, units.map((u) => ({ unit: u, ...h.now.units[u] })), [col("Unit", "unit"),
    col("Running", "present", "bool"), col("CPU %", "cpu_pct", "num", { formatter: (c) => document.createTextNode((c.getValue() || 0).toFixed(1)) }),
    col("Memory", "mem_bytes", "bytes"), col("CPU pressure", "cpu_pressure", "num"), col("Memory pressure", "mem_pressure", "num"),
    col("IO pressure", "io_pressure", "num")], { pagination: false });
  main.append(el("h2", { text: "Feeds" }));
  table(main, h.feeds, [col("Feed", "name"), col("Kind", "kind"), col("Verdict", "verdict", "verdict"), col("Every", "interval"),
    col("Entries", "entries", "num"), col("Fetched", "age_s", "num", { formatter: (c) => document.createTextNode(fmtAge(c.getValue()) + (c.getValue() >= 0 ? " ago" : "")) }),
    col("Stale", "stale", "bool"), col("Unchecked rows", "outdated_rows", "num"), col("Skipped", "skipped"), col("Error", "error"),
    col("About", "about")], { pagination: false });
  main.append(el("h2", { text: "Tables" }));
  const tables = Object.entries(o.tables || {}).map(([name, c]) => ({ name, rows: c.rows, last_24h: c.last_24h }));
  table(main, tables, [col("Table", "name"), col("Rows", "rows", "num"), col("Last 24h", "last_24h", "num")], { pagination: false });
  main.append(el("h2", { text: "Data problems" }));
  if ((h.data_problems || []).length) main.append(el("ul", {}, h.data_problems.map((p) => el("li", { text: p }))));
  else main.append(el("p", { class: "muted", text: `None (checked ${fmtTime(h.checked_at)}).` }));
  if (h.check_error) main.append(el("p", { class: "error", text: h.check_error }));
  main.append(el("h2", { text: "Outside services (queried providers)" }),
    el("p", { class: "muted", text: "Requests sent, against each provider's caps; answers are cached and re-asked after their TTL." }));
  if (h.lookups_error) main.append(el("p", { class: "error", text: h.lookups_error }));
  table(main, h.lookups || [], [col("Provider", "provider"), col("Units, last 24h", "units_24h", "num"),
    col("Units this month", "units_month", "num"), col("Cached answers", "cached", "num"),
    col("Last request", "last_request", "time"), col("Last error", "last_error"), col("Error at", "last_error_at", "time")], { pagination: false });
  main.append(el("h2", { text: "Breakers (live, from dnscount serve)" }));
  if (h.admin_error) main.append(el("p", { class: "error", text: h.admin_error }));
  table(main, h.breakers || [], [col("Name", "name"), col("Trips", "trips", "num"), col("Suppressed", "suppressed", "num"),
    col("Tripped now", "tripped_now", "num"), col("Keys", "keys", "num")], { pagination: false });
  main.append(el("h2", { text: "Slowest requests, last hour" }));
  table(main, h.slow_queries || [], [col("When", "ts", "time"), col("Path", "path"), col("ms", "took_ms", "num"), col("Error", "error")], { pagination: false });
  clearTimeout(healthTimer);
  healthTimer = setTimeout(() => { if (parseHash().view === "health" && !document.hidden) route({ quiet: true }); }, 15000);
}

// ---------- router ----------
let routeSeq = 0;
async function route(opts) {
  const { view, arg, q } = parseHash();
  const seq = ++routeSeq;
  renderNav(view);
  document.title = `dnscount · ${arg || (LIST_VIEWS[view]?.title) || view}`;
  const y = window.scrollY;
  const main = $main();
  if (opts?.quiet) {
    // Hold the page at its height while it's rebuilt, so the browser doesn't
    // clamp the scroll position to a briefly shorter page.
    main.style.minHeight = `${main.offsetHeight}px`;
  }
  tablesBuilding = [];
  try {
    if (LIST_VIEWS[view]) await renderList(view, q);
    else if (view === "ip" && arg) await renderIP(arg);
    else if (view === "domain" && arg) await renderDomain(arg);
    else if (view === "trip" && arg) await renderTrip(arg);
    else if (view === "client" && arg) location.replace(href("ip", arg)); // old links
    else if (view === "health") await renderHealth();
    else await renderOverview();
    if (opts?.quiet) {
      const settle = new Promise((done) => setTimeout(done, 2000)); // never wait forever
      await Promise.race([Promise.all(tablesBuilding), settle]);
      if (seq === routeSeq) window.scrollTo(0, y);
    }
  } catch (e) {
    if (seq !== routeSeq) return;
    $main().replaceChildren(el("h1", { text: "Couldn't load this" }), el("p", { class: "error", text: e.message }));
  } finally {
    if (seq === routeSeq) main.style.minHeight = "";
  }
}

// The find box: an IP goes to its page, anything else is taken as a domain.
// A pasted URL counts as its host.
function findTarget(raw) {
  let s = String(raw || "").trim();
  if (!s) return null;
  if (s.includes("://")) { try { s = new URL(s).hostname; } catch { return null; } }
  s = s.replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (/^[0-9.]+$/.test(s) || (s.includes(":") && /^[0-9a-f:.]+$/i.test(s))) return href("ip", s);
  s = s.toLowerCase();
  if (!/^[a-z0-9_.-]+$/.test(s) || !s.includes(".")) return null;
  return href("domain", s);
}

function init() {
  const find = document.getElementById("find");
  const findQ = document.getElementById("find-q");
  find.addEventListener("submit", (e) => {
    e.preventDefault();
    const to = findTarget(findQ.value);
    find.querySelector(".error")?.remove();
    if (!to) { find.append(el("span", { class: "error", text: "not an IP or domain" })); return; }
    findQ.value = "";
    location.hash = to;
  });
  const sel = document.getElementById("since");
  sel.value = state.since;
  sel.addEventListener("change", () => { state.since = sel.value; state.limits = {}; localStorageSet("since", sel.value); route(); });
  document.getElementById("foot").textContent = "Read-only. Data from dnscount.db; feed matches from explore.db.";
  window.addEventListener("hashchange", () => route());
  document.addEventListener("visibilitychange", () => { if (!document.hidden && parseHash().view === "health") route({ quiet: true }); });
  let rt;
  window.addEventListener("resize", () => { clearTimeout(rt); rt = setTimeout(() => document.querySelectorAll(".chart").forEach((c) => c._draw && c._draw()), 150); });
  route();
}
document.addEventListener("DOMContentLoaded", init);
