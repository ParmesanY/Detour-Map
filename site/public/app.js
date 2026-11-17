// Detour Map front end: no dependencies. On the main site everything comes from the same origin (/v1 API,
// regions.json); the GitHub Pages mirror asks the collector for /v1 and carries the rest itself.

const COLLECTOR = "https://detour-map-collector.detour-map-collector.workers.dev";
const PAGES = "https://parmesany.github.io/Detour-Map/";
const ON_PAGES = location.hostname.endsWith("github.io");
const API_BASE = ON_PAGES ? COLLECTOR : "";

const METHODS = {
  dns: "DNS-подмена",
  ip: "Блок по IP",
  sni: "DPI по имени (SNI)",
  freeze: "Заморозка 16 КБ",
  stall: "Тишина после TLS",
  throttle: "Замедление",
};
const GROUPS = { site: "Сервисы", hosting: "Хостинги (VPN-серверы)", ip: "Адреса", special: "Режим сети" };
const WHITELIST = "_whitelist";
/** Upper bounds of the blocked-share classes c0..c3; c4 is the rest. */
const BINS = [0.1, 0.3, 0.6, 0.9];
const BIN_LABELS = ["<10%", "10–30", "30–60", "60–90", "90%+"];

const $ = (id) => document.getElementById(id);
const pct = (x) => `${Math.round(x * 100)}%`;
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const binOf = (share) => {
  const i = BINS.findIndex((b) => share < b);
  return i === -1 ? 4 : i;
};
const methodName = (m) => (m ? METHODS[m] ?? m : "—");

/** Outage layer (IODA): hours with an outage per region over 7 days. */
const HOUR_BINS = [1, 6, 24, 72];
const HOUR_LABELS = ["<1 ч", "1–6", "6–24", "24–72", "72 ч+"];
const SOURCE_NAMES = { bgp: "BGP", "ping-slash24": "активный пинг", "merit-nt": "телескоп", gtr: "Google" };

const state = { target: "youtube", days: "1", net: "", region: null, layer: "auto" };
/** What the map shows right now: the chosen layer, or outages when ours has nothing for this target. */
let mapMode = "blocks";
let targets = [];
let regionShapes = new Map();
let regionData = new Map();

// ---- URL state ------------------------------------------------------------------------------------

function readUrl() {
  const p = new URLSearchParams(location.search);
  state.target = p.get("t") ?? state.target;
  state.days = ["1", "7", "30"].includes(p.get("days")) ? p.get("days") : "1";
  state.net = ["home", "mobile"].includes(p.get("net")) ? p.get("net") : "";
  state.region = /^[A-Z0-9]{1,3}$/.test(p.get("region") ?? "") ? p.get("region") : null;
  state.layer = ["blocks", "outages"].includes(p.get("layer")) ? p.get("layer") : "auto";
}

function writeUrl() {
  const p = new URLSearchParams();
  p.set("t", state.target);
  if (state.days !== "1") p.set("days", state.days);
  if (state.net) p.set("net", state.net);
  if (state.region) p.set("region", state.region);
  if (state.layer !== "auto") p.set("layer", state.layer);
  history.replaceState(null, "", `?${p}`);
}

// ---- API ------------------------------------------------------------------------------------------

async function api(path, params = {}) {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v !== null && v !== ""));
  const res = await fetch(`${API_BASE}/v1/${path}?${q}`);
  if (!res.ok) throw new Error(`${path}: HTTP ${res.status}`);
  return res.json();
}

const common = () => ({ days: state.days, net: state.net });

// ---- Tooltip --------------------------------------------------------------------------------------

const tip = $("tip");

function showTip(html, event) {
  tip.innerHTML = html;
  tip.hidden = false;
  const pad = 14;
  const { innerWidth: w, innerHeight: h } = window;
  const r = tip.getBoundingClientRect();
  let x = event.clientX + pad;
  let y = event.clientY + pad;
  if (x + r.width > w - 8) x = event.clientX - r.width - pad;
  if (y + r.height > h - 8) y = event.clientY - r.height - pad;
  tip.style.left = `${Math.max(8, x)}px`;
  tip.style.top = `${Math.max(8, y)}px`;
}

const hideTip = () => (tip.hidden = true);

function statRows(s) {
  const rows = [
    ["Блокировка", pct(s.blocked)],
    ["Основной способ", methodName(s.main)],
    ["Участники", s.reporters],
    ["Замеры", s.probes],
  ];
  for (const [k, name] of Object.entries(METHODS)) {
    if (s.methods?.[k] > 0 && k !== s.main) rows.push([name, pct(s.methods[k])]);
  }
  return rows.map(([a, b]) => `<div class="row"><span>${esc(a)}</span><span>${esc(b)}</span></div>`).join("");
}

// ---- Controls -------------------------------------------------------------------------------------

function initControls() {
  for (const seg of document.querySelectorAll(".seg")) {
    const name = seg.dataset.name;
    for (const b of seg.querySelectorAll("button")) {
      b.addEventListener("click", () => {
        state[name] = b.dataset.value;
        syncControls();
        writeUrl();
        refresh();
      });
    }
  }
  $("region-clear").addEventListener("click", () => selectRegion(null));
}

function syncControls() {
  for (const seg of document.querySelectorAll(".seg")) {
    for (const b of seg.querySelectorAll("button")) {
      // The layer switch shows what the map shows (in "auto" that may be outages), not the stored choice.
      const current = seg.dataset.name === "layer" ? mapMode : state[seg.dataset.name];
      b.setAttribute("aria-checked", String(b.dataset.value === current));
    }
  }
}

// ---- Target list ----------------------------------------------------------------------------------

function renderTargets(summary) {
  const byId = new Map(summary.targets.map((t) => [t.target, t]));
  const rank = (t) => {
    const s = byId.get(t.id);
    if (s) return 2 + s.blocked;
    const o = ooniOf(t.id);
    return o ? 1 + o.share : 0;
  };
  const list = $("target-list");
  list.innerHTML = "";
  const items = [
    ...targets.filter((t) => t.kind !== "control"),
    { id: WHITELIST, name: "Белые списки", kind: "special" },
  ];
  for (const kind of Object.keys(GROUPS)) {
    const group = items
      .filter((t) => t.kind === kind)
      // Ours first (by share), then OONI-only (by share), then nothing; OONI never outranks our own data.
      .sort((a, b) => rank(b) - rank(a) || a.name.localeCompare(b.name));
    if (group.length === 0) continue;
    const h = document.createElement("li");
    h.className = "group";
    h.setAttribute("role", "presentation");
    h.textContent = GROUPS[kind];
    list.append(h);
    for (const t of group) {
      const s = byId.get(t.id);
      const li = document.createElement("li");
      li.setAttribute("role", "option");
      li.tabIndex = 0;
      li.dataset.id = t.id;
      li.setAttribute("aria-selected", String(t.id === state.target));
      const o = s ? null : ooniOf(t.id);
      li.innerHTML = s
        ? `<span class="name">${esc(t.name)}</span><span class="meter"><i data-w="${Math.round(s.blocked * 100)}"></i></span><span class="val">${pct(s.blocked)}</span>`
        : o
          ? `<span class="name">${esc(t.name)}</span><span class="meter ooni"><i data-w="${Math.round(o.share * 100)}"></i></span><span class="val ooni">≈${pct(o.share)}</span>`
          : `<span class="name">${esc(t.name)}</span><span></span><span class="val nodata-dash">—</span>`;
      li.title = s
        ? `${t.name}: блокировка в ${pct(s.blocked)} замеров, ${s.reporters} участн.`
        : o
          ? `${t.name}: наших данных мало; по OONI за 7 дней аномалии в ${pct(o.share)} из ${num(o.measurements)} замеров`
          : `${t.name}: мало данных`;
      const pick = () => {
        state.target = t.id;
        writeUrl();
        for (const x of list.querySelectorAll("[role=option]")) x.setAttribute("aria-selected", String(x.dataset.id === t.id));
        refreshTarget();
      };
      li.addEventListener("click", pick);
      li.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          pick();
        }
      });
      list.append(li);
    }
  }
}

// Meter widths go through data-w: the CSP blocks style="" in markup, but not styles set from script.
function applyMeters() {
  for (const i of document.querySelectorAll(".meter > i[data-w]")) {
    i.style.width = `${i.dataset.w}%`;
    delete i.dataset.w;
  }
}

// ---- Map ------------------------------------------------------------------------------------------

async function initMap() {
  const geo = await (await fetch("regions.json")).json();
  const svg = $("map");
  svg.setAttribute("viewBox", `0 0 ${geo.width} ${geo.height}`);
  const ns = "http://www.w3.org/2000/svg";
  for (const r of geo.regions) {
    const p = document.createElementNS(ns, "path");
    p.setAttribute("d", r.d);
    p.dataset.code = r.code;
    p.classList.add("nodata");
    svg.append(p);
    regionShapes.set(r.code, { ...r, el: p });
  }
  svg.addEventListener("pointermove", (e) => {
    const code = e.target.dataset?.code;
    if (!code) return hideTip();
    const shape = regionShapes.get(code);
    if (mapMode === "outages") {
      const o = external?.ioda?.regions?.[code];
      const rows = o
        ? `<div class="row"><span>Сбои связи</span><span>${hours(o.hours)}</span></div>
           <div class="row"><span>События</span><span>${o.events}</span></div>
           <div class="row"><span>Заметили</span><span>${esc(o.sources.map((s) => SOURCE_NAMES[s] ?? s).join(", "))}</span></div>`
        : '<div class="row"><span>Сбоев не замечено</span><span></span></div>';
      return showTip(`<b>${esc(shape.name)}</b>${rows}`, e);
    }
    const s = regionData.get(code);
    showTip(`<b>${esc(shape.name)}</b>${s ? statRows(s) : '<div class="row"><span>Мало данных</span><span></span></div>'}`, e);
  });
  svg.addEventListener("pointerleave", hideTip);
  svg.addEventListener("click", (e) => {
    const code = e.target.dataset?.code;
    if (mapMode === "blocks" && code && regionData.has(code)) selectRegion(state.region === code ? null : code);
  });
}

const hours = (h) => (h < 1 ? `${Math.max(1, Math.round(h * 60))} мин` : `${h.toLocaleString("ru-RU")} ч`) + " за 7 дней";

function renderLegend(mode) {
  const labels = mode === "outages" ? HOUR_LABELS : BIN_LABELS;
  const legend = $("legend");
  legend.innerHTML =
    labels.map((l, i) => `<span class="sw${i === 4 ? " last" : ""}"><i class="lg c${i}"></i>${l}</span>`).join("") +
    (mode === "outages" ? `<span class="sw nd zero"><i></i>нет сбоев</span>` : `<span class="sw nd"><i></i>нет данных</span>`);
  // Legend swatches take the map's class colours.
  legend.querySelectorAll("i.lg").forEach((i, n) => (i.style.background = `var(--c${n})`));
}

function hourBin(h) {
  const i = HOUR_BINS.findIndex((b) => h < b);
  return i === -1 ? 4 : i;
}

/** The IODA layer: every region has a value (no outage is a value too). */
function renderOutages(auto) {
  const regions = external.ioda.regions;
  regionData = new Map();
  for (const [code, shape] of regionShapes) {
    const o = regions[code];
    shape.el.setAttribute("class", o ? `c${hourBin(o.hours)}` : "zero");
  }
  $("map").classList.remove("dim");
  $("map-empty").hidden = true;
  renderLegend("outages");
  const name = targetName(state.target);
  const why = auto
    ? `Наших замеров по ${esc(name)} пока мало, поэтому карта показывает сбои связи по регионам. `
    : "";
  $("map-note").innerHTML =
    `${why}Сбои связи — когда регион заметно пропадает из интернета (BGP, активный пинг, телескоп) по данным ` +
    `<a href="${esc(external.ioda.url)}" rel="noopener" target="_blank">IODA</a>, ${esc(fmtDate(external.ioda.since))} — ${esc(fmtDate(external.ioda.until))}. ` +
    `Отключения мобильного интернета с «белыми списками» видны не всегда.` +
    radarNote();
  $("map-note").hidden = false;
  $("map-sub").textContent = "сбои связи по регионам за 7 дней · IODA";

  $("region-head").innerHTML = `<tr><th>Регион</th><th class="num">События</th><th class="num">Сбои</th><th>Кто заметил</th></tr>`;
  const rows = Object.entries(regions).sort((a, b) => b[1].hours - a[1].hours);
  $("region-rows").innerHTML = rows.length
    ? rows
        .map(([code, o]) => `<tr><td>${esc(regionName(code))}</td><td class="num">${o.events}</td><td class="num">${esc(hours(o.hours))}</td><td class="method">${esc(o.sources.map((s) => SOURCE_NAMES[s] ?? s).join(", "))}</td></tr>`)
        .join("")
    : `<tr class="empty"><td colspan="4">За неделю сбоев не замечено</td></tr>`;
}

function regionName(code) {
  return regionShapes.get(code)?.name ?? code;
}

function renderMap(map) {
  regionData = new Map(map.regions.map((r) => [r.region, r]));
  for (const [code, shape] of regionShapes) {
    const s = regionData.get(code);
    shape.el.setAttribute("class", s ? `has-data c${binOf(s.blocked)}` : "nodata");
    shape.el.classList.toggle("active", code === state.region);
  }
  $("map").classList.toggle("dim", Boolean(state.region));
  $("map-empty").hidden = map.regions.length > 0;
  $("map-note").hidden = true;
  renderLegend("blocks");
  if (map.regions.length === 0) {
    // Say what other sources know instead of just "no data".
    const o = ooniOf(state.target);
    $("map-empty").innerHTML =
      "Пока данных мало: регион появляется на карте, когда его подтвердили минимум три разных человека." +
      (o
        ? `<br><br>По данным OONI за неделю у ${esc(targetName(state.target))} аномалии в <b>${pct(o.share)}</b> из ${num(o.measurements)} замеров — по провайдерам ниже. Регионы OONI не различает.`
        : "");
  }

  $("region-head").innerHTML = `<tr><th>Регион</th><th class="num">Участники</th><th class="num">Блокировка</th><th>Основной способ</th></tr>`;
  const rows = [...map.regions].sort((a, b) => b.blocked - a.blocked || b.reporters - a.reporters);
  $("region-rows").innerHTML = rows.length
    ? rows
        .map((r) => `<tr><td>${esc(regionName(r.region || "—"))}</td><td class="num">${r.reporters}</td><td class="num">${pct(r.blocked)}</td><td class="method">${esc(methodName(r.main))}</td></tr>`)
        .join("")
    : `<tr class="empty"><td colspan="4">Нет регионов с тремя и более участниками</td></tr>`;
}

function selectRegion(code) {
  state.region = code;
  writeUrl();
  for (const [c, shape] of regionShapes) shape.el.classList.toggle("active", c === code);
  $("map").classList.toggle("dim", Boolean(code));
  $("region-bar").hidden = !code;
  if (code) $("region-name").textContent = regionName(code);
  refreshDetails();
}

// ---- ISPs -----------------------------------------------------------------------------------------

function renderIsps(data) {
  const where = state.region ? regionName(state.region) : "вся страна";
  $("isps-sub").textContent = where;
  $("isp-rows").innerHTML = data.isps.length
    ? data.isps
        .map(
          (i) => `<tr>
            <td>${esc(i.as_org || "—")}<span class="asn">AS${i.asn}</span></td>
            <td class="num">${i.reporters}</td>
            <td><span class="bar"><span class="meter"><i data-w="${Math.round(i.blocked * 100)}"></i></span>${pct(i.blocked)}</span></td>
            <td class="method">${esc(methodName(i.main))}</td>
          </tr>`,
        )
        .join("")
    : `<tr class="empty"><td colspan="4">Нет провайдеров с тремя и более участниками</td></tr>`;
  // OONI knows ISPs but not regions: its rows only for the whole country, under their own heading.
  const o = state.region ? null : ooniOf(state.target);
  if (o && o.raw.asns?.length) {
    $("isp-rows").innerHTML +=
      `<tr class="src-head"><td colspan="4">OONI, 7 дней: замеры и доля аномалий</td></tr>` +
      o.raw.asns
        .filter((a) => a.measurements >= 10)
        .map((a) => {
          const sh = (a.anomaly + a.confirmed) / a.measurements;
          return `<tr>
            <td>${esc(asnName(a.asn) || "—")}<span class="asn">AS${a.asn}</span></td>
            <td class="num">${num(a.measurements)}</td>
            <td><span class="bar"><span class="meter ooni"><i data-w="${Math.round(sh * 100)}"></i></span>≈${pct(sh)}</span></td>
            <td class="method muted">аномалии OONI</td>
          </tr>`;
        })
        .join("");
  }
  applyMeters();
}

// ---- History --------------------------------------------------------------------------------------

function renderHistory(data) {
  $("history-sub").textContent = state.region ? regionName(state.region) : "вся страна";
  const svg = $("history");
  const W = 520;
  const H = 180;
  const m = { l: 34, r: 6, t: 8, b: 22 };
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  const today = new Date();
  const days = [];
  for (let i = 29; i >= 0; i--) {
    const d = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate() - i));
    days.push(d.toISOString().slice(0, 10));
  }
  const byDay = new Map(data.days.map((d) => [d.day, d]));
  const iw = W - m.l - m.r;
  const ih = H - m.t - m.b;
  const step = iw / days.length;
  const bw = Math.max(2, step - 2);
  const y = (v) => m.t + ih * (1 - v);
  let out = "";
  for (const v of [0, 0.5, 1]) {
    out += `<line class="${v === 0 ? "baseline" : "gridline"}" x1="${m.l}" x2="${W - m.r}" y1="${y(v)}" y2="${y(v)}"/>`;
    out += `<text class="tick" x="${m.l - 6}" y="${y(v) + 3}" text-anchor="end">${v * 100}%</text>`;
  }
  // OONI, whole country only (it has no regions): a line over our bars, same 0–100% axis.
  const ooni = state.region ? null : ooniOf(state.target);
  const ooniByDay = new Map((ooni?.raw.days ?? []).filter((d) => d.measurements >= 5).map((d) => [d.day, d]));
  const ooniShare = (d) => (d.anomaly + d.confirmed) / d.measurements;
  $("history-legend").hidden = ooniByDay.size === 0;

  days.forEach((day, i) => {
    const x = m.l + i * step + 1;
    const d = byDay.get(day);
    if (d || ooniByDay.has(day)) {
      out += `<rect class="hit" data-day="${day}" x="${x - 1}" y="${m.t}" width="${step}" height="${ih}"/>`;
    }
    if (d) {
      const h = Math.max(d.blocked > 0 ? 2 : 0, ih * d.blocked);
      // Rounded data-end, square on the baseline.
      const r = Math.min(4, h / 2, bw / 2);
      const top = y(0) - h;
      out +=
        h > 0
          ? `<path class="bar" d="M${x},${y(0)} V${top + r} Q${x},${top} ${x + r},${top} H${x + bw - r} Q${x + bw},${top} ${x + bw},${top + r} V${y(0)} Z"/>`
          : `<path class="bar"/>`;
    } else if (ooniByDay.has(day)) {
      out += `<path class="bar"/>`; // keeps .hit + .bar pairs for the hover rule
    }
    // A date every 7 days, counted from today so the last bar is always labelled.
    if ((days.length - 1 - i) % 7 === 0) {
      out += `<text class="tick" x="${x + bw / 2}" y="${H - 6}" text-anchor="middle">${day.slice(8, 10)}.${day.slice(5, 7)}</text>`;
    }
  });
  // The line breaks over days OONI has no data for, instead of bridging them.
  let path = "";
  let open = false;
  const dots = [];
  days.forEach((day, i) => {
    const o = ooniByDay.get(day);
    if (!o) {
      open = false;
      return;
    }
    const cx = m.l + i * step + 1 + bw / 2;
    const cy = y(ooniShare(o));
    path += `${open ? "L" : "M"}${cx.toFixed(1)},${cy.toFixed(1)} `;
    open = true;
    dots.push([cx, cy]);
  });
  if (path) {
    out += `<path class="ooni-line" d="${path}"/>`;
    // The last point gets a marker: where the line ends today.
    const [lx, ly] = dots[dots.length - 1];
    out += `<circle class="ooni-dot" cx="${lx.toFixed(1)}" cy="${ly.toFixed(1)}" r="4"/>`;
  }

  if (data.days.length === 0 && ooniByDay.size === 0) {
    out += `<text class="empty" x="${m.l + iw / 2}" y="${m.t + ih / 2}" text-anchor="middle">Пока нет дней с тремя и более участниками</text>`;
  }
  svg.innerHTML = out;
  for (const hit of svg.querySelectorAll(".hit")) {
    const d = byDay.get(hit.dataset.day);
    const o = ooniByDay.get(hit.dataset.day);
    const ours = d ? statRows(d) : `<div class="row"><span>Наши замеры</span><span>мало данных</span></div>`;
    const theirs = o
      ? `<div class="row ooni"><span>OONI, аномалии</span><span>${pct(ooniShare(o))} из ${num(o.measurements)}</span></div>`
      : "";
    hit.addEventListener("pointermove", (e) => showTip(`<b>${hit.dataset.day}</b>${ours}${theirs}`, e));
    hit.addEventListener("pointerleave", hideTip);
  }
}

// ---- Other sources --------------------------------------------------------------------------------

let external = null;

/** data/external.json: rebuilt daily on the Pages mirror; the main site takes that fresh copy and falls back to its own. */
async function loadExternal() {
  const local = ON_PAGES || ["localhost", "127.0.0.1"].includes(location.hostname);
  const urls = local ? ["data/external.json"] : [`${PAGES}data/external.json`, "data/external.json"];
  for (const url of urls) {
    try {
      const res = await fetch(url, { cache: "no-cache" });
      if (res.ok) return await res.json();
    } catch {
      // next one
    }
  }
  return null;
}

const num = (n) => n.toLocaleString("ru-RU");
const share = (part, all) => (all > 0 ? pct(part / all) : "—");
const fmtDate = (d) => `${d.slice(8, 10)}.${d.slice(5, 7)}.${d.slice(0, 4)}`;
const link = (url, text) => `<a href="${esc(url)}" rel="noopener" target="_blank">${esc(text)}</a>`;

function renderExternal() {
  const box = $("ext");
  if (!external) {
    box.innerHTML = `<p class="muted">Не удалось загрузить данные других источников.</p>`;
    return;
  }
  const id = state.target;
  const blocks = [];

  const rkn = external.rkn?.targets?.[id];
  if (rkn) {
    const reg = rkn.register
      ? `<b class="flag on">в реестре</b> ${rkn.register !== hostOf(id) ? `<span class="muted">(домен ${esc(rkn.register)})</span>` : ""}`
      : `<b class="flag">нет в реестре</b>`;
    const comm = rkn.community
      ? `<div class="ext-line muted">Есть в списке сообщества «нужен обход»: блокируется без записи в реестре или закрыт самим сервисом для России.</div>`
      : "";
    blocks.push(`<div class="ext-block"><div class="ext-head"><span class="label">Реестр Роскомнадзора</span>${link(external.rkn.url, "antifilter.download")}</div>
      <div class="ext-line">${reg}</div>${comm}</div>`);
  }

  const o = external.ooni?.targets?.[id];
  if (o && !o.error) {
    const head = `<div class="ext-head"><span class="label">OONI, ${esc(fmtDate(external.ooni.since))} — ${esc(fmtDate(external.ooni.until))}</span>${link(`https://explorer.ooni.org/chart/mat?probe_cc=RU&test_name=web_connectivity&domain=${encodeURIComponent(o.domain)}&axis_x=measurement_start_day`, "OONI Explorer")}</div>`;
    if (o.measurements === 0) {
      blocks.push(`<div class="ext-block">${head}<div class="ext-line muted">Нет замеров ${esc(o.domain)} из России за неделю.</div></div>`);
    } else {
      const rows = o.asns
        .map((a) => `<tr><td class="mono">AS${a.asn}</td><td class="num">${num(a.measurements)}</td><td class="num">${share(a.anomaly + a.confirmed, a.measurements)}</td></tr>`)
        .join("");
      blocks.push(`<div class="ext-block">${head}
        <div class="ext-line"><b>${num(o.measurements)}</b> замеров ${esc(o.domain)}: аномалия в <b>${share(o.anomaly, o.measurements)}</b>,
          подтверждённая блокировка в <b>${share(o.confirmed, o.measurements)}</b>, без проблем — ${share(o.ok, o.measurements)}</div>
        <table class="data compact"><thead><tr><th>Сеть</th><th class="num">Замеры</th><th class="num">Аномалии</th></tr></thead><tbody>${rows}</tbody></table>
        <div class="ext-line muted">«Аномалия» у OONI — признак вмешательства, но не доказательство; «подтверждённая» — найдена известная заглушка. Данные OONI: CC BY-NC-SA 4.0.</div>
      </div>`);
    }
  }

  const evs = (external.events ?? [])
    .filter((e) => e.targets.includes(id) || e.targets.length === 0)
    .sort((a, b) => b.date.localeCompare(a.date));
  if (evs.length) {
    blocks.push(`<div class="ext-block"><div class="ext-head"><span class="label">События</span></div><ul class="events">${evs
      .map((e) => `<li><span class="mono muted">${esc(fmtDate(e.date))}</span> ${esc(e.ru)} ${link(e.source, "источник")}</li>`)
      .join("")}</ul></div>`);
  }

  const radar = radarBlock();
  if (radar) blocks.push(radar);

  box.innerHTML = blocks.length ? blocks.join("") : `<p class="muted">Для этой цели других источников нет.</p>`;
}

const CAUSES = {
  GOVERNMENT_DIRECTED: "по решению властей",
  POWER_OUTAGE: "отключение электричества",
  CABLE_CUT: "обрыв кабеля",
  TECHNICAL_PROBLEMS: "технические проблемы",
  WEATHER: "погода",
  MILITARY_ACTION: "боевые действия",
  MAINTENANCE: "работы",
};
const isoDate = (s) => (s ? fmtDate(String(s).slice(0, 10)) : "…");

function radarNote() {
  const n = external?.radar?.outages?.length ?? 0;
  return n > 0 ? ` Cloudflare Radar за 4 недели подтвердил отключений: ${n} — список в «Других источниках» ниже.` : "";
}

/** Cloudflare Radar, whole country: verified outages and the ISPs whose traffic dropped. Same for every target. */
function radarBlock() {
  const r = external?.radar;
  if (!r || r.error) return null;
  const outages = (r.outages ?? []).slice(0, 8);
  const anomalies = (r.anomalies ?? []).filter((a) => a.asn?.asn).slice(0, 8);
  if (!outages.length && !anomalies.length) {
    return `<div class="ext-block"><div class="ext-head"><span class="label">Cloudflare Radar, 4 недели</span>${link(r.url, "Radar")}</div>
      <div class="ext-line muted">Отключений и аномалий трафика в России не отмечено.</div></div>`;
  }
  const outageItems = outages
    .map((o) => {
      const who = o.asns.map((a) => a.name || `AS${a.asn}`).join(", ");
      const what = [o.scope, who, CAUSES[o.cause] ?? ""].filter(Boolean).join(" · ");
      return `<li><span class="mono muted">${esc(isoDate(o.start))}</span> ${esc(what || o.description || "отключение")}${o.link ? ` ${link(o.link, "подробнее")}` : ""}</li>`;
    })
    .join("");
  const anomalyItems = anomalies
    .map((a) => `<li><span class="mono muted">${esc(isoDate(a.start))}</span> ${esc(a.asn.name || "—")} <span class="mono muted">AS${a.asn.asn}</span>${a.region ? ` · ${esc(a.region)}` : ""}</li>`)
    .join("");
  return `<div class="ext-block"><div class="ext-head"><span class="label">Cloudflare Radar, 4 недели</span>${link(r.url, "Radar")}</div>
    ${outageItems ? `<div class="ext-line">Подтверждённые отключения</div><ul class="events">${outageItems}</ul>` : ""}
    ${anomalyItems ? `<div class="ext-line">Провалы трафика у провайдеров</div><ul class="events">${anomalyItems}</ul>` : ""}
    <div class="ext-line muted">Данные Cloudflare Radar: CC BY-NC 4.0.</div></div>`;
}

/** OONI's view of a target over 7 days, or null when it has too few measurements to say anything. */
const OONI_MIN = 30;
function ooniOf(id) {
  const o = external?.ooni?.targets?.[id];
  if (!o || o.error || !(o.measurements >= OONI_MIN)) return null;
  return { share: (o.anomaly + o.confirmed) / o.measurements, measurements: o.measurements, raw: o };
}

const asnName = (asn) => external?.ooni?.asn_names?.[asn] ?? "";

function hostOf(id) {
  return (targets.find((t) => t.id === id)?.host ?? "").replace(/^www\./, "");
}

// ---- Refresh --------------------------------------------------------------------------------------

function targetName(id) {
  return id === WHITELIST ? "Белые списки (доля отчётов)" : targets.find((t) => t.id === id)?.name ?? id;
}

async function refreshDetails() {
  const region = state.region;
  const [isps, history] = await Promise.all([
    api("isps", { target: state.target, region, ...common() }),
    api("history", { target: state.target, region, net: state.net, days: 30 }),
  ]);
  renderIsps(isps);
  renderHistory(history);
}

async function refreshTarget() {
  $("target-name").textContent = targetName(state.target);
  const period = { 1: "за сутки", 7: "за 7 дней", 30: "за 30 дней" }[state.days];
  const net = { "": "", home: ", домашний интернет", mobile: ", мобильный интернет" }[state.net];
  $("map-sub").textContent = `доля замеров с блокировкой ${period}${net}`;
  const map = await api("map", { target: state.target, ...common() });
  const haveOutages = Boolean(external?.ioda?.regions);
  const auto = state.layer === "auto" && map.regions.length === 0 && haveOutages;
  mapMode = (state.layer === "outages" && haveOutages) || auto ? "outages" : "blocks";
  if (mapMode === "outages") {
    state.region = null;
    renderOutages(auto);
  } else {
    renderMap(map);
  }
  syncControls();
  if (state.region && !regionData.has(state.region)) state.region = null;
  $("region-bar").hidden = !state.region;
  if (state.region) $("region-name").textContent = regionName(state.region);
  renderExternal();
  await refreshDetails();
}

async function refresh() {
  const summary = await api("summary", common());
  renderTargets(summary);
  applyMeters();
  await refreshTarget();
}

async function main() {
  readUrl();
  initControls();
  syncControls();
  const [list, , ext] = await Promise.all([api("targets"), initMap(), loadExternal()]);
  targets = list.targets;
  external = ext;
  if (state.target !== WHITELIST && !targets.some((t) => t.id === state.target)) state.target = "youtube";
  writeUrl();
  await refresh();
}

main().catch((e) => {
  $("map-empty").hidden = false;
  $("map-empty").textContent = `Не удалось загрузить данные: ${e.message}`;
});
