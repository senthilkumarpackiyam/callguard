// CallGuard website: the latest-vulnerabilities list, CVE details, the streaming chat, exports and email drafts.
// Text from the data (CVE descriptions, AI answers) is always escaped or sanitized before it's shown.
"use strict";

const $ = (id) => document.getElementById(id);
const onPhone = window.matchMedia("(max-width: 640px)").matches;
const state = { offset: 0, pageSize: onPhone ? 10 : 30, total: 0, status: null, products: [], lastQuestion: "" };
const MAILTO_LIMIT = 1800; // email apps accept roughly this much text in a pre-filled draft

// ---------- helpers ----------
function esc(text) {
  return String(text ?? "").replace(/[&<>"']/g, (c) => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"})[c]);
}
function safeUrl(url) {
  return /^https?:\/\//i.test(url || "") ? url : null;
}
function fmtDate(iso) {
  return new Date(iso.length <= 10 ? iso + "T00:00:00Z" : iso)
    .toLocaleDateString(undefined, {day: "numeric", month: "short", year: "numeric", timeZone: "UTC"});
}
function sevBadge(severity, score) {
  const sev = severity || "NONE";
  const label = severity ? `${severity[0]}${severity.slice(1).toLowerCase()} ${score ?? ""}` : "No score";
  return `<span class="badge sev-${esc(sev)}">${esc(label.trim())}</span>`;
}
function filters() {
  return {
    vendor: $("f-vendor").value, product: $("f-product").value, severity: $("f-severity").value,
    exploited: $("f-exploited").checked ? "true" : "", q: $("f-q").value.trim(),
  };
}
function query(params) {
  return new URLSearchParams(Object.entries(params).filter(([, v]) => v !== "" && v != null)).toString();
}
function asOfText(status) {
  const d = new Date(status.as_of);
  return d.toLocaleString(undefined, {day: "numeric", month: "short", hour: "2-digit", minute: "2-digit", timeZone: "UTC"}) + " UTC";
}
function download(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = Object.assign(document.createElement("a"), {href: url, download: name});
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

// ---------- status: freshness badge, stats, filters ----------
async function loadStatus() {
  const status = await (await fetch("/api/status")).json();
  const changed = state.status && state.status.as_of !== status.as_of;
  state.status = status;
  state.products = status.products;
  const ageHours = (Date.now() - new Date(status.as_of)) / 3.6e6;
  $("freshness").classList.toggle("stale", ageHours > 3);
  $("freshness-text").textContent = `Data as of ${asOfText(status)}`;
  $("freshness").title = `CISA KEV catalog ${status.kev_catalog} · EPSS scores of ${status.epss_date}` +
    (ageHours > 3 ? " · The data may be out of date: check that the sync is running." : "");
  $("stat-records").textContent = status.records.toLocaleString();
  $("stat-exploited").textContent = status.exploited;
  $("stat-products").textContent = status.products_covered;
  if ($("f-vendor").options.length === 1) {
    status.vendors.forEach((v) => $("f-vendor").add(new Option(v, v)));
    fillProducts();
    $("product-tags").innerHTML = status.products.map((p) =>
      `<li class="${p.scope === "cloud" ? "cloud" : ""}">${esc(p.name)}${p.scope === "cloud" ? " · cloud" : ""}</li>`).join("");
  }
  if (changed) loadList(true); // a sync brought new data
}
function fillProducts() {
  const vendor = $("f-vendor").value;
  const keep = $("f-product").value;
  $("f-product").length = 1;
  state.products.filter((p) => !vendor || p.vendor === vendor)
    .forEach((p) => $("f-product").add(new Option(p.name, p.id)));
  $("f-product").value = [...$("f-product").options].some((o) => o.value === keep) ? keep : "";
}

// ---------- latest vulnerabilities ----------
async function loadList(reset) {
  if (reset) state.offset = 0;
  const params = {...filters(), limit: state.pageSize, offset: state.offset};
  const list = $("cve-list");
  if (reset) list.innerHTML = `<li class="empty">Loading…</li>`;
  let data;
  try {
    data = await (await fetch(`/api/cves?${query(params)}`)).json();
  } catch {
    list.innerHTML = `<li class="empty">Couldn't load the list. Is the CallGuard server running?</li>`;
    return;
  }
  state.total = data.total;
  if (reset) list.innerHTML = "";
  if (!data.items.length && reset) list.innerHTML = `<li class="empty">No vulnerabilities match these filters.</li>`;
  list.insertAdjacentHTML("beforeend", data.items.map((c) => `
    <li><button class="cve-item sev-border-${esc(c.severity || "NONE")}" data-cve="${esc(c.id)}" type="button">
      <span class="top"><span class="id">${esc(c.id)}</span>${sevBadge(c.severity, c.score)}</span>
      <span class="meta"><span>${esc(c.products.join(", "))}</span><span>${esc(fmtDate(c.published))}</span>
        ${c.exploited ? `<span class="badge exploited">Exploited</span>` : ""}
        ${c.ransomware ? `<span class="badge ransom">Ransomware</span>` : ""}</span>
      <span class="summary">${esc(c.summary)}</span>
    </button></li>`).join(""));
  state.offset += data.items.length;
  $("latest-count").textContent = `${data.total.toLocaleString()} match${data.total === 1 ? "" : "es"} · newest first`;
  $("more").hidden = state.offset >= state.total;
  const q = query(filters());
  for (const fmt of ["csv", "xlsx", "pdf"]) $(`export-${fmt}`).href = `/api/export/cves.${fmt}${q ? "?" + q : ""}`;
}

// ---------- detail drawer ----------
async function openDetails(id) {
  const res = await fetch(`/api/cves/${encodeURIComponent(id)}`);
  if (!res.ok) return;
  const r = await res.json();
  const cvss = r.cvss || {};
  const names = Object.fromEntries(r.products.map((p) => [p.id, p.name]));
  const versions = {};
  r.versions.filter((v) => v.status === "affected").forEach((v) => {
    (versions[v.product] ??= new Set()).add(v.range);
  });
  const versionHtml = Object.entries(versions).map(([pid, ranges]) => {
    const list = [...ranges];
    const shown = list.slice(0, 12).map(esc).join(", ") + (list.length > 12 ? ` and ${list.length - 12} more` : "");
    return `<li><b>${esc(names[pid] || pid)}</b>: ${shown}</li>`;
  }).join("") || `<li>Not in the structured data. The description may say more.</li>`;
  const e = r.exploited;
  const epss = r.epss ? Math.round(r.epss.score * 1000) / 10 : null;
  const links = r.links.map((l) => safeUrl(l.url) ? `<li><a href="${esc(l.url)}" target="_blank" rel="noopener noreferrer">${esc(l.url)}</a>${l.tags.length ? ` <span class="sub">(${esc(l.tags.join(", "))})</span>` : ""}</li>` : "").join("");
  $("drawer-body").innerHTML = `
    <p class="sub">Published ${esc(fmtDate(r.published))} · updated ${esc(fmtDate(r.last_modified))} · NVD status: ${esc(r.nvd_status)}</p>
    <h3 id="drawer-title">${esc(r.id)}</h3>
    <div class="badges">${sevBadge(cvss.severity, cvss.score)}
      ${e ? `<span class="badge exploited">Exploited since ${esc(fmtDate(e.since))}</span>` : `<span class="badge sev-NONE">Not in CISA KEV</span>`}
      ${e && e.ransomware === "Known" ? `<span class="badge ransom">Used by ransomware</span>` : ""}</div>
    <p class="products">${esc(r.products.map((p) => p.name).join(" · "))}</p>
    <section><h4>What it is</h4><p>${esc(r.description)}</p>
      ${r.cwe.length ? `<p class="sub">Weakness: ${esc(r.cwe.join(", "))}</p>` : ""}</section>
    <section><h4>Affected versions</h4><ul>${versionHtml}</ul></section>
    ${e ? `<section><h4>Exploitation (CISA KEV)</h4>
      <p>In CISA's known-exploited list since ${esc(fmtDate(e.since))}. Ransomware use: ${esc(e.ransomware || "Unknown")}${e.ransomware === "Unknown" ? " (not confirmed, which is not the same as no)" : ""}.</p>
      ${e.summary ? `<p>${esc(e.summary)}</p>` : ""}
      <p class="sub">Required action: ${esc(e.required_action)}${e.federal_due_date ? ` · US federal due date ${esc(fmtDate(e.federal_due_date))}` : ""}</p></section>` : ""}
    ${epss !== null ? `<section><h4>Exploit forecast (EPSS)</h4><p><b>${epss}%</b> chance of exploitation in the next 30 days</p>
      <div class="epss-bar"><span style="width:${Math.min(100, Math.max(2, epss))}%"></span></div>
      <p class="sub">Scored ${esc(r.epss.date)} · a forecast, not a confirmation</p></section>` : ""}
    ${links ? `<section><h4>Advisories and fixes</h4><ul>${links}</ul></section>` : ""}
    <div class="drawer-actions">
      <button class="btn primary" type="button" id="d-ask">Ask CallGuard about this</button>
      <button class="btn ghost" type="button" id="d-email">✉ Email</button>
      <a class="btn ghost" href="${esc(r.nvd_page)}" target="_blank" rel="noopener noreferrer">Open in NVD ↗</a>
    </div>`;
  $("d-ask").onclick = () => { closeDrawer(); ask(`Tell me about ${r.id}. How serious is it, and what should we do?`); };
  $("d-email").onclick = () => openEmail(`CallGuard: ${r.id} (${r.products.map((p) => p.name).join(", ")})`, [
    `${r.id}: ${r.products.map((p) => p.name).join(", ")}`,
    `Severity: ${cvss.severity ? `${cvss.severity} ${cvss.score}` : "no score yet"}`,
    `Exploited (CISA KEV): ${e ? `yes, since ${e.since}; ransomware use: ${e.ransomware}` : "not listed"}`,
    `Affected versions: ${Object.entries(versions).map(([pid, s]) => `${names[pid] || pid}: ${[...s].slice(0, 8).join(", ")}${s.size > 8 ? " …" : ""}`).join("; ") || "see the description"}`,
    "", r.description, "", `Details: ${r.nvd_page}`, ...r.links.slice(0, 2).map((l) => `Advisory: ${l.url}`),
  ].join("\n"));
  $("drawer").classList.add("open");
  $("drawer").setAttribute("aria-hidden", "false");
  $("scrim").hidden = false;
  $("drawer-close").focus();
}
function closeDrawer() {
  $("drawer").classList.remove("open");
  $("drawer").setAttribute("aria-hidden", "true");
  $("scrim").hidden = true;
}

// ---------- chat ----------
function renderMarkdown(text) {
  // [CVE-…] citations become links that open the detail panel
  const linked = text.replace(/\[(CVE-\d{4}-\d{4,})\](?!\()/g, "[$1](#cve:$1)");
  const html = DOMPurify.sanitize(marked.parse(linked), {ALLOWED_URI_REGEXP: /^(?:https?:|#cve:)/i});
  const box = document.createElement("div");
  box.innerHTML = html;
  box.querySelectorAll("a").forEach((a) => {
    const href = a.getAttribute("href") || "";
    if (href.startsWith("#cve:")) { a.classList.add("cve-link"); a.dataset.cve = href.slice(5); a.removeAttribute("href"); a.setAttribute("role", "button"); a.tabIndex = 0; }
    else { a.target = "_blank"; a.rel = "noopener noreferrer"; }
  });
  return box.innerHTML;
}
function plainText(markdown) {
  return markdown.replace(/\[(CVE-\d{4}-\d{4,})\](?!\()/g, "$1").replace(/\[([^\]]+)\]\((https?:[^)]+)\)/g, "$1 ($2)")
    .replace(/\*\*([^*]+)\*\*/g, "$1").replace(/(^|\s)_([^_]+)_/g, "$1$2").replace(/^\s*[-*]\s+/gm, "• ");
}
function addMessage(role, html) {
  const wrap = document.createElement("div");
  wrap.className = `msg ${role}`;
  wrap.innerHTML = role === "bot" ? `<img class="avatar" src="/static/brand/logo-mark.svg" alt=""><div class="bubble">${html}</div>`
    : `<div class="bubble">${html}</div>`;
  $("messages").append(wrap);
  $("messages").scrollTop = $("messages").scrollHeight;
  return wrap.querySelector(".bubble");
}
async function ask(question) {
  question = question.trim();
  if (question.length < 3 || $("send").disabled) return;
  state.lastQuestion = question;
  addMessage("user", esc(question));
  const bubble = addMessage("bot", `<span class="status">Understanding the question…</span>`);
  $("send").disabled = true;
  // finished: once the full answer (or an error) is shown, a redraw still waiting for the next frame must not
  // paint the half-written text back over it
  let text = "", pending = false, finished = false;
  const paint = () => {
    pending = false;
    if (finished) return;
    bubble.innerHTML = renderMarkdown(text);
    $("messages").scrollTop = $("messages").scrollHeight;
  };
  try {
    const res = await fetch("/api/ask", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({question})});
    if (!res.ok) throw new Error(res.status === 422 ? "Please ask a slightly longer question." : `Server error ${res.status}`);
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    for (;;) {
      const {value, done} = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, {stream: true});
      let cut;
      while ((cut = buffer.indexOf("\n\n")) >= 0) {
        const block = buffer.slice(0, cut); buffer = buffer.slice(cut + 2);
        const name = (block.match(/^event: (.*)$/m) || [])[1];
        const data = JSON.parse((block.match(/^data: (.*)$/m) || [, "{}"])[1]);
        if (name === "status" && !text) bubble.innerHTML = `<span class="status">${esc(data.text)}</span>`;
        if (name === "token") { text += data.text; if (!pending) { pending = true; requestAnimationFrame(paint); } }
        if (name === "error") throw new Error(data.text);
        if (name === "done") { finished = true; finishAnswer(bubble, question, data); }
      }
    }
    if (!finished) throw new Error("The connection closed before the answer was finished. Please try again.");
  } catch (err) {
    finished = true;
    bubble.innerHTML = `<p>${esc(err.message || "Something went wrong. Please try again.")}</p>`;
  } finally {
    $("send").disabled = false;
  }
}
function finishAnswer(bubble, question, data) {
  bubble.innerHTML = renderMarkdown(data.text) + `
    <div class="answer-tools">
      <button class="btn small ghost" type="button" data-act="email">✉ Email</button>
      <button class="btn small ghost" type="button" data-act="pdf">⬇ PDF</button>
      <button class="btn small ghost" type="button" data-act="copy">Copy</button>
      <span class="meta">${esc(data.kind === "refusal" ? "Answered by CallGuard's rules" : `${data.seconds} s`)}</span>
    </div>`;
  bubble.querySelector('[data-act="email"]').onclick = () => openEmail(`CallGuard: ${question.slice(0, 80)}`,
    `Question: ${question}\n\n${plainText(data.text)}`);
  bubble.querySelector('[data-act="pdf"]').onclick = async (ev) => {
    ev.target.disabled = true;
    const res = await fetch("/api/export/answer.pdf", {method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({question, text: data.text})});
    if (res.ok) download(await res.blob(), "callguard-answer.pdf");
    ev.target.disabled = false;
  };
  bubble.querySelector('[data-act="copy"]').onclick = async (ev) => {
    await navigator.clipboard.writeText(`Question: ${question}\n\n${plainText(data.text)}`);
    ev.target.textContent = "Copied ✓"; setTimeout(() => (ev.target.textContent = "Copy"), 1500);
  };
  $("messages").scrollTop = $("messages").scrollHeight;
}

// ---------- email drafts (opened in the user's own email app) ----------
function openEmail(subject, body) {
  $("email-subject").value = subject;
  $("email-body").value = body + `\n\n— Sent from CallGuard. Data as of ${state.status ? asOfText(state.status) : "unknown"}. ` +
    "No CVE found does not mean a product or version is safe.";
  $("email-error").hidden = true;
  $("email-modal").hidden = false;
  $("email-to").focus();
}
function sendEmail() {
  const recipients = $("email-to").value.split(/[,;\s]+/).filter(Boolean);
  const bad = recipients.filter((r) => !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(r));
  const error = !recipients.length ? "Enter at least one email address." : bad.length ? `Please check: ${bad.join(", ")}` : "";
  $("email-error").textContent = error;
  $("email-error").hidden = !error;
  if (error) return;
  $("email-modal").hidden = true;
  window.location.href = mailtoLink(recipients, $("email-subject").value, $("email-body").value);
}
function mailtoLink(recipients, subject, body) {
  if (body.length > MAILTO_LIMIT) body = body.slice(0, MAILTO_LIMIT) + "\n… (shortened: open CallGuard for the full answer)";
  return `mailto:${recipients.map(encodeURIComponent).join(",")}` +
    `?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
}
async function emailList() {
  const f = filters();
  const data = await (await fetch(`/api/cves?${query({...f, limit: 15, offset: 0})}`)).json();
  const described = [f.vendor, f.product && state.products.find((p) => p.id === f.product)?.name, f.severity,
    f.exploited && "exploited only", f.q && `"${f.q}"`].filter(Boolean).join(", ");
  openEmail(`CallGuard: ${data.total} contact-center vulnerabilities${described ? ` (${described})` : ""}`,
    [`${data.total} vulnerabilities${described ? ` matching ${described}` : ""}, newest first` +
      (data.total > 15 ? " (first 15 shown):" : ":"), "",
     ...data.items.map((c) => `• ${c.id} · ${c.products.join(", ")} · ${c.severity ? `${c.severity} ${c.score}` : "no score"}` +
       `${c.exploited ? " · EXPLOITED" : ""} · ${c.published}`),
     "", "Full details: https://nvd.nist.gov/vuln/detail/<CVE number>"].join("\n"));
}

// ---------- wiring ----------
let searchTimer;
$("filters").addEventListener("change", (e) => { if (e.target.id === "f-vendor") fillProducts(); loadList(true); });
$("f-q").addEventListener("input", () => { clearTimeout(searchTimer); searchTimer = setTimeout(() => loadList(true), 250); });
$("filters").addEventListener("submit", (e) => e.preventDefault());
$("more").addEventListener("click", () => loadList(false));
$("cve-list").addEventListener("click", (e) => { const item = e.target.closest("[data-cve]"); if (item) openDetails(item.dataset.cve); });
$("messages").addEventListener("click", (e) => {
  const link = e.target.closest(".cve-link"); if (link) openDetails(link.dataset.cve);
  const chip = e.target.closest(".chip"); if (chip) ask(chip.textContent);
});
$("messages").addEventListener("keydown", (e) => { const link = e.target.closest(".cve-link"); if (link && e.key === "Enter") openDetails(link.dataset.cve); });
$("composer").addEventListener("submit", (e) => { e.preventDefault(); const q = $("question").value; $("question").value = ""; ask(q); });
$("question").addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); $("composer").requestSubmit(); } });
$("drawer-close").addEventListener("click", closeDrawer);
$("scrim").addEventListener("click", closeDrawer);
$("email-list").addEventListener("click", emailList);
$("email-cancel").addEventListener("click", () => ($("email-modal").hidden = true));
$("email-open").addEventListener("click", sendEmail);
document.addEventListener("keydown", (e) => { if (e.key === "Escape") { closeDrawer(); $("email-modal").hidden = true; } });

// Direct links: #cve=CVE-2024-41713 opens that CVE's details; #ask=<question> asks it
function followLink() {
  const target = decodeURIComponent(location.hash.slice(1));
  if (target.startsWith("cve=")) openDetails(target.slice(4));
  else if (target.startsWith("ask=")) { $("ask").scrollIntoView(); ask(target.slice(4)); }
}
window.addEventListener("hashchange", followLink);

loadStatus().then(() => loadList(true)).then(followLink)
  .catch(() => { $("freshness-text").textContent = "Server not reachable"; });
setInterval(() => loadStatus().catch(() => {}), 5 * 60 * 1000); // pick up a sync while the page is open
