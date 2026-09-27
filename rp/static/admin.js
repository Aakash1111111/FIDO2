import { api } from "./webauthn.js";

const $ = (id) => document.getElementById(id);
const fmt = (ts) => (ts ? new Date(ts).toLocaleString() : "—");
let timer = null;

function row(tbody, values, classes = []) {
  const tr = document.createElement("tr");
  values.forEach((v, i) => {
    const td = document.createElement("td");
    td.textContent = v ?? "";
    if (classes[i]) td.className = classes[i];
    tr.appendChild(td);
  });
  tbody.appendChild(tr);
}

function tile(label, value) {
  const d = document.createElement("div");
  d.className = "tile";
  const v = document.createElement("div");
  v.className = "tile-value";
  v.textContent = value;
  const l = document.createElement("div");
  l.className = "tile-label";
  l.textContent = label;
  d.append(v, l);
  return d;
}

async function load() {
  let token = "";
  try { token = sessionStorage.getItem("adminToken") || ""; } catch (_) { /* storage blocked */ }
  let d;
  try {
    d = await api("/admin/api", undefined, "GET", { "X-Admin-Token": token });
  } catch (err) {
    $("gate").hidden = false;
    $("content").hidden = true;
    $("gate-msg").textContent = err.reason === "ADMIN_TOKEN_REQUIRED"
      ? "Enter the admin token (RP_ADMIN_TOKEN). If it is not set on the server, the admin dashboard is disabled."
      : err.reason;
    return;
  }
  $("gate").hidden = true;
  $("content").hidden = false;

  const by = (c, r) => d.stats.find((s) => s.ceremony === c && s.result === r) || { n: 0 };
  const rate = (c) => {
    const ok = by(c, "success").n, bad = by(c, "failure").n;
    return ok + bad ? `${((100 * ok) / (ok + bad)).toFixed(1)} %` : "—";
  };
  const avg = (c, key, scale = 1) => (by(c, "success")[key] != null ? (by(c, "success")[key] / scale).toFixed(1) + " ms" : "—");
  $("tiles").replaceChildren(
    tile("users", d.users.length),
    tile("registered keys", d.credentials.length),
    tile("registrations ok", `${by("reg", "success").n} (${rate("reg")})`),
    tile("logins ok", `${by("auth", "success").n} (${rate("auth")})`),
    tile("avg login verify (server)", avg("auth", "avg_us", 1000)),
    tile("avg login total (browser, incl. button)", avg("auth", "avg_client_ms")),
  );

  const u = $("users"); u.replaceChildren();
  d.users.forEach((x) => row(u, [x.username, x.credentials, fmt(x.created_at)], ["", "num", ""]));
  const c = $("creds"); c.replaceChildren();
  d.credentials.forEach((x) => row(c, [x.username, x.id.slice(0, 12) + "…", x.is_project_token ? "this project" : x.aaguid,
                                        x.fmt, x.sign_count, fmt(x.last_used_at)], ["", "mono", "", "", "num", ""]));
  const r = $("reasons"); r.replaceChildren();
  d.failure_reasons.forEach((x) => row(r, [x.ceremony, x.reason, x.n], ["", "", "num"]));
  const e = $("events"); e.replaceChildren();
  d.events.forEach((x) => row(e, [fmt(x.ts), x.username, x.ceremony, x.result, x.reason,
                                  x.server_verify_ms?.toFixed(1), x.client_total_ms?.toFixed(0), x.run_id],
                              ["", "", "", x.result === "success" ? "ok" : "error", "", "num", "num", ""]));
  $("updated").textContent = new Date().toLocaleTimeString();
}

$("save").addEventListener("click", () => {
  try { sessionStorage.setItem("adminToken", $("token").value); } catch (_) { /* ignore */ }
  load();
});
$("refresh").addEventListener("click", load);
$("auto").addEventListener("change", (ev) => {
  clearInterval(timer);
  if (ev.target.checked) timer = setInterval(load, 3000);
});
load();
