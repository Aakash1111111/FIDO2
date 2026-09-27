import { api, attestationToJSON, creationOptionsFromJSON, explain } from "./webauthn.js";

const $ = (id) => document.getElementById(id);
const fmt = (ts) => (ts ? new Date(ts).toLocaleString() : "never");

function cell(tr, text, cls) {
  const td = document.createElement("td");
  td.textContent = text ?? "";
  if (cls) td.className = cls;
  tr.appendChild(td);
  return td;
}

async function load() {
  let me;
  try {
    me = await api("/me", undefined, "GET");
  } catch (_) {
    $("content").hidden = true;
    $("signin").hidden = false;
    return;
  }
  $("who").textContent = me.username;
  $("since").textContent = fmt(me.created_at);
  $("ncred").textContent = me.credentials.length;

  const tb = $("creds");
  tb.replaceChildren();
  for (const c of me.credentials) {
    const tr = document.createElement("tr");
    cell(tr, c.id.slice(0, 12) + "…", "mono");
    cell(tr, c.is_project_token ? "ESP32-S3 FIDO2 Token (this project)" : (c.aaguid || "unknown"));
    cell(tr, c.fmt);
    cell(tr, c.sign_count, "num");
    cell(tr, fmt(c.created_at));
    cell(tr, fmt(c.last_used_at));
    const td = cell(tr, "");
    const b = document.createElement("button");
    b.className = "danger small";
    b.textContent = "Remove";
    b.addEventListener("click", async () => {
      if (!confirm("Remove this key from your account? It will no longer be able to log in.")) return;
      try { await api(`/credentials/${c.id}`, undefined, "DELETE"); load(); }
      catch (err) { alert(err.reason === "LAST_CREDENTIAL" ? "You cannot remove your only key." : explain(err)); }
    });
    td.appendChild(b);
    tb.appendChild(tr);
  }

  const eb = $("events");
  eb.replaceChildren();
  for (const e of me.events) {
    const tr = document.createElement("tr");
    cell(tr, fmt(e.ts));
    cell(tr, e.ceremony === "reg" ? "register" : "login");
    cell(tr, e.result, e.result === "success" ? "ok" : "error");
    cell(tr, e.reason || "");
    cell(tr, e.server_verify_ms != null ? e.server_verify_ms.toFixed(1) : "", "num");
    cell(tr, e.client_total_ms != null ? e.client_total_ms.toFixed(0) : "", "num");
    eb.appendChild(tr);
  }
}

async function addKey() {
  const t0 = performance.now();
  try {
    const options = await api("/register/options", { username: $("who").textContent });
    $("msg").textContent = "Press the BOOT button on the token…";
    const cred = await navigator.credentials.create({ publicKey: creationOptionsFromJSON(options) });
    await api("/register/verify", { credential: attestationToJSON(cred), client_total_ms: performance.now() - t0 });
    $("msg").textContent = "Key added.";
    load();
  } catch (err) {
    $("msg").textContent = explain(err);
  }
}

$("logout").addEventListener("click", async () => { await api("/logout"); location.href = "/"; });
$("add").addEventListener("click", addKey);
$("refresh").addEventListener("click", load);
load();
