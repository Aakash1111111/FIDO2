import { api, assertionToJSON, attestationToJSON, creationOptionsFromJSON, explain,
         requestOptionsFromJSON, supportCheck } from "./webauthn.js";

const $ = (id) => document.getElementById(id);
const log = $("log");
let inProgress = false;

function status(msg, kind = "info") {
  const li = document.createElement("li");
  li.className = kind;
  li.textContent = `${new Date().toLocaleTimeString()}  ${msg}`;
  log.prepend(li);
  $("log-empty").hidden = true;
  $("banner").textContent = msg;
  $("banner").className = `banner ${kind}`;
}

function busy(on) {
  inProgress = on;
  $("account-form").setAttribute("aria-busy", String(on));
  $("username").disabled = on;
  for (const b of document.querySelectorAll("button")) b.disabled = on;
}

async function register() {
  if (inProgress) return;
  if (!$("username").value.trim()) {
    status("Enter your username to continue.", "error");
    $("username").focus();
    return;
  }
  const username = $("username").value.trim();
  busy(true);
  const t0 = performance.now();
  try {
    status("Requesting registration options…");
    const options = await api("/register/options", { username });
    status("Follow the browser prompt: enter your security key PIN, then press BOOT when asked…", "action");
    const cred = await navigator.credentials.create({ publicKey: creationOptionsFromJSON(options) });
    status("Verifying with the server…");
    const res = await api("/register/verify", { credential: attestationToJSON(cred),
                                                client_total_ms: performance.now() - t0 });
    status(`Registered a ${res.fmt} credential for ${res.username} (server verify ${res.server_verify_ms.toFixed(1)} ms).`, "ok");
    $("dash").hidden = false;
  } catch (err) {
    status(`Registration failed: ${explain(err)}`, "error");
  } finally {
    busy(false);
  }
}

async function login() {
  if (inProgress) return;
  if (!$("username").value.trim()) {
    status("Enter your username to continue.", "error");
    $("username").focus();
    return;
  }
  const username = $("username").value.trim();
  busy(true);
  const t0 = performance.now();
  try {
    status("Requesting login options…");
    const options = await api("/login/options", { username });
    status("Follow the browser prompt: enter your security key PIN, then press BOOT when asked…", "action");
    const cred = await navigator.credentials.get({ publicKey: requestOptionsFromJSON(options) });
    status("Verifying the signature with the server…");
    const res = await api("/login/verify", { credential: assertionToJSON(cred),
                                             client_total_ms: performance.now() - t0 });
    status(`Logged in as ${res.username}. Signature counter is now ${res.sign_count}.`, "ok");
    $("dash").hidden = false;
  } catch (err) {
    status(`Login failed: ${explain(err)}`, "error");
  } finally {
    busy(false);
  }
}

$("register").addEventListener("click", register);
$("account-form").addEventListener("submit", (event) => {
  event.preventDefault();
  login();
});
$("origin").textContent = location.origin;
const problem = supportCheck();
if (problem) status(problem, "error");
// Warn early when the page is opened at an address the RP does not accept
// (e.g. 127.0.0.1 instead of localhost, or a different port).
fetch("/healthz").then((r) => r.json()).then((h) => {
  if (!h.origins.includes(location.origin)) {
    status(`Wrong address: this page is ${location.origin}, but the site is configured for ${h.origins.join(", ")} (RP ID "${h.rp_id}"). Open ${h.origins[0]} instead.`, "error");
  }
}).catch(() => {});
fetch("/me", { credentials: "same-origin" }).then((r) => { if (r.ok) $("dash").hidden = false; });
