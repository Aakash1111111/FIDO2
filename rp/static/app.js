import { api, assertionToJSON, attestationToJSON, creationOptionsFromJSON, explain,
         requestOptionsFromJSON, supportCheck } from "./webauthn.js";

const $ = (id) => document.getElementById(id);
const log = $("log");

function status(msg, kind = "info") {
  const li = document.createElement("li");
  li.className = kind;
  li.textContent = `${new Date().toLocaleTimeString()}  ${msg}`;
  log.prepend(li);
  $("banner").textContent = msg;
  $("banner").className = `banner ${kind}`;
}

function busy(on) {
  for (const b of document.querySelectorAll("button")) b.disabled = on;
}

async function register() {
  const username = $("username").value.trim();
  busy(true);
  const t0 = performance.now();
  try {
    status("Requesting registration options…");
    const options = await api("/register/options", { username });
    status("Press the BOOT button on your ESP32-S3 token now…", "action");
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
  const username = $("username").value.trim();
  busy(true);
  const t0 = performance.now();
  try {
    status("Requesting login options…");
    const options = await api("/login/options", { username });
    status("Press the BOOT button on your ESP32-S3 token now…", "action");
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
$("login").addEventListener("click", login);
$("username").addEventListener("keydown", (e) => { if (e.key === "Enter") login(); });
$("origin").textContent = location.origin;
const problem = supportCheck();
if (problem) status(problem, "error");
fetch("/me", { credentials: "same-origin" }).then((r) => { if (r.ok) $("dash").hidden = false; });
