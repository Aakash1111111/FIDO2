// WebAuthn helpers: base64url <-> ArrayBuffer, JSON <-> browser credential objects.
// Written without PublicKeyCredential.parseCreationOptionsFromJSON so older
// mobile browsers work too.

export function b64uEncode(buf) {
  const bytes = new Uint8Array(buf);
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64uDecode(str) {
  const s = str.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((str.length + 3) % 4);
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

const descriptors = (list) => (list || []).map((c) => ({ ...c, id: b64uDecode(c.id) }));

export function creationOptionsFromJSON(o) {
  return { ...o, challenge: b64uDecode(o.challenge), user: { ...o.user, id: b64uDecode(o.user.id) },
           excludeCredentials: descriptors(o.excludeCredentials) };
}

export function requestOptionsFromJSON(o) {
  return { ...o, challenge: b64uDecode(o.challenge), allowCredentials: descriptors(o.allowCredentials) };
}

export function attestationToJSON(cred) {
  const r = cred.response;
  return {
    id: cred.id, rawId: b64uEncode(cred.rawId), type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment || null,
    clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
    response: {
      clientDataJSON: b64uEncode(r.clientDataJSON),
      attestationObject: b64uEncode(r.attestationObject),
      transports: typeof r.getTransports === "function" ? r.getTransports() : undefined,
    },
  };
}

export function assertionToJSON(cred) {
  const r = cred.response;
  return {
    id: cred.id, rawId: b64uEncode(cred.rawId), type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment || null,
    clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
    response: {
      clientDataJSON: b64uEncode(r.clientDataJSON),
      authenticatorData: b64uEncode(r.authenticatorData),
      signature: b64uEncode(r.signature),
      userHandle: r.userHandle ? b64uEncode(r.userHandle) : null,
    },
  };
}

export async function api(path, body, method = "POST", headers = {}) {
  const res = await fetch(path, {
    method, credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data = {};
  try { data = await res.json(); } catch (_) { /* non-JSON */ }
  if (!res.ok || data.ok === false) {
    const err = new Error(data.reason || `HTTP ${res.status}`);
    err.reason = data.reason || `HTTP_${res.status}`;
    throw err;
  }
  return data;
}

export function explain(err) {
  const reasons = {
    NotAllowedError: "Cancelled or timed out. Did you press the BOOT button on the token within 30 s?",
    InvalidStateError: "This token is already registered for this account.",
    SecurityError: "Origin / RP ID mismatch. Open the site exactly at the configured address (e.g. http://localhost:8000).",
    NotSupportedError: "This browser or device does not support the requested key type.",
    AbortError: "The operation was aborted.",
    USER_EXISTS_AUTH_REQUIRED: "That username already has a key. Log in first to add another key.",
    UNKNOWN_USER: "No account with a registered key for that username.",
    INVALID_USERNAME: "Username: 3-32 characters, letters, digits, . _ -",
  };
  return reasons[err.name] || reasons[err.reason] || `${err.name && err.name !== "Error" ? err.name + ": " : ""}${err.reason || err.message}`;
}

export function supportCheck() {
  if (!window.isSecureContext) return "This page is not a secure context. Use http://localhost or HTTPS.";
  if (!window.PublicKeyCredential) return "This browser does not support WebAuthn.";
  return null;
}
