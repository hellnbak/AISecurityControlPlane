const SECUREAI_GATEWAY = "http://127.0.0.1:8787";
const POLICY_URL = `${SECUREAI_GATEWAY}/v1/policy/evaluate`;
const WEB_EVALUATE_URL = `${SECUREAI_GATEWAY}/v1/web/evaluate`;
const CONFIG_URL = `${SECUREAI_GATEWAY}/v1/extension/config`;

const LOCAL_PATTERNS = [
  { type: "aws_access_key_id", re: /\b(A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}\b/ },
  { type: "private_key", re: /-----BEGIN (RSA |EC |OPENSSH |DSA |)?PRIVATE KEY-----/ },
  { type: "github_token", re: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b/ },
  { type: "slack_token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { type: "jwt", re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
  { type: "ssn", re: /\b\d{3}-\d{2}-\d{4}\b/ },
  { type: "credit_card", re: /\b(?:\d[ -]*?){13,19}\b/ }
];

const SENSITIVE_FILE_SUFFIXES = [".pem", ".key", ".p12", ".pfx", ".env", ".tfstate", ".sqlite", ".db"];
const SENSITIVE_FILE_NAMES = ["id_rsa", "id_ed25519", "credentials", "credentials.csv", "aws_credentials", "secrets.yaml", "secrets.yml", "terraform.tfstate"];

let lastEditableText = "";
let gatewayConfig = null;
let secureaiIdentity = {
  user: "browser-user",
  device_id: "browser-device",
  device_token: "",
  groups: ""
};

function showBanner(message, level = "warn") {
  let existing = document.getElementById("secureai-banner");
  if (existing) existing.remove();

  const banner = document.createElement("div");
  banner.id = "secureai-banner";
  banner.textContent = message;
  banner.style.position = "fixed";
  banner.style.left = "16px";
  banner.style.right = "16px";
  banner.style.bottom = "16px";
  banner.style.zIndex = "2147483647";
  banner.style.padding = "12px 14px";
  banner.style.borderRadius = "10px";
  banner.style.fontSize = "14px";
  banner.style.fontFamily = "system-ui, -apple-system, BlinkMacSystemFont, sans-serif";
  banner.style.boxShadow = "0 8px 30px rgba(0,0,0,0.25)";
  banner.style.background = level === "block" ? "#4a0b0b" : "#3b2f00";
  banner.style.color = "white";
  banner.style.whiteSpace = "pre-wrap";
  document.documentElement.appendChild(banner);
  setTimeout(() => banner.remove(), 7000);
}

function localScan(text) {
  const findings = LOCAL_PATTERNS.filter((p) => p.re.test(text || "")).map((p) => ({
    type: p.type,
    severity: "local",
    description: `Local ${p.type} pattern matched`
  }));

  const lower = String(text || "").toLowerCase();
  if (/ignore (all )?(previous|prior|above) instructions/i.test(lower) || /reveal (your )?(system|developer) prompt/i.test(lower)) {
    findings.push({ type: "prompt_injection_or_jailbreak", severity: "local", description: "Local jailbreak pattern matched" });
  }
  return findings;
}

function fileNameFindings(fileNames) {
  const findings = [];
  for (const rawName of fileNames || []) {
    const name = String(rawName || "").trim();
    const lower = name.toLowerCase();
    if (!lower) continue;
    if (SENSITIVE_FILE_NAMES.includes(lower) || SENSITIVE_FILE_SUFFIXES.some((suffix) => lower.endsWith(suffix))) {
      findings.push({ type: "sensitive_file_upload", severity: "local", description: `Sensitive-looking upload filename: ${name}` });
    }
  }
  return findings;
}

async function postJson(url, payload) {
  const headers = {
    "content-type": "application/json",
    "x-secureai-user": secureaiIdentity.user || "browser-user",
    "x-secureai-app": "claude.ai",
    "x-secureai-device": secureaiIdentity.device_id || "browser-device",
    "x-secureai-groups": secureaiIdentity.groups || ""
  };
  if (secureaiIdentity.device_token) headers["x-secureai-device-token"] = secureaiIdentity.device_token;
  const resp = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify(payload)
  });
  if (!resp.ok) throw new Error(`gateway ${resp.status}`);
  return await resp.json();
}

async function evaluateWebEvent(payload) {
  try {
    return await postJson(WEB_EVALUATE_URL, payload);
  } catch (e) {
    const text = payload.text || payload.body || payload.request_body || "";
    const findings = localScan(text).concat(fileNameFindings(payload.file_names || []));
    if (findings.length) {
      return {
        decision: "block",
        reasons: ["Local sensitive-data pattern matched; gateway unavailable"],
        findings
      };
    }
    return { decision: "allow", reasons: ["Gateway unavailable; no local finding"], findings: [] };
  }
}

function summarizeFindings(findings) {
  return (findings || []).map((f) => f.type || f).filter(Boolean).join(", ") || "policy violation";
}

async function enforceText(event, text, eventType) {
  if (!text || String(text).length < 8) return true;
  const result = await evaluateWebEvent({
    event_type: eventType,
    url: location.href,
    method: "DOM",
    text: String(text).slice(0, 250000)
  });
  const findings = summarizeFindings(result.findings);

  if (result.decision === "block") {
    if (event?.preventDefault) event.preventDefault();
    if (event?.stopImmediatePropagation) event.stopImmediatePropagation();
    showBanner(`AISecurityControlPlane blocked Claude.ai ${eventType}. Findings: ${findings}`, "block");
    return false;
  }
  if ((result.findings || []).length > 0 || result.decision === "allow_with_warning") {
    showBanner(`AISecurityControlPlane warning for Claude.ai ${eventType}: ${findings}`, "warn");
  }
  return true;
}

function isEditable(target) {
  return !!(target && (target.isContentEditable || ["TEXTAREA", "INPUT"].includes(target.tagName)));
}

function getEditableText(target) {
  if (!target) return "";
  if (target.isContentEditable) return target.innerText || target.textContent || "";
  if (["TEXTAREA", "INPUT"].includes(target.tagName)) return target.value || "";
  return "";
}

async function handlePaste(event) {
  const text = event.clipboardData?.getData("text") || "";
  await enforceText(event, text, "paste");
}

async function handleDrop(event) {
  const text = event.dataTransfer?.getData("text") || "";
  const fileNames = Array.from(event.dataTransfer?.files || []).map((f) => f.name);
  const result = await evaluateWebEvent({ event_type: "drop", url: location.href, method: "DOM", text, file_names: fileNames });
  if (result.decision === "block") {
    event.preventDefault();
    event.stopImmediatePropagation();
    showBanner(`AISecurityControlPlane blocked Claude.ai drop/upload. Findings: ${summarizeFindings(result.findings)}`, "block");
  }
}

async function handleFileChange(event) {
  const fileNames = Array.from(event.target?.files || []).map((f) => f.name);
  if (!fileNames.length) return;
  const result = await evaluateWebEvent({ event_type: "file_change", url: location.href, method: "DOM", file_names: fileNames });
  if (result.decision === "block") {
    event.preventDefault();
    event.stopImmediatePropagation();
    try { event.target.value = ""; } catch (_) {}
    showBanner(`AISecurityControlPlane blocked Claude.ai file upload. Findings: ${summarizeFindings(result.findings)}`, "block");
  }
}

async function handlePossibleSubmit(event) {
  const target = event.target;
  const text = getEditableText(target) || lastEditableText;
  await enforceText(event, text, "submit_attempt");
}

function recordEditableInput(event) {
  if (isEditable(event.target)) {
    lastEditableText = getEditableText(event.target).slice(-250000);
  }
}

function injectPageHook() {
  const script = document.createElement("script");
  script.src = chrome.runtime.getURL("page_hook.js");
  script.onload = () => script.remove();
  (document.documentElement || document.head || document.body).appendChild(script);
}

window.addEventListener("message", async (event) => {
  if (event.source !== window) return;
  const msg = event.data || {};
  if (msg.type !== "SECUREAI_WEB_REQUEST_EVALUATE") return;

  const result = await evaluateWebEvent(msg.payload || {});
  if (result.decision === "block") {
    showBanner(`AISecurityControlPlane blocked Claude.ai web request. Findings: ${summarizeFindings(result.findings)}`, "block");
  } else if ((result.findings || []).length > 0 || result.decision === "allow_with_warning") {
    showBanner(`AISecurityControlPlane warning on Claude.ai web request: ${summarizeFindings(result.findings)}`, "warn");
  }

  window.postMessage({
    type: "SECUREAI_WEB_REQUEST_DECISION",
    id: msg.id,
    result
  }, "*");
});

async function loadConfig() {
  try {
    const managed = await chrome.storage.managed.get(["secureai_user", "secureai_device_id", "secureai_device_token", "secureai_groups"]);
    const sync = await chrome.storage.sync.get(["secureai_user", "secureai_device_id", "secureai_device_token", "secureai_groups"]);
    const cfg = Object.assign({}, sync || {}, managed || {});
    secureaiIdentity = {
      user: cfg.secureai_user || secureaiIdentity.user,
      device_id: cfg.secureai_device_id || secureaiIdentity.device_id,
      device_token: cfg.secureai_device_token || secureaiIdentity.device_token,
      groups: cfg.secureai_groups || secureaiIdentity.groups
    };
  } catch (_) {
    // Managed storage may not exist in local dev. Keep defaults.
  }
  try {
    const resp = await fetch(CONFIG_URL);
    if (resp.ok) gatewayConfig = await resp.json();
  } catch (_) {
    gatewayConfig = null;
  }
}

// DOM-level controls.
document.addEventListener("paste", (event) => {
  if (isEditable(event.target)) handlePaste(event);
}, true);

document.addEventListener("input", recordEditableInput, true);

document.addEventListener("drop", handleDrop, true);

document.addEventListener("change", (event) => {
  if (event.target?.tagName === "INPUT" && event.target?.type === "file") handleFileChange(event);
}, true);

document.addEventListener("submit", handlePossibleSubmit, true);

document.addEventListener("keydown", (event) => {
  const enterSubmit = event.key === "Enter" && (event.metaKey || event.ctrlKey);
  if (enterSubmit && isEditable(event.target)) handlePossibleSubmit(event);
}, true);

loadConfig();
injectPageHook();
