(() => {
  if (window.__secureAIClaudeHookInstalled) return;
  window.__secureAIClaudeHookInstalled = true;

  const MAX_BODY_CHARS = 250000;
  let nextId = 1;

  function shouldInspectUrl(url) {
    try {
      const u = new URL(url, location.href);
      if (u.hostname === "127.0.0.1" || u.hostname === "localhost") return false;
      return u.hostname === "claude.ai" || u.hostname.endsWith(".claude.ai");
    } catch (_) {
      return false;
    }
  }

  function likelyPromptCarrier(text) {
    if (!text) return false;
    const s = String(text);
    if (s.length > 80) return true;
    return /prompt|message|content|text|attachments|files|completion|conversation/i.test(s);
  }

  function requestDecision(payload, timeoutMs = 1800) {
    return new Promise((resolve) => {
      const id = `secureai-${Date.now()}-${nextId++}`;
      const timeout = setTimeout(() => {
        cleanup();
        resolve({ decision: "allow", reasons: ["AISecurityControlPlane extension timeout"], findings: [] });
      }, timeoutMs);

      function cleanup() {
        clearTimeout(timeout);
        window.removeEventListener("message", onMessage);
      }

      function onMessage(event) {
        if (event.source !== window) return;
        const msg = event.data || {};
        if (msg.type === "SECUREAI_WEB_REQUEST_DECISION" && msg.id === id) {
          cleanup();
          resolve(msg.result || { decision: "allow", reasons: [], findings: [] });
        }
      }

      window.addEventListener("message", onMessage);
      window.postMessage({ type: "SECUREAI_WEB_REQUEST_EVALUATE", id, payload }, "*");
    });
  }

  function blockedError(result) {
    const findings = (result.findings || []).map((f) => f.type || f).join(", ") || "policy violation";
    return new DOMException(`AISecurityControlPlane blocked Claude.ai web request: ${findings}`, "AbortError");
  }

  async function bodyToText(body) {
    if (body == null) return "";
    if (typeof body === "string") return body.slice(0, MAX_BODY_CHARS);
    if (body instanceof URLSearchParams) return body.toString().slice(0, MAX_BODY_CHARS);
    if (body instanceof FormData) {
      const parts = [];
      for (const [key, value] of body.entries()) {
        if (typeof value === "string") {
          parts.push(`${key}=${value}`);
        } else if (value && typeof value === "object") {
          parts.push(`${key}=FILE:${value.name || "unnamed"}`);
        }
      }
      return parts.join("\n").slice(0, MAX_BODY_CHARS);
    }
    if (body instanceof Blob) {
      try { return (await body.text()).slice(0, MAX_BODY_CHARS); } catch (_) { return ""; }
    }
    if (body instanceof ArrayBuffer) return "[arraybuffer body]";
    try { return JSON.stringify(body).slice(0, MAX_BODY_CHARS); } catch (_) { return String(body).slice(0, MAX_BODY_CHARS); }
  }

  async function requestToPayload(req, source) {
    let bodyText = "";
    try {
      if (req.method && !["GET", "HEAD", "OPTIONS"].includes(req.method.toUpperCase())) {
        bodyText = (await req.clone().text()).slice(0, MAX_BODY_CHARS);
      }
    } catch (_) {
      bodyText = "";
    }
    return {
      event_type: source,
      url: req.url,
      method: req.method,
      request_body: likelyPromptCarrier(bodyText) ? bodyText : bodyText.slice(0, 5000)
    };
  }

  const originalFetch = window.fetch;
  window.fetch = async function secureAIFetch(input, init) {
    const req = new Request(input, init);
    if (!shouldInspectUrl(req.url)) return originalFetch.apply(this, arguments);

    const payload = await requestToPayload(req, "fetch");
    if (payload.request_body) {
      const result = await requestDecision(payload);
      if (result.decision === "block") throw blockedError(result);
      if (result.rewrite_request_body && req.method && !["GET", "HEAD", "OPTIONS"].includes(req.method.toUpperCase())) {
        const headers = new Headers(req.headers);
        if (!headers.has("content-type")) headers.set("content-type", "application/json");
        const rewrittenReq = new Request(req.url, {
          method: req.method,
          headers,
          body: result.rewrite_request_body,
          mode: req.mode,
          credentials: req.credentials,
          cache: req.cache,
          redirect: req.redirect,
          referrer: req.referrer,
          referrerPolicy: req.referrerPolicy,
          integrity: req.integrity,
          keepalive: req.keepalive,
          signal: req.signal
        });
        return originalFetch.call(this, rewrittenReq);
      }
    }
    return originalFetch.call(this, req);
  };

  const originalOpen = XMLHttpRequest.prototype.open;
  const originalSend = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function secureAIXhrOpen(method, url) {
    this.__secureAI = { method: method || "GET", url: new URL(url, location.href).href };
    return originalOpen.apply(this, arguments);
  };

  XMLHttpRequest.prototype.send = function secureAIXhrSend(body) {
    const meta = this.__secureAI || {};
    if (!shouldInspectUrl(meta.url)) return originalSend.apply(this, arguments);

    const xhr = this;
    const args = arguments;
    bodyToText(body).then((bodyText) => {
      if (!bodyText) return originalSend.apply(xhr, args);
      return requestDecision({ event_type: "xhr", url: meta.url, method: meta.method, request_body: bodyText }).then((result) => {
        if (result.decision === "block") {
          try { xhr.dispatchEvent(new Event("abort")); } catch (_) {}
          return;
        }
        if (result.rewrite_request_body) {
          return originalSend.call(xhr, result.rewrite_request_body);
        }
        return originalSend.apply(xhr, args);
      });
    }).catch(() => originalSend.apply(xhr, args));
  };

  const originalBeacon = navigator.sendBeacon?.bind(navigator);
  if (originalBeacon) {
    navigator.sendBeacon = function secureAIBeacon(url, data) {
      if (!shouldInspectUrl(url)) return originalBeacon(url, data);
      bodyToText(data).then((bodyText) => {
        if (!bodyText) return;
        requestDecision({ event_type: "sendBeacon", url: new URL(url, location.href).href, method: "POST", request_body: bodyText });
      });
      // Beacon API is synchronous. Do not break telemetry paths; audit only in this MVP.
      return originalBeacon(url, data);
    };
  }
})();
