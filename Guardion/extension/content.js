/**
 * Guardion — Content Script
 * Injected into AI chat sites (ChatGPT, Claude, Gemini).
 * Intercepts prompt submission, analyses via Guardion backend,
 * and shows brand-themed banners with AI fix placeholders.
 */

(function () {
  "use strict";

  const SITE = window.location.hostname;
  let isProcessing = false;
  let aiFix = true;

  // Load AI-fix preference
  chrome.storage.local.get("aiFix", (d) => {
    aiFix = d.aiFix !== false;
  });
  chrome.storage.onChanged.addListener((changes) => {
    if (changes.aiFix) aiFix = changes.aiFix.newValue;
  });

  console.log(`[Guardion] Content script loaded on ${SITE}`);

  // ──────── Placeholder map per category ────────
  const PLACEHOLDERS = {
    api_key: "[API_KEY_REDACTED]",
    password: "[PASSWORD_REMOVED]",
    secret: "[SECRET_REDACTED]",
    token: "[TOKEN_REMOVED]",
    credit_card: "[CARD_NUMBER_REDACTED]",
    ssn: "[SSN_REDACTED]",
    email: "[EMAIL_REDACTED]",
    phone: "[PHONE_REDACTED]",
    ip_address: "[IP_ADDRESS_REDACTED]",
    private_key: "[PRIVATE_KEY_REDACTED]",
    aws_key: "[AWS_KEY_REDACTED]",
    database_url: "[DATABASE_URL_REDACTED]",
    jwt: "[JWT_REDACTED]",
    address: "[ADDRESS_REDACTED]",
    name: "[NAME_REDACTED]",
    medical: "[MEDICAL_INFO_REDACTED]",
    financial: "[FINANCIAL_DATA_REDACTED]",
    credentials: "[CREDENTIALS_REDACTED]",
    internal_url: "[INTERNAL_URL_REDACTED]",
    code_vulnerability: "[VULNERABLE_CODE_REDACTED]",
    harmful_instruction: "[HARMFUL_CONTENT_REMOVED]",
    jailbreak: "[PROMPT_SANITIZED]",
  };

  // ──────── SVG icons (inline, no external deps) ────────
  const SHIELD_SVG = `<svg class="guardion-shield-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`;
  const SPARKLE_SVG = `<svg class="guardion-fix-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2l2.4 7.2L22 12l-7.6 2.8L12 22l-2.4-7.2L2 12l7.6-2.8z"/></svg>`;

  // ──────── Prompt Interception ────────
  document.addEventListener("keydown", handleKeyDown, true);
  document.addEventListener("click", handleClick, true);

  // ChatGPT may submit via form — intercept that too
  document.addEventListener("submit", handleSubmit, true);

  // Also intercept beforeinput to catch Enter in contenteditable
  document.addEventListener("beforeinput", handleBeforeInput, true);

  function handleKeyDown(event) {
    if (event.key === "Enter" && !event.shiftKey && !isProcessing) {
      const el = event.target;
      // Only intercept in chat input areas
      if (isChatInput(el)) {
        const promptText = getPromptText();
        if (promptText && promptText.trim().length > 0) {
          submitPrompt(promptText, event);
        }
      }
    }
  }

  function handleBeforeInput(event) {
    if (isProcessing) return;
    if (event.inputType === "insertParagraph" || event.inputType === "insertLineBreak") {
      const el = event.target;
      if (isChatInput(el)) {
        const promptText = getPromptText();
        if (promptText && promptText.trim().length > 0) {
          submitPrompt(promptText, event);
        }
      }
    }
  }

  function handleSubmit(event) {
    if (isProcessing) return;
    const form = event.target;
    if (form && form.tagName === "FORM") {
      const promptText = getPromptText();
      if (promptText && promptText.trim().length > 0) {
        submitPrompt(promptText, event);
      }
    }
  }

  function handleClick(event) {
    if (isProcessing) return;
    const button = event.target.closest("button");
    if (button && isSendButton(button)) {
      const promptText = getPromptText();
      if (promptText && promptText.trim().length > 0) {
        submitPrompt(promptText, event);
      }
    }
  }

  function isChatInput(el) {
    if (!el) return false;
    const id = el.id || "";
    const role = el.getAttribute("role") || "";
    return (
      id === "prompt-textarea" ||
      el.matches?.("#prompt-textarea, .ProseMirror, .ql-editor") ||
      (el.isContentEditable && role === "textbox") ||
      el.tagName === "TEXTAREA" ||
      el.closest?.("#prompt-textarea, [contenteditable='true']")
    );
  }

  function isSendButton(button) {
    const ariaLabel = (button.getAttribute("aria-label") || "").toLowerCase();
    const testId = button.getAttribute("data-testid") || "";
    return (
      ariaLabel.includes("send") ||
      ariaLabel.includes("submit") ||
      testId.includes("send") ||
      testId.includes("composer") ||
      button.querySelector('svg[data-icon="send"]') !== null ||
      button.querySelector("path[d*='M15.192']") !== null ||
      button.classList.toString().toLowerCase().includes("send")
    );
  }

  function getPromptText() {
    // ChatGPT: div#prompt-textarea[contenteditable] with <p> children
    const chatgptInput =
      document.querySelector('div#prompt-textarea[contenteditable="true"]') ||
      document.querySelector("#prompt-textarea") ||
      document.querySelector("textarea[data-id='root']");
    // Claude: ProseMirror contenteditable
    const claudeInput =
      document.querySelector('div[contenteditable="true"].ProseMirror') ||
      document.querySelector('fieldset div[contenteditable="true"]');
    // Gemini: Quill editor
    const geminiInput =
      document.querySelector(".ql-editor") ||
      document.querySelector('div[contenteditable="true"][aria-label]');
    // Generic fallback
    const genericInput =
      document.querySelector("textarea") ||
      document.querySelector('div[contenteditable="true"]');

    const input = chatgptInput || claudeInput || geminiInput || genericInput;
    if (!input) return "";

    // For contenteditable divs, get text from <p> children or innerText
    if (input.isContentEditable) {
      const paragraphs = input.querySelectorAll("p");
      if (paragraphs.length > 0) {
        return Array.from(paragraphs).map((p) => p.textContent).join("\n").trim();
      }
      return input.innerText?.trim() || input.textContent?.trim() || "";
    }
    return input.value || input.innerText || input.textContent || "";
  }

  // ──────── Build safe placeholder prompt ────────
  function buildSafePrompt(originalText, categories, sanitizedPrompt) {
    // Prefer backend-provided sanitized prompt
    if (sanitizedPrompt) return sanitizedPrompt;

    let safe = originalText;
    for (const cat of categories) {
      const placeholder = PLACEHOLDERS[cat] || `[${cat.toUpperCase()}_REDACTED]`;
      // Simple pattern: replace obvious matches with placeholder
      const patterns = getCategoryPatterns(cat);
      for (const p of patterns) {
        safe = safe.replace(p, placeholder);
      }
    }
    return safe;
  }

  // ──────── Shared submit decision (fast path vs full verdict) ────────
  function submitPrompt(promptText, event) {
    if (localPreScreen(promptText)) {
      // Nothing suspicious locally → let the natural submit proceed instantly.
      fastPathAllow(promptText);
      return;
    }
    event.preventDefault();
    event.stopImmediatePropagation();
    processPrompt(promptText, event);
  }

  // ──────── Instant local pre-screen ────────
  // Conservative: ANY hit (regex or keyword) routes to the full backend
  // verdict, so this can only fast-track genuinely clean, short prompts.
  const RISKY_KEYWORDS = [
    // secrets / credentials
    "api_key", "apikey", "api key", "secret", "password", "passwd", "credential",
    "token", "private key", "-----begin", "ghp_", "sk-", "mongodb://", "postgres://",
    "mysql://", "redis://", ".env", ".pem", "ssh-rsa", "akia",
    // pii / financial
    "ssn", "social security", "credit card", "debit card", "card number", "cvv",
    "date of birth", "passport", "salary", "bank account", "routing number",
    "iban", "medical", "diagnos", "prescription",
    // injection / exfiltration
    "ignore previous", "ignore all", "disregard", "system prompt", "reveal",
    "jailbreak", "developer mode", "act as", "pretend", "roleplay", "override",
    "bypass", "exploit", "malware", "ransomware", "phishing", "keylogger",
    "exfiltrat", "drop table",
  ];

  function localPreScreen(text) {
    if (text.length > 500) return false;
    const lower = text.toLowerCase();
    for (const kw of RISKY_KEYWORDS) {
      if (lower.includes(kw)) return false;
    }
    for (const cat of Object.keys(PATTERN_MAP)) {
      for (const re of PATTERN_MAP[cat]) {
        re.lastIndex = 0; // /g regexes keep state between .test() calls
        if (re.test(text)) return false;
      }
    }
    return true;
  }

  /**
   * Fast path: local scan is clean, so release the prompt instantly instead of
   * holding it for a network round-trip. The backend analysis still runs in the
   * background for audit logging — and if it disagrees, warn the user post-send.
   */
  function fastPathAllow(promptText) {
    isProcessing = true; // suppress duplicate keydown/beforeinput handling
    setTimeout(() => {
      isProcessing = false;
    }, 150);

    if (!chrome.runtime?.id) return;

    chrome.runtime
      .sendMessage({ action: "analyzePrompt", prompt: promptText, source: SITE })
      .then((resp) => {
        if (resp && !resp.error && (resp.decision === "block" || resp.decision === "warn")) {
          showBanner({
            type: "warn",
            title: "Flagged after send",
            message: "Guardion detected possible sensitive data in the message you just sent.",
            risk: resp.risk_score,
            categories: resp.detected_categories || [],
            sanitizedPrompt: resp.sanitized_prompt,
            originalText: promptText,
            ml: resp.ml_prediction,
          });
        }
      })
      .catch(() => {});
  }

  function getCategoryPatterns(category) {
    const map = PATTERN_MAP;
    return map[category] || [];
  }

  const PATTERN_MAP = {
      api_key: [/\b[A-Za-z0-9_\-]{20,}\b/g],
      password: [/(?:password|passwd|pwd)\s*[:=]\s*\S+/gi],
      email: [/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g],
      phone: [/\b\d{3}[\s\-.]?\d{3}[\s\-.]?\d{4}\b/g],
      credit_card: [/\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b/g],
      ssn: [/\b\d{3}[\s\-]?\d{2}[\s\-]?\d{4}\b/g],
      ip_address: [/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g],
      token: [/\b(?:eyJ|ghp_|gho_|sk-)[A-Za-z0-9_\-\.]+/g],
      private_key: [/-----BEGIN\s[\w\s]+KEY-----[\s\S]*?-----END\s[\w\s]+KEY-----/g],
      aws_key: [/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g],
      jwt: [/eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+/g],
      database_url: [/(?:mongodb|postgres|mysql|redis):\/\/\S+/gi],
      internal_url: [/https?:\/\/(?:localhost|127\.0\.0\.1|10\.\d+|192\.168)\S*/g],
    };

  // ──────── Escape HTML for safe rendering ────────
  function esc(str) {
    const d = document.createElement("div");
    d.appendChild(document.createTextNode(str));
    return d.innerHTML;
  }

  // ──────── Analysis Pipeline ────────
  async function processPrompt(promptText, originalEvent) {
    // Guard: if the extension was reloaded, the old content script context
    // is orphaned — chrome.runtime.id becomes undefined.
    if (!chrome.runtime?.id) {
      console.warn("[Guardion] Extension context invalidated — allowing prompt.");
      isProcessing = false;
      return;
    }

    isProcessing = true;
    showBanner({ message: "Scanning prompt for sensitive data…", type: "info" });

    try {
      const response = await chrome.runtime.sendMessage({
        action: "analyzePrompt",
        prompt: promptText,
        source: SITE,
      });

      if (!response) {
        allowPrompt(originalEvent);
        return;
      }

      const cats = response.detected_categories || [];
      const risk = response.risk_score || 0;

      switch (response.decision) {
        case "block":
          showBanner({
            type: "block",
            title: "Blocked",
            message: "Sensitive data detected — prompt was not sent.",
            risk,
            categories: cats,
            sanitizedPrompt: response.sanitized_prompt,
            originalText: promptText,
            ml: response.ml_prediction,
          });
          break;

        case "warn":
          showBanner({
            type: "warn",
            title: "Warning",
            message: "Possible sensitive data detected.",
            risk,
            categories: cats,
            sanitizedPrompt: response.sanitized_prompt,
            originalText: promptText,
            onProceed: () => allowPrompt(originalEvent),
            ml: response.ml_prediction,
          });
          break;

        case "allow":
        default:
          removeBanner();
          allowPrompt(originalEvent);
          break;
      }
    } catch (error) {
      console.error("[Guardion] Error:", error);
      allowPrompt(originalEvent);
    } finally {
      isProcessing = false;
    }
  }

  function allowPrompt(originalEvent) {
    isProcessing = true;

    const sendBtn =
      document.querySelector('button[data-testid="send-button"]') ||
      document.querySelector('button[data-testid="composer-send-button"]') ||
      document.querySelector('button[aria-label="Send prompt"]') ||
      document.querySelector('button[aria-label="Send"]') ||
      document.querySelector('button[aria-label="Send message"]') ||
      document.querySelector('form button[type="submit"]') ||
      document.querySelector("button.send-button");

    if (sendBtn) {
      sendBtn.click();
    } else {
      const input =
        document.querySelector("textarea") ||
        document.querySelector('div[contenteditable="true"]');
      if (input) {
        input.focus();
        input.dispatchEvent(
          new KeyboardEvent("keydown", {
            key: "Enter",
            code: "Enter",
            keyCode: 13,
            which: 13,
            bubbles: true,
          })
        );
      }
    }

    setTimeout(() => {
      isProcessing = false;
    }, 500);
  }

  // ──────── UI Banners ────────
  function showBanner(opts) {
    removeBanner();

    if (typeof opts === "string") {
      opts = { message: opts, type: "info" };
    }

    const {
      type,
      title,
      message,
      risk,
      categories,
      sanitizedPrompt,
      originalText,
      onProceed,
      ml,
    } = opts;

    const banner = document.createElement("div");
    banner.id = "guardion-banner";
    banner.className = `guardion-banner guardion-${type}`;

    // Risk badge
    const riskPct = risk != null ? (risk * 100).toFixed(0) : null;
    const riskBadge =
      riskPct != null
        ? `<span class="guardion-risk-badge">${riskPct}% risk</span>`
        : "";

    // ML model verdict chip (precision detail: which class + confidence)
    const mlExcluded = ml == null || ["benign", "error", "unknown"].includes(ml.prediction);
    const mlChip =
      !mlExcluded && ml.prediction
        ? `<span class="guardion-ml-chip">ML: ${esc(ml.prediction)}${
            ml.confidence != null ? ` ${(ml.confidence * 100).toFixed(0)}%` : ""
          }</span>`
        : "";

    // Category tags
    const catTags =
      categories && categories.length
        ? `<div class="guardion-categories">${categories.map((c) => `<span class="guardion-cat-tag">${esc(c)}</span>`).join("")}</div>`
        : "";

    // Title label
    const titleLabel = title
      ? `<strong>${esc(title)}</strong> — `
      : "";

    banner.innerHTML = `
      <div class="guardion-banner-content">
        ${SHIELD_SVG}
        <div class="guardion-message">
          ${titleLabel}${esc(message)}${riskBadge}${mlChip}
          ${catTags}
        </div>
        <div class="guardion-actions">
          ${onProceed ? '<button class="guardion-btn guardion-btn-proceed">Send Anyway</button>' : ""}
          ${sanitizedPrompt ? '<button class="guardion-btn guardion-btn-sanitize">Use Sanitized</button>' : ""}
          <button class="guardion-btn guardion-btn-dismiss">Dismiss</button>
        </div>
      </div>
    `;

    document.body.prepend(banner);

    // Listeners
    banner.querySelector(".guardion-btn-dismiss")?.addEventListener("click", removeBanner);

    if (onProceed) {
      banner.querySelector(".guardion-btn-proceed")?.addEventListener("click", () => {
        removeBanner();
        onProceed();
      });
    }

    if (sanitizedPrompt) {
      banner.querySelector(".guardion-btn-sanitize")?.addEventListener("click", () => {
        replaceInput(sanitizedPrompt);
        removeBanner();
      });
    }

    // Show AI fix suggestion panel if enabled
    if (aiFix && (type === "block" || type === "warn") && categories && categories.length) {
      showFixPanel(banner, originalText, categories, sanitizedPrompt);
    }

    if (type === "info") setTimeout(removeBanner, 5000);
    if (type === "block" || type === "warn") setTimeout(removeBanner, 60000);
  }

  // ──────── AI Fix Suggestion Panel ────────
  function showFixPanel(banner, originalText, categories, sanitizedPrompt) {
    const safePrompt = buildSafePrompt(originalText || "", categories, sanitizedPrompt);

    const panel = document.createElement("div");
    panel.className = "guardion-fix-panel";
    panel.innerHTML = `
      <div class="guardion-fix-header">
        ${SPARKLE_SVG}
        <span class="guardion-fix-title">AI Fix Suggestion</span>
      </div>
      <div class="guardion-fix-body">
        <span class="guardion-fix-label">Safe version with placeholders</span>
        <div class="guardion-fix-prompt">${esc(safePrompt)}</div>
      </div>
      <div class="guardion-fix-actions">
        <button class="guardion-btn guardion-btn-fix">&#10003; Use Safe Version</button>
        <button class="guardion-btn guardion-btn-dismiss">Ignore</button>
      </div>
    `;

    banner.appendChild(panel);

    panel.querySelector(".guardion-btn-fix")?.addEventListener("click", () => {
      replaceInput(safePrompt);
      removeBanner();
    });

    panel.querySelector(".guardion-btn-dismiss")?.addEventListener("click", () => {
      panel.remove();
    });
  }

  // ──────── Replace chat input text ────────
  function replaceInput(text) {
    const input =
      document.querySelector('div#prompt-textarea[contenteditable="true"]') ||
      document.querySelector("#prompt-textarea") ||
      document.querySelector('div[contenteditable="true"]') ||
      document.querySelector("textarea");

    if (!input) return;

    if (input.tagName === "TEXTAREA" || input.tagName === "INPUT") {
      input.value = text;
    } else {
      // ChatGPT uses <p> inside contenteditable — set via innerHTML for proper rendering
      input.innerHTML = `<p>${text.replace(/\n/g, "</p><p>")}</p>`;
    }
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.focus();
  }

  function removeBanner() {
    const banner = document.getElementById("guardion-banner");
    if (banner) {
      banner.classList.add("guardion-closing");
      setTimeout(() => banner.remove(), 250);
    }
  }
})();
