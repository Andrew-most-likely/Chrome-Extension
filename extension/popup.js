// ============================================================
// POPUP LOGIC
// ============================================================

const THREAT_SHORT = {
  MALWARE:                          "Malware",
  SOCIAL_ENGINEERING:               "Phishing",
  UNWANTED_SOFTWARE:                "Unwanted SW",
  POTENTIALLY_HARMFUL_APPLICATION:  "Harmful App",
  PAYMENT_REDIRECT:                 "Pay Redirect",
  HEURISTIC:                        "Susp. URL",
  FORM_HIJACK:                      "Form Hijack",
  UNKNOWN_THREAT:                   "Threat",
};

function timeUntil(timestamp) {
  if (!timestamp) return "";
  const diff = timestamp - Date.now();
  if (diff <= 0) return "expired";
  const mins  = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  if (mins < 60) return `exp ${mins}m`;
  return `exp ${hours}h`;
}

function timeAgo(timestamp) {
  const diff  = Date.now() - timestamp;
  const mins  = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  const days  = Math.floor(diff / 86400000);
  if (mins < 1)   return "just now";
  if (mins < 60)  return `${mins}m ago`;
  if (hours < 24) return `${hours}h ago`;
  return `${days}d ago`;
}

function render(data) {
  const { tally = {}, history = [], bypassed = [], whitelist = [] } = data;

  // ── Tally ──
  const set = (id, n) => {
    const el = document.getElementById(id);
    el.textContent = n || 0;
    el.className = "tally-value" + (!n ? " zero" : "");
  };
  set("tally-total",    tally.total);
  set("tally-phishing", tally.SOCIAL_ENGINEERING || 0);
  set("tally-malware",  tally.MALWARE || 0);
  set("tally-payment",  tally.PAYMENT_REDIRECT || 0);

  // ── History ──
  // Uses DOM building (not innerHTML) so that entry.url and entry.domain from
  // storage are always assigned via textContent and can never inject HTML.
  const histList = document.getElementById("history-list");
  histList.innerHTML = "";
  if (history.length === 0) {
    const empty = document.createElement("li");
    empty.className = "empty-state";
    empty.textContent = "No threats blocked yet";
    histList.appendChild(empty);
  } else {
    history.forEach((entry) => {
      const tag    = Object.prototype.hasOwnProperty.call(THREAT_SHORT, entry.type) ? entry.type : "UNKNOWN_THREAT";
      const label  = THREAT_SHORT[tag];
      const domain = entry.domain || entry.url || "(unknown)";

      const li = document.createElement("li");

      const tagSpan = document.createElement("span");
      tagSpan.className = `threat-tag tag-${tag}`;
      tagSpan.textContent = label;

      const info = document.createElement("div");
      info.className = "history-info";

      const domainEl = document.createElement("div");
      domainEl.className = "history-domain";
      domainEl.title = entry.url || "";
      domainEl.textContent = domain;

      const timeEl = document.createElement("div");
      timeEl.className = "history-time";
      timeEl.textContent = timeAgo(entry.timestamp);

      info.appendChild(domainEl);
      info.appendChild(timeEl);
      li.appendChild(tagSpan);
      li.appendChild(info);
      histList.appendChild(li);
    });
  }

  // ── Bypassed ──
  const bypassList = document.getElementById("bypass-list");
  bypassList.innerHTML = "";
  if (bypassed.length === 0) {
    const empty = document.createElement("li");
    empty.className = "empty-state";
    empty.style.cssText = "list-style:none;padding:4px 0 8px";
    empty.textContent = "None";
    bypassList.appendChild(empty);
  } else {
    bypassed.forEach((entry) => {
      const url    = entry.url || entry;
      const expiry = timeUntil(entry.expiresAt);

      const li = document.createElement("li");

      const textSpan = document.createElement("span");
      textSpan.className = "list-text";
      textSpan.title = url;
      textSpan.textContent = url;
      li.appendChild(textSpan);

      if (expiry) {
        const expirySpan = document.createElement("span");
        expirySpan.style.cssText = "font-size:9px;color:#9aa0a6;flex-shrink:0";
        expirySpan.textContent = expiry;
        li.appendChild(expirySpan);
      }

      const btn = document.createElement("button");
      btn.className = "remove-btn";
      btn.textContent = "\u2715";
      btn.addEventListener("click", () => {
        chrome.runtime.sendMessage({ type: "REMOVE_BYPASS", url }, () => { li.remove(); });
      });
      li.appendChild(btn);
      bypassList.appendChild(li);
    });
  }

  // ── Whitelist ──
  const whitelistList = document.getElementById("whitelist-list");
  whitelistList.innerHTML = "";
  if (whitelist.length === 0) {
    const empty = document.createElement("li");
    empty.className = "empty-state";
    empty.style.cssText = "list-style:none;padding:4px 0 8px";
    empty.textContent = "None";
    whitelistList.appendChild(empty);
  } else {
    whitelist.forEach((hostname) => {
      const li = document.createElement("li");

      const textSpan = document.createElement("span");
      textSpan.className = "list-text";
      textSpan.title = hostname;
      textSpan.textContent = hostname;

      const btn = document.createElement("button");
      btn.className = "remove-btn";
      btn.textContent = "\u2715";
      btn.addEventListener("click", () => {
        chrome.runtime.sendMessage({ type: "REMOVE_WHITELIST", hostname }, () => { li.remove(); });
      });

      li.appendChild(textSpan);
      li.appendChild(btn);
      whitelistList.appendChild(li);
    });
  }
}

chrome.runtime.sendMessage({ type: "GET_STATS" }, (response) => {
  if (chrome.runtime.lastError) {
    console.warn("[Popup]", chrome.runtime.lastError.message);
    render({});
    return;
  }
  render(response);
});

// ── Protection toggle ──
const toggleInput = document.getElementById("protection-toggle");
const toggleState = document.getElementById("toggle-state");

chrome.storage.local.get({ enabled: true }, ({ enabled }) => {
  toggleInput.checked = enabled;
  toggleState.textContent = enabled ? "On" : "Off";
  toggleState.className = enabled ? "on" : "off";
});

toggleInput.addEventListener("change", () => {
  const enabled = toggleInput.checked;
  chrome.storage.local.set({ enabled }, () => {
    toggleState.textContent = enabled ? "On" : "Off";
    toggleState.className = enabled ? "on" : "off";
  });
});

// ── Whitelist add ──
function addWhitelistEntry() {
  const input = document.getElementById("whitelist-input");
  let value = input.value.trim()
    .replace(/^https?:\/\//i, "")  // strip protocol if typed
    .replace(/\/.*$/, "")           // strip path
    .toLowerCase();

  if (!value) return;

  chrome.runtime.sendMessage({ type: "ADD_WHITELIST", url: "https://" + value }, () => {
    if (chrome.runtime.lastError) return;
    input.value = "";

    const list = document.getElementById("whitelist-list");
    const empty = list.querySelector(".empty-state");
    if (empty) empty.remove();

    const li = document.createElement("li");

    const textSpan = document.createElement("span");
    textSpan.className = "list-text";
    textSpan.title = value;
    textSpan.textContent = value;

    const btn = document.createElement("button");
    btn.className = "remove-btn";
    btn.textContent = "\u2715";
    btn.addEventListener("click", () => {
      chrome.runtime.sendMessage({ type: "REMOVE_WHITELIST", hostname: value }, () => {
        li.remove();
      });
    });

    li.appendChild(textSpan);
    li.appendChild(btn);
    list.appendChild(li);
  });
}

document.getElementById("whitelist-add-btn").addEventListener("click", addWhitelistEntry);
document.getElementById("whitelist-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter") addWhitelistEntry();
});
