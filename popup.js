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
  const histList = document.getElementById("history-list");
  if (history.length === 0) {
    histList.innerHTML = '<li class="empty-state">No threats blocked yet</li>';
  } else {
    histList.innerHTML = history.map((entry) => {
      const tag   = entry.type || "UNKNOWN_THREAT";
      const label = THREAT_SHORT[tag] || tag;
      const domain = entry.domain || entry.url;
      return `
        <li>
          <span class="threat-tag tag-${tag}">${label}</span>
          <div class="history-info">
            <div class="history-domain" title="${entry.url}">${domain}</div>
            <div class="history-time">${timeAgo(entry.timestamp)}</div>
          </div>
        </li>`;
    }).join("");
  }

  // ── Bypassed ──
  const bypassList = document.getElementById("bypass-list");
  if (bypassed.length === 0) {
    bypassList.innerHTML = '<li class="empty-state" style="list-style:none;padding:4px 0 8px">None</li>';
  } else {
    bypassList.innerHTML = bypassed.map((entry) => {
      const url = entry.url || entry;
      const expiry = timeUntil(entry.expiresAt);
      return `<li>
        <span class="list-text" title="${url}">${url}</span>
        ${expiry ? `<span style="font-size:9px;color:#9aa0a6;flex-shrink:0">${expiry}</span>` : ""}
        <button class="remove-btn" data-type="bypass" data-value="${url}">✕</button>
      </li>`;
    }).join("");
  }

  // ── Whitelist ──
  const whitelistList = document.getElementById("whitelist-list");
  if (whitelist.length === 0) {
    whitelistList.innerHTML = '<li class="empty-state" style="list-style:none;padding:4px 0 8px">None</li>';
  } else {
    whitelistList.innerHTML = whitelist.map((hostname) => `
      <li>
        <span class="list-text" title="${hostname}">${hostname}</span>
        <button class="remove-btn" data-type="whitelist" data-value="${hostname}">✕</button>
      </li>`).join("");
  }

  // ── Remove buttons ──
  document.querySelectorAll(".remove-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const value = btn.dataset.value;
      if (btn.dataset.type === "bypass") {
        chrome.runtime.sendMessage({ type: "REMOVE_BYPASS", url: value }, () => {
          btn.closest("li").remove();
        });
      } else {
        chrome.runtime.sendMessage({ type: "REMOVE_WHITELIST", hostname: value }, () => {
          btn.closest("li").remove();
        });
      }
    });
  });
}

chrome.runtime.sendMessage({ type: "GET_STATS" }, (response) => {
  if (chrome.runtime.lastError) {
    console.warn("[Popup]", chrome.runtime.lastError.message);
    render({});
    return;
  }
  render(response);
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
    li.innerHTML = `
      <span class="list-text" title="${value}">${value}</span>
      <button class="remove-btn" data-type="whitelist" data-value="${value}">✕</button>`;
    li.querySelector(".remove-btn").addEventListener("click", () => {
      chrome.runtime.sendMessage({ type: "REMOVE_WHITELIST", hostname: value }, () => {
        li.remove();
      });
    });
    list.appendChild(li);
  });
}

document.getElementById("whitelist-add-btn").addEventListener("click", addWhitelistEntry);
document.getElementById("whitelist-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter") addWhitelistEntry();
});
