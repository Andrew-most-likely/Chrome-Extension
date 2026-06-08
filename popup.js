// ============================================================
// POPUP LOGIC
// ============================================================

const THREAT_SHORT = {
  MALWARE:                          "Malware",
  SOCIAL_ENGINEERING:               "Phishing",
  UNWANTED_SOFTWARE:                "Unwanted SW",
  POTENTIALLY_HARMFUL_APPLICATION:  "Harmful App",
  PAYMENT_REDIRECT:                 "Pay Redirect",
  UNKNOWN_THREAT:                   "Threat",
};

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
  const { tally = {}, history = [], bypassed = [] } = data;

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
    bypassList.innerHTML = bypassed.map((url) => {
      const display = url.length > 46 ? url.slice(0, 43) + "…" : url;
      return `<li title="${url}">${display}</li>`;
    }).join("");
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
