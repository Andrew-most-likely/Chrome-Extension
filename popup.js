// ============================================================
// POPUP LOGIC
// ============================================================

function renderStats(data) {
  const { blockedCount = 0, bypassed = [] } = data;

  document.getElementById("blocked-count").textContent = blockedCount;
  document.getElementById("bypass-count").textContent = bypassed.length;

  const list = document.getElementById("bypass-list");

  if (bypassed.length === 0) {
    list.innerHTML = '<li class="empty-state">None yet</li>';
    return;
  }

  list.innerHTML = bypassed
    .map((url) => {
      const display = url.length > 48 ? url.slice(0, 45) + "…" : url;
      return `<li title="${url}">${display}</li>`;
    })
    .join("");
}

chrome.runtime.sendMessage({ type: "GET_STATS" }, (response) => {
  if (chrome.runtime.lastError) {
    console.warn("[Popup] Could not get stats:", chrome.runtime.lastError.message);
    renderStats({});
    return;
  }
  renderStats(response);
});
