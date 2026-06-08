// ============================================================
// CONFIGURATION
// ============================================================

importScripts("config.js");

const PROXY_URL = CONFIG.PROXY_URL;

// ============================================================
// URL HEURISTICS
// ============================================================

function runHeuristics(url) {
  let parsed;
  try { parsed = new URL(url); } catch (_) { return null; }

  const hostname = parsed.hostname.toLowerCase();

  // Bare IP address - but skip private/loopback ranges used for local dev
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    if (/^127\./.test(hostname)) return null;           // 127.x.x.x loopback
    if (/^10\./.test(hostname)) return null;            // 10.x.x.x private
    if (/^192\.168\./.test(hostname)) return null;      // 192.168.x.x private
    if (/^172\.(1[6-9]|2\d|3[01])\./.test(hostname)) return null; // 172.16–31.x.x private
    return "HEURISTIC";
  }

  // @ symbol trick (e.g. https://legit.com@evil.com)
  if (parsed.href.includes("@")) return "HEURISTIC";

  // Punycode / IDN homograph
  if (hostname.includes("xn--")) return "HEURISTIC";

  // High-risk free TLDs commonly abused in phishing
  const highRiskTlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".buzz", ".click"];
  if (highRiskTlds.some((tld) => hostname.endsWith(tld))) return "HEURISTIC";

  // Fake TLD buried inside subdomain - e.g. paypal.com.attacker.net
  // Legitimate hostnames never have a real TLD in the middle of their labels.
  if (/\.(com|net|org|gov|edu)\./.test(hostname)) return "HEURISTIC";

  // Number-substitution lookalikes
  const numberFakes = ["paypa1", "amaz0n", "g00gle", "faceb00k", "micros0ft", "app1e", "netf1ix"];
  if (numberFakes.some((fake) => hostname.includes(fake))) return "HEURISTIC";

  // Brand name in subdomain but not the registrable domain
  const brands = [
    "paypal", "amazon", "google", "facebook", "microsoft", "apple",
    "netflix", "instagram", "twitter", "whatsapp", "chase", "wellsfargo",
    "citibank", "bankofamerica",
  ];
  const parts = hostname.split(".");
  const registrable = parts.slice(-2).join(".");
  for (const brand of brands) {
    if (hostname.includes(brand) && !registrable.includes(brand)) return "HEURISTIC";
  }

  return null;
}

// ============================================================
// HELPERS
// ============================================================

function shouldSkip(url) {
  if (!url) return true;
  if (url.startsWith("chrome://")) return true;
  if (url.startsWith("chrome-extension://")) return true;
  if (url.startsWith("about:")) return true;
  if (url.startsWith("edge://")) return true;
  if (url.startsWith("data:")) return true;
  if (url.startsWith("file://")) return true;
  return false;
}

function buildWarningUrl(originalUrl, threatType, source, detail) {
  const base = chrome.runtime.getURL("warning.html");
  const params = new URLSearchParams({
    url: originalUrl,
    threat: threatType || "UNKNOWN_THREAT",
    source: source || "safebrowsing",
  });
  if (detail) params.set("detail", detail);
  return `${base}?${params.toString()}`;
}

// ============================================================
// SAFE BROWSING API
// ============================================================

async function checkSafeBrowsing(url) {
  if (!PROXY_URL || PROXY_URL.includes("your-project")) return null;

  try {
    const headers = { "Content-Type": "application/json" };
    if (CONFIG.PROXY_SECRET) headers["X-Detector-Token"] = CONFIG.PROXY_SECRET;

    const response = await fetch(PROXY_URL, {
      method: "POST",
      headers,
      body: JSON.stringify({ url }),
    });

    if (!response.ok) {
      console.warn("[PhishingDetector] Proxy error:", response.status);
      return null;
    }

    const data = await response.json();
    if (data.matches && data.matches.length > 0) {
      return data.matches[0].threatType;
    }
    return null;
  } catch (err) {
    console.error("[PhishingDetector] Proxy fetch failed:", err);
    return null;
  }
}

// ============================================================
// WHITELIST (permanent - survives browser restarts)
// ============================================================

async function isWhitelisted(url) {
  let hostname;
  try { hostname = new URL(url).hostname; } catch (_) { return false; }
  return new Promise((resolve) => {
    chrome.storage.local.get({ whitelist: [] }, (data) => {
      resolve(data.whitelist.includes(hostname));
    });
  });
}

async function addWhitelist(url) {
  let hostname;
  try { hostname = new URL(url).hostname; } catch (_) { return; }
  return new Promise((resolve) => {
    chrome.storage.local.get({ whitelist: [] }, (data) => {
      const list = data.whitelist;
      if (!list.includes(hostname)) list.push(hostname);
      chrome.storage.local.set({ whitelist: list }, resolve);
    });
  });
}

async function removeWhitelist(hostname) {
  return new Promise((resolve) => {
    chrome.storage.local.get({ whitelist: [] }, (data) => {
      const list = data.whitelist.filter((h) => h !== hostname);
      chrome.storage.local.set({ whitelist: list }, resolve);
    });
  });
}

// ============================================================
// BYPASS LIST (session - entries expire after 24 h)
// ============================================================

const BYPASS_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

function isEntryActive(entry) {
  if (typeof entry === "string") return true;          // legacy format
  return entry.expiresAt > Date.now();
}

function entryUrl(entry) {
  return typeof entry === "string" ? entry : entry.url;
}

async function isBypassed(url) {
  return new Promise((resolve) => {
    chrome.storage.session.get({ bypassed: [] }, (data) => {
      resolve(data.bypassed.some((e) => isEntryActive(e) && entryUrl(e) === url));
    });
  });
}

async function addBypass(url) {
  return new Promise((resolve) => {
    chrome.storage.session.get({ bypassed: [] }, (data) => {
      const now = Date.now();
      // Prune expired entries and add the new one
      const list = data.bypassed.filter(isEntryActive).filter((e) => entryUrl(e) !== url);
      list.push({ url, expiresAt: now + BYPASS_TTL_MS });
      chrome.storage.session.set({ bypassed: list }, resolve);
    });
  });
}

async function removeBypass(url) {
  return new Promise((resolve) => {
    chrome.storage.session.get({ bypassed: [] }, (data) => {
      const list = data.bypassed.filter((e) => entryUrl(e) !== url);
      chrome.storage.session.set({ bypassed: list }, resolve);
    });
  });
}

// ============================================================
// PERSISTENT BLOCK HISTORY (survives browser restarts)
// ============================================================

async function logBlockedSite(url, threatType) {
  let domain = url;
  try { domain = new URL(url).hostname; } catch (_) {}

  const entry = {
    url,
    domain,
    type: threatType,
    timestamp: Date.now(),
  };

  return new Promise((resolve) => {
    chrome.storage.local.get({ history: [], tally: {} }, (data) => {
      // Keep most recent 200 entries
      const history = [entry, ...data.history].slice(0, 200);
      const tally = { ...data.tally };
      tally[threatType] = (tally[threatType] || 0) + 1;
      tally.total = (tally.total || 0) + 1;
      chrome.storage.local.set({ history, tally }, resolve);
    });
  });
}

// ============================================================
// CORE INTERCEPT LOGIC
// ============================================================

async function handleNavigation(tabId, url) {
  if (shouldSkip(url)) return;
  if (await isBypassed(url)) {
    console.log("[PhishingDetector] Bypassed (user allowed):", url);
    return;
  }
  if (await isWhitelisted(url)) {
    console.log("[PhishingDetector] Whitelisted:", url);
    return;
  }

  const threatType = await checkSafeBrowsing(url);
  if (threatType) {
    console.warn("[PhishingDetector] THREAT DETECTED:", threatType, url);
    await logBlockedSite(url, threatType);
    const warningUrl = buildWarningUrl(url, threatType, "safebrowsing");
    chrome.tabs.update(tabId, { url: warningUrl });
  }
}

// ============================================================
// NAVIGATION LISTENERS
// ============================================================

// Heuristics run on onBeforeNavigate so they catch navigations that never
// resolve (NXDOMAIN, refused connections) - onCommitted only fires on success.
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;
  const { tabId, url } = details;
  if (shouldSkip(url)) return;

  isBypassed(url).then(async (bypassed) => {
    if (bypassed) return;
    if (await isWhitelisted(url)) return;
    const heuristicThreat = runHeuristics(url);
    if (heuristicThreat) {
      console.warn("[PhishingDetector] HEURISTIC HIT:", url);
      await logBlockedSite(url, "HEURISTIC");
      chrome.tabs.update(tabId, { url: buildWarningUrl(url, "HEURISTIC", "heuristic") });
    }
  });
});

// Safe Browsing runs on onCommitted (page is loading, network is available).
chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  handleNavigation(details.tabId, details.url);
});

// ============================================================
// MESSAGE LISTENER
// ============================================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Form-scanner detected a cross-origin password form
  if (message.type === "FORM_HIJACK_DETECTED") {
    const { sourceUrl, actionUrl, detail } = message;
    const tabId = sender.tab?.id;

    if (!tabId) {
      sendResponse({ status: "error", reason: "no tab id" });
      return false;
    }

    isBypassed(sourceUrl).then(async (bypassed) => {
      if (bypassed) {
        sendResponse({ status: "bypassed" });
        return;
      }
      await logBlockedSite(sourceUrl, "FORM_HIJACK");
      const warningUrl = buildWarningUrl(sourceUrl, "FORM_HIJACK", "contentscript", detail);
      chrome.tabs.update(tabId, { url: warningUrl });
      sendResponse({ status: "redirected" });
    });

    return true;
  }

  // Content script detected a payment redirect
  if (message.type === "PAYMENT_REDIRECT_DETECTED") {
    const { sourceUrl, redirectUrl, detail } = message;
    const tabId = sender.tab?.id;

    if (!tabId) {
      sendResponse({ status: "error", reason: "no tab id" });
      return false;
    }

    isBypassed(sourceUrl).then(async (bypassed) => {
      if (bypassed) {
        sendResponse({ status: "bypassed" });
        return;
      }
      await logBlockedSite(redirectUrl, "PAYMENT_REDIRECT");
      const warningUrl = buildWarningUrl(redirectUrl, "PAYMENT_REDIRECT", "contentscript", detail);
      chrome.tabs.update(tabId, { url: warningUrl });
      sendResponse({ status: "redirected" });
    });

    return true;
  }

  // Warning page: user clicked "Go back to safety"
  // history.back() would return to the malicious URL and re-trigger the warning,
  // so background navigates the tab to the new tab page instead.
  if (message.type === "GO_BACK_SAFE") {
    chrome.tabs.update(sender.tab.id, { url: "chrome://newtab" });
    sendResponse({ status: "ok" });
    return false;
  }

  // Warning page: user clicked "Proceed anyway"
  if (message.type === "ADD_BYPASS") {
    addBypass(message.url).then(() => {
      sendResponse({ status: "ok" });
    });
    return true;
  }

  // Popup: request stats
  if (message.type === "GET_STATS") {
    chrome.storage.local.get({ history: [], tally: {}, whitelist: [] }, (localData) => {
      chrome.storage.session.get({ bypassed: [] }, (sessionData) => {
        // Filter expired entries before sending
        const activeBypassed = sessionData.bypassed
          .filter(isEntryActive)
          .map((e) => typeof e === "string" ? { url: e, expiresAt: null } : e);
        sendResponse({
          tally: localData.tally,
          history: localData.history.slice(0, 20),
          bypassed: activeBypassed,
          whitelist: localData.whitelist,
        });
      });
    });
    return true;
  }

  // Warning page: user clicked "Always allow this domain"
  if (message.type === "ADD_WHITELIST") {
    addWhitelist(message.url).then(() => {
      sendResponse({ status: "ok" });
    });
    return true;
  }

  // Popup: remove a domain from the whitelist
  if (message.type === "REMOVE_WHITELIST") {
    removeWhitelist(message.hostname).then(() => {
      sendResponse({ status: "ok" });
    });
    return true;
  }

  // Popup: remove a URL from the session bypass list
  if (message.type === "REMOVE_BYPASS") {
    removeBypass(message.url).then(() => {
      sendResponse({ status: "ok" });
    });
    return true;
  }
});
