// ============================================================
// CONFIGURATION
// ============================================================

importScripts("config.js");

const PROXY_URL = CONFIG.PROXY_URL;
const UPDATE_URL = CONFIG.UPDATE_URL || null; // Vercel proxy for hash-prefix update API

// ============================================================
// URL SCAN CACHE (in-memory, 5-min TTL)
// ============================================================

const urlCache = new Map(); // url -> { result: string|null, timestamp: number }
const URL_CACHE_TTL_MS = 5 * 60 * 1000;

function getCachedResult(url) {
  const entry = urlCache.get(url);
  if (!entry) return undefined;
  if (Date.now() - entry.timestamp > URL_CACHE_TTL_MS) {
    urlCache.delete(url);
    return undefined;
  }
  return entry.result;
}

function setCachedResult(url, result) {
  if (urlCache.size >= 500) {
    const sorted = [...urlCache.entries()].sort((a, b) => a[1].timestamp - b[1].timestamp);
    sorted.slice(0, 100).forEach(([k]) => urlCache.delete(k));
  }
  urlCache.set(url, { result, timestamp: Date.now() });
}

// ============================================================
// URL HEURISTICS
// ============================================================

// Shared list of common two-part ccTLD suffixes.
// Used by getRegistrable() and the fake-TLD heuristic so both stay consistent.
const TWO_PART_TLDS = [
  "co.uk", "co.au", "co.nz", "co.za", "co.in", "co.jp", "co.kr", "co.id",
  "com.au", "com.br", "com.mx", "com.ar", "com.tr", "com.sg", "com.hk",
  "org.uk", "net.au", "gov.uk", "ac.uk", "me.uk",
];

// Returns the registrable domain (eTLD+1), handling common two-part ccTLDs.
function getRegistrable(hostname) {
  const parts = hostname.split(".");
  if (parts.length < 2) return hostname;
  const lastTwo = parts.slice(-2).join(".");
  if (TWO_PART_TLDS.includes(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }
  return lastTwo;
}

// Levenshtein edit distance - used for typosquatting detection.
// Space-optimised O(min(m,n)) implementation.
function levenshtein(a, b) {
  if (a === b) return 0;
  if (a.length > b.length) [a, b] = [b, a];
  const n = b.length;
  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  const curr = new Array(n + 1);
  for (let i = 1; i <= a.length; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      curr[j] = a[i - 1] === b[j - 1]
        ? prev[j - 1]
        : 1 + Math.min(prev[j], curr[j - 1], prev[j - 1]);
    }
    [prev, curr.length] = [[...curr], curr.length];
    // swap via copy
    for (let k = 0; k <= n; k++) prev[k] = curr[k];
  }
  return prev[n];
}

function runHeuristics(url) {
  let parsed;
  try { parsed = new URL(url); } catch (_) { return null; }

  const hostname = parsed.hostname.toLowerCase();

  // Bare IP address - skip private/loopback ranges used for local dev
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    if (/^127\./.test(hostname)) return null;           // 127.x.x.x loopback
    if (/^10\./.test(hostname)) return null;            // 10.x.x.x private
    if (/^192\.168\./.test(hostname)) return null;      // 192.168.x.x private
    if (/^172\.(1[6-9]|2\d|3[01])\./.test(hostname)) return null; // 172.16-31.x.x private
    return "HEURISTIC";
  }

  // @ symbol trick (e.g. https://paypal.com@evil.com)
  if (parsed.username || parsed.password) return "HEURISTIC";

  // Punycode / IDN homograph
  if (hostname.includes("xn--")) return "HEURISTIC";

  // High-risk free TLDs commonly abused in phishing
  const highRiskTlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".buzz", ".click"];
  if (highRiskTlds.some((tld) => hostname.endsWith(tld))) return "HEURISTIC";

  // Fake TLD buried inside subdomain - e.g. paypal.com.attacker.net
  if (/\.(com|net|org|gov|edu)\./.test(hostname)) {
    if (!TWO_PART_TLDS.some((tld) => hostname.endsWith("." + tld))) return "HEURISTIC";
  }

  // Number-substitution lookalikes
  const numberFakes = ["paypa1", "amaz0n", "g00gle", "faceb00k", "micros0ft", "app1e", "netf1ix"];
  if (numberFakes.some((fake) => hostname.includes(fake))) return "HEURISTIC";

  const brands = [
    "paypal", "amazon", "google", "facebook", "microsoft", "apple",
    "netflix", "instagram", "twitter", "whatsapp", "chase", "wellsfargo",
    "citibank", "bankofamerica",
  ];
  const registrable = getRegistrable(hostname);

  // Brand name in subdomain but not the registrable domain
  for (const brand of brands) {
    if (hostname.includes(brand) && !registrable.includes(brand)) return "HEURISTIC";
  }

  // Levenshtein typosquatting: registrable name is 1-2 edits away from a known brand
  // e.g. "paypa1.com", "arnazon.com", "micosoft.com"
  const regName = registrable.split(".")[0];
  for (const brand of brands) {
    if (regName !== brand && levenshtein(regName, brand) <= 2) return "HEURISTIC";
  }

  return null;
}

// ============================================================
// HELPERS
// ============================================================

function shouldSkip(url) {
  if (!url) return true;
  return !url.startsWith("http://") && !url.startsWith("https://");
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
  // 1. In-memory result cache
  const cached = getCachedResult(url);
  if (cached !== undefined) return cached;

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
      console.warn("[VantaSecurity] Proxy error:", response.status);
      return null;
    }

    const data = await response.json();
    const result = (data.matches && data.matches.length > 0) ? data.matches[0].threatType : null;
    setCachedResult(url, result);
    return result;
  } catch (err) {
    console.error("[VantaSecurity] Proxy fetch failed:", err);
    return null;
  }
}

// ============================================================
// HASH-PREFIX CACHE (Safe Browsing v4 Update API)
// ============================================================

// threatType -> Set of hex-encoded hash prefixes (variable size, usually 4 bytes)
const hashPrefixSets = new Map();
// threatType -> opaque state token for incremental updates
const hashStateTokens = new Map();

const HASH_THREAT_TYPES = [
  "MALWARE",
  "SOCIAL_ENGINEERING",
  "UNWANTED_SOFTWARE",
  "POTENTIALLY_HARMFUL_APPLICATION",
];

const HASH_PREFIX_ALARM = "vanta-hash-refresh";
const HASH_REFRESH_MINUTES = 30;

async function fetchHashPrefixes() {
  if (!UPDATE_URL) return;

  try {
    const listUpdateRequests = HASH_THREAT_TYPES.map((threatType) => ({
      threatType,
      platformType: "ANY_PLATFORM",
      threatEntryType: "URL",
      state: hashStateTokens.get(threatType) || "",
      constraints: {
        maxUpdateEntries: 2048,
        maxDatabaseEntries: 65536,
        supportedCompressions: ["RAW"],
      },
    }));

    const headers = { "Content-Type": "application/json" };
    if (CONFIG.PROXY_SECRET) headers["X-Detector-Token"] = CONFIG.PROXY_SECRET;

    const response = await fetch(UPDATE_URL, {
      method: "POST",
      headers,
      body: JSON.stringify({ listUpdateRequests }),
    });

    if (!response.ok) {
      console.warn("[VantaSecurity] Hash update proxy error:", response.status);
      return;
    }

    const data = await response.json();
    if (!data.listUpdateResponses) return;

    for (const resp of data.listUpdateResponses) {
      const { threatType, responseType, additions, removals, newClientState } = resp;
      if (!threatType) continue;

      if (!hashPrefixSets.has(threatType)) hashPrefixSets.set(threatType, new Set());
      const prefixSet = hashPrefixSets.get(threatType);

      if (responseType === "FULL_UPDATE") prefixSet.clear();

      if (additions) {
        for (const addition of additions) {
          if (addition.rawHashes) {
            const { prefixSize, rawHashes: b64 } = addition.rawHashes;
            const bytes = _base64ToBytes(b64);
            for (let i = 0; i < bytes.length; i += prefixSize) {
              const prefix = Array.from(bytes.slice(i, i + prefixSize))
                .map((b) => b.toString(16).padStart(2, "0"))
                .join("");
              prefixSet.add(prefix);
            }
          }
        }
      }

      if (removals) {
        const sorted = [...prefixSet].sort();
        for (const removal of removals) {
          if (removal.rawIndices) {
            for (const idx of removal.rawIndices.indices) {
              if (sorted[idx]) prefixSet.delete(sorted[idx]);
            }
          }
        }
      }

      if (newClientState) hashStateTokens.set(threatType, newClientState);
    }

    const total = [...hashPrefixSets.values()].reduce((s, set) => s + set.size, 0);
    console.log("[VantaSecurity] Hash prefixes updated. Total entries:", total);
  } catch (err) {
    console.error("[VantaSecurity] Hash prefix fetch failed:", err);
  }
}

function _base64ToBytes(b64) {
  const binaryStr = atob(b64);
  const bytes = new Uint8Array(binaryStr.length);
  for (let i = 0; i < binaryStr.length; i++) bytes[i] = binaryStr.charCodeAt(i);
  return bytes;
}

// Returns true if any SHA-256 prefix of the URL matches the downloaded hash lists.
// Uses simplified Safe Browsing URL canonicalization (covers the most common cases).
async function isInPrefixCache(url) {
  if (hashPrefixSets.size === 0) return true; // no data yet - allow API call

  let parsed;
  try { parsed = new URL(url); } catch (_) { return false; }

  const host = parsed.hostname.toLowerCase();
  const path = parsed.pathname || "/";
  const query = parsed.search;

  // URL expressions to hash (ordered by specificity)
  const expressions = new Set([
    `${host}${path}${query}`,
    `${host}${path}`,
    `${host}/`,
  ]);

  // Add intermediate paths
  const segments = path.split("/").filter(Boolean);
  for (let i = 1; i < segments.length; i++) {
    expressions.add(`${host}/${segments.slice(0, i).join("/")}/`);
  }

  for (const expr of expressions) {
    const encoded = new TextEncoder().encode(expr);
    const hashBuf = await crypto.subtle.digest("SHA-256", encoded);
    const hashBytes = new Uint8Array(hashBuf);

    for (const prefixSet of hashPrefixSets.values()) {
      if (prefixSet.size === 0) continue;
      const sample = prefixSet.values().next().value;
      const byteLen = sample ? sample.length / 2 : 4;
      const prefix = Array.from(hashBytes.slice(0, byteLen))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      if (prefixSet.has(prefix)) return true;
    }
  }

  return false;
}

// ============================================================
// BADGE & ICON HELPERS
// ============================================================

async function updateBadge() {
  return new Promise((resolve) => {
    chrome.storage.local.get({ enabled: true, tally: {} }, ({ enabled, tally }) => {
      if (!enabled) {
        chrome.action.setBadgeText({ text: "" });
        resolve();
        return;
      }
      const total = tally.total || 0;
      if (total > 0) {
        chrome.action.setBadgeText({ text: total > 999 ? "999+" : String(total) });
        chrome.action.setBadgeBackgroundColor({ color: "#6366f1" });
      } else {
        chrome.action.setBadgeText({ text: "" });
      }
      resolve();
    });
  });
}

async function setIconEnabled(enabled) {
  if (enabled) {
    chrome.action.setIcon({
      path: {
        "16":  "icons/icon16.png",
        "48":  "icons/icon48.png",
        "64":  "icons/icon64.png",
        "128": "icons/icon128.png",
      },
    });
    return;
  }

  // Generate greyscale/dimmed icons via OffscreenCanvas
  const sizes = [16, 48, 64, 128];
  const imageDataMap = {};
  for (const size of sizes) {
    try {
      const resp = await fetch(chrome.runtime.getURL(`icons/icon${size}.png`));
      const blob = await resp.blob();
      const bitmap = await createImageBitmap(blob);
      const canvas = new OffscreenCanvas(size, size);
      const ctx = canvas.getContext("2d");
      ctx.drawImage(bitmap, 0, 0, size, size);
      const imgData = ctx.getImageData(0, 0, size, size);
      for (let i = 0; i < imgData.data.length; i += 4) {
        const grey = Math.round(
          0.299 * imgData.data[i] + 0.587 * imgData.data[i + 1] + 0.114 * imgData.data[i + 2]
        );
        imgData.data[i] = imgData.data[i + 1] = imgData.data[i + 2] = Math.round(grey * 0.4);
      }
      imageDataMap[size] = imgData;
    } catch (e) {
      console.warn("[VantaSecurity] Greyscale icon failed for size", size, e);
    }
  }
  if (Object.keys(imageDataMap).length > 0) {
    chrome.action.setIcon({ imageData: imageDataMap });
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
      chrome.storage.local.set({ history, tally }, () => {
        updateBadge();
        resolve();
      });
    });
  });
}

// ============================================================
// CORE INTERCEPT LOGIC
// ============================================================

async function handleNavigation(tabId, url) {
  if (shouldSkip(url)) return;
  if (await isBypassed(url)) {
    console.log("[VantaSecurity] Bypassed (user allowed):", url);
    return;
  }
  if (await isWhitelisted(url)) {
    console.log("[VantaSecurity] Whitelisted:", url);
    return;
  }

  const threatType = await checkSafeBrowsing(url);
  if (threatType) {
    console.warn("[VantaSecurity] THREAT DETECTED:", threatType, url);
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

  chrome.storage.local.get({ enabled: true }, ({ enabled }) => {
    if (!enabled) return;
    isBypassed(url).then(async (bypassed) => {
      if (bypassed) return;
      if (await isWhitelisted(url)) return;
      const heuristicThreat = runHeuristics(url);
      if (heuristicThreat) {
        console.warn("[VantaSecurity] HEURISTIC HIT:", url);
        await logBlockedSite(url, "HEURISTIC");
        chrome.tabs.update(tabId, { url: buildWarningUrl(url, "HEURISTIC", "heuristic") });
      }
    });
  });
});

// Safe Browsing runs on onCommitted (page is loading, network is available).
chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  chrome.storage.local.get({ enabled: true }, ({ enabled }) => {
    if (!enabled) return;
    handleNavigation(details.tabId, details.url);
  });
});

// ============================================================
// STARTUP / INSTALL
// ============================================================

chrome.runtime.onInstalled.addListener(() => {
  updateBadge();
  chrome.alarms.create(HASH_PREFIX_ALARM, { periodInMinutes: HASH_REFRESH_MINUTES });
  fetchHashPrefixes();
});

chrome.runtime.onStartup.addListener(() => {
  updateBadge();
  chrome.storage.local.get({ enabled: true }, ({ enabled }) => setIconEnabled(enabled));
  fetchHashPrefixes();
  chrome.alarms.get(HASH_PREFIX_ALARM, (alarm) => {
    if (!alarm) chrome.alarms.create(HASH_PREFIX_ALARM, { periodInMinutes: HASH_REFRESH_MINUTES });
  });
});

// ============================================================
// ALARMS
// ============================================================

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === HASH_PREFIX_ALARM) fetchHashPrefixes();
});

// ============================================================
// STORAGE CHANGE LISTENER (badge/icon sync)
// ============================================================

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;
  if ("enabled" in changes) {
    setIconEnabled(changes.enabled.newValue !== false);
    updateBadge();
  }
  if ("tally" in changes) {
    updateBadge();
  }
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

    chrome.storage.local.get({ enabled: true }, ({ enabled }) => {
      if (!enabled) { sendResponse({ status: "disabled" }); return; }
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

    chrome.storage.local.get({ enabled: true }, ({ enabled }) => {
      if (!enabled) { sendResponse({ status: "disabled" }); return; }
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

  // Popup: get current tab status (clean / blocked / whitelisted / bypassed)
  if (message.type === "GET_TAB_STATUS") {
    const { url } = message;
    if (!url || shouldSkip(url)) {
      sendResponse({ status: "unknown" });
      return false;
    }

    chrome.storage.local.get({ enabled: true, history: [] }, async ({ enabled, history }) => {
      if (!enabled) {
        sendResponse({ status: "disabled" });
        return;
      }
      if (await isWhitelisted(url)) {
        sendResponse({ status: "whitelisted" });
        return;
      }
      if (await isBypassed(url)) {
        sendResponse({ status: "bypassed" });
        return;
      }
      // Check if this URL/domain has been blocked before
      let hostname = "";
      try { hostname = new URL(url).hostname; } catch (_) {}
      const blocked = history.find((e) => e.domain === hostname || e.url === url);
      if (blocked) {
        sendResponse({ status: "blocked", type: blocked.type });
        return;
      }
      sendResponse({ status: "clean" });
    });

    return true;
  }

  // Popup: manually scan the active tab URL
  if (message.type === "SCAN_TAB") {
    const { url, tabId } = message;
    if (!url || shouldSkip(url)) {
      sendResponse({ status: "skipped" });
      return false;
    }

    chrome.storage.local.get({ enabled: true }, ({ enabled }) => {
      if (!enabled) { sendResponse({ status: "disabled" }); return; }

      const heuristicThreat = runHeuristics(url);
      if (heuristicThreat) {
        logBlockedSite(url, "HEURISTIC").then(() => {
          if (tabId) chrome.tabs.update(tabId, { url: buildWarningUrl(url, "HEURISTIC", "heuristic") });
          sendResponse({ status: "threat", threatType: "HEURISTIC" });
        });
        return;
      }

      // Invalidate cache so we get a fresh result
      urlCache.delete(url);
      checkSafeBrowsing(url).then(async (threatType) => {
        if (threatType) {
          await logBlockedSite(url, threatType);
          if (tabId) chrome.tabs.update(tabId, { url: buildWarningUrl(url, threatType, "safebrowsing") });
          sendResponse({ status: "threat", threatType });
        } else {
          sendResponse({ status: "clean" });
        }
      });
    });

    return true;
  }

  // Popup: clear all block history and tally counters
  if (message.type === "CLEAR_HISTORY") {
    chrome.storage.local.set({ history: [], tally: {} }, () => {
      updateBadge();
      sendResponse({ status: "ok" });
    });
    return true;
  }
});
