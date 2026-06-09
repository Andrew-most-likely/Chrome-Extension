// ============================================================
// WARNING PAGE LOGIC
// ============================================================

// Prevent this page from being embedded in iframes by external websites.
// An attacker could otherwise iframe warning.html with crafted parameters
// to social-engineer the user on a third-party page.
if (window.self !== window.top) {
  document.documentElement.innerHTML = "";
  window.stop();
}

const THREAT_INFO = {
  MALWARE: {
    label: "MALWARE",
    items: [
      "This site attempts to install malicious software on your device.",
      "It may steal personal data, passwords, or banking credentials.",
      "Your antivirus software may not be able to protect you here.",
    ],
  },
  SOCIAL_ENGINEERING: {
    label: "PHISHING / SOCIAL ENGINEERING",
    items: [
      "This site is impersonating a legitimate website to steal your information.",
      "It may show fake login pages for banks, payment services, or social media.",
      "Any credentials you enter here will be sent to attackers.",
    ],
  },
  UNWANTED_SOFTWARE: {
    label: "UNWANTED SOFTWARE",
    items: [
      "This site distributes software that may change your browser settings without consent.",
      "Downloads from this site may be bundled with adware or spyware.",
      "Proceed only if you fully trust this source.",
    ],
  },
  POTENTIALLY_HARMFUL_APPLICATION: {
    label: "POTENTIALLY HARMFUL APP",
    items: [
      "This site offers applications that violate software safety policies.",
      "Such apps may display intrusive ads, track your activity, or be difficult to remove.",
    ],
  },
  PAYMENT_REDIRECT: {
    label: "SUSPICIOUS PAYMENT REDIRECT",
    items: [
      "A script on this page attempts to redirect you to a payment service.",
      "Legitimate websites do not silently redirect to payment platforms like PayPal, Stripe, or cryptocurrency exchanges.",
      "This is a strong indicator of a financial phishing attack.",
    ],
  },
  HEURISTIC: {
    label: "SUSPICIOUS URL",
    items: [
      "This URL matches patterns commonly used in phishing and fraud.",
      "It may be impersonating a well-known brand or using a deceptive domain name.",
      "Legitimate sites do not use IP addresses, number substitutions, or free high-risk domains.",
    ],
  },
  FORM_HIJACK: {
    label: "CREDENTIAL HARVESTING FORM",
    items: [
      "This page contains a login form that sends your password to a different website.",
      "Legitimate sites always submit credentials to their own domain.",
      "Entering your password here will likely send it directly to attackers.",
    ],
  },
  UNKNOWN_THREAT: {
    label: "SECURITY THREAT",
    items: [
      "This site has been flagged as potentially dangerous.",
      "We recommend leaving immediately.",
    ],
  },
};

// ============================================================
// URL validation
// ============================================================

// Only allow http:// and https:// URLs. Blocks javascript:, data:,
// vbscript:, and other schemes that could be injected via the ?url= param.
function isSafeUrl(url) {
  if (!url || typeof url !== "string") return false;
  try {
    const parsed = new URL(url);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch (_) {
    return false;
  }
}

// ============================================================
// Parse URL parameters
// ============================================================

function getParams() {
  const params = new URLSearchParams(window.location.search);
  return {
    url: params.get("url") || "",
    threat: params.get("threat") || "UNKNOWN_THREAT",
    source: params.get("source") || "safebrowsing",
    detail: params.get("detail") || "",
  };
}

// ============================================================
// Render page content
// ============================================================

function render() {
  const { url, threat, source, detail } = getParams();
  const info = THREAT_INFO[threat] || THREAT_INFO["UNKNOWN_THREAT"];

  document.getElementById("threat-label").textContent = info.label;

  // Only display the URL if it is a safe http/https URL to prevent open redirect
  // display issues and to signal clearly when the warning page was opened with a
  // crafted/invalid parameter.
  document.getElementById("blocked-url").textContent = isSafeUrl(url) ? url : "(invalid or unknown URL)";

  const list = document.getElementById("threat-details");
  list.innerHTML = info.items.map((item) => `<li>${item}</li>`).join("");

  // Show the code snippet block only for content script detections
  if (source === "contentscript" && detail) {
    const snippetBlock = document.getElementById("snippet-block");
    snippetBlock.style.display = "block";
    document.getElementById("snippet-code").textContent = detail;
  }

  // Hide the navigation buttons if the URL is not a safe http/https URL.
  // This prevents the open redirect: a crafted ?url=javascript:... or
  // ?url=data:... cannot trigger code execution via the proceed/whitelist buttons.
  if (!isSafeUrl(url)) {
    document.getElementById("btn-proceed").style.display = "none";
    document.getElementById("btn-whitelist").style.display = "none";
  }
}

// ============================================================
// Button handlers
// ============================================================

function setupButtons() {
  const { url } = getParams();

  document.getElementById("btn-back").addEventListener("click", () => {
    // history.back() would return to the malicious URL and re-trigger the warning.
    // Ask background to navigate the tab to the new tab page instead.
    chrome.runtime.sendMessage({ type: "GO_BACK_SAFE" });
  });

  document.getElementById("btn-whitelist").addEventListener("click", () => {
    if (!isSafeUrl(url)) return;
    const btn = document.getElementById("btn-whitelist");
    btn.disabled = true;
    btn.textContent = "Adding to whitelist...";
    chrome.runtime.sendMessage({ type: "ADD_WHITELIST", url }, () => {
      window.location.href = url;
    });
  });

  document.getElementById("btn-proceed").addEventListener("click", () => {
    if (!isSafeUrl(url)) return;

    const btn = document.getElementById("btn-proceed");
    btn.disabled = true;
    btn.textContent = "Storing bypass…";

    chrome.runtime.sendMessage({ type: "ADD_BYPASS", url }, (response) => {
      if (chrome.runtime.lastError) {
        console.error("[Warning] Could not reach background:", chrome.runtime.lastError.message);
        // Navigate anyway even if bypass storage failed
        window.location.href = url;
        return;
      }
      window.location.href = url;
    });
  });
}

// ============================================================
// Init
// ============================================================

render();
setupButtons();
