// ============================================================
// WARNING PAGE LOGIC
// ============================================================

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
  UNKNOWN_THREAT: {
    label: "SECURITY THREAT",
    items: [
      "This site has been flagged as potentially dangerous.",
      "We recommend leaving immediately.",
    ],
  },
};

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
  document.getElementById("blocked-url").textContent = url || "(unknown)";

  const list = document.getElementById("threat-details");
  list.innerHTML = info.items.map((item) => `<li>${item}</li>`).join("");

  // Show the code snippet block only for content script detections
  if (source === "contentscript" && detail) {
    const snippetBlock = document.getElementById("snippet-block");
    snippetBlock.style.display = "block";
    document.getElementById("snippet-code").textContent = detail;
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

  document.getElementById("btn-proceed").addEventListener("click", () => {
    if (!url) return;

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
