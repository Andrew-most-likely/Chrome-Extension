// ============================================================
// FORM ACTION SCANNER - ISOLATED world, document_idle
// Detects cross-origin password forms (credential harvesting).
// ============================================================

(function () {
  function getActionOrigin(form) {
    const raw = form.getAttribute("action") || "";
    // Only flag forms with an explicit absolute http/https action.
    // Relative, empty, fragment-only, or protocol-relative actions are
    // same-origin by definition and must never be flagged.
    if (!/^https?:\/\//i.test(raw)) return null;
    try {
      return new URL(raw).origin;
    } catch (_) {
      return null;
    }
  }

  function hasPasswordField(form) {
    return !!form.querySelector('input[type="password"]');
  }

  function scan() {
    const forms = document.querySelectorAll("form");
    for (const form of forms) {
      if (!hasPasswordField(form)) continue;

      const actionOrigin = getActionOrigin(form);
      if (!actionOrigin) continue;

      // Skip if the action resolves to the same origin as the current page
      if (window.location.origin !== "null" && actionOrigin === window.location.origin) continue;

      // Cross-origin absolute action with a password field - credential harvesting pattern
      const detail = form.getAttribute("action") || actionOrigin;
      chrome.runtime.sendMessage({
        type: "FORM_HIJACK_DETECTED",
        sourceUrl: window.location.href,
        actionUrl: actionOrigin,
        detail,
      });
      break; // One report per page load is enough
    }
  }

  scan();
})();
