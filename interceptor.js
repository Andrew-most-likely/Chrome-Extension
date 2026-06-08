// ============================================================
// LOCATION INTERCEPTOR - runs in MAIN world (page JS context)
// Declared as a content script with "world": "MAIN" so it
// executes before any page scripts and is NOT subject to CSP.
// ============================================================

(function () {
  const PAYMENT_DOMAINS = [
    "paypal.com",
    "stripe.com",
    "venmo.com",
    "cash.app",
    "cashapp.com",
    "coinbase.com",
    "zelle.com",
    "blockchain.com",
    "kraken.com",
    "binance.com",
    "wise.com",
    "transferwise.com",
    "squarecash.com",
    "apple.com/pay",
    "pay.google.com",
    "moneygram.com",
    "westernunion.com",
  ];

  function isPaymentUrl(url) {
    if (!url || typeof url !== "string") return false;
    return PAYMENT_DOMAINS.some((d) => url.toLowerCase().includes(d));
  }

  function report(redirectUrl) {
    window.dispatchEvent(
      new CustomEvent("__phishing_redirect__", {
        detail: { redirectUrl },
      })
    );
  }

  // Override location.href setter
  const locDesc = Object.getOwnPropertyDescriptor(Location.prototype, "href");
  if (locDesc) {
    Object.defineProperty(Location.prototype, "href", {
      set(url) {
        if (isPaymentUrl(url)) { report(url); return; }
        locDesc.set.call(this, url);
      },
      get: locDesc.get,
      configurable: false,  // prevent page scripts from re-overriding this setter
    });
  }

  // Override location.replace
  const origReplace = Location.prototype.replace;
  Location.prototype.replace = function (url) {
    if (isPaymentUrl(url)) { report(url); return; }
    return origReplace.call(this, url);
  };

  // Override location.assign
  const origAssign = Location.prototype.assign;
  Location.prototype.assign = function (url) {
    if (isPaymentUrl(url)) { report(url); return; }
    return origAssign.call(this, url);
  };
})();
