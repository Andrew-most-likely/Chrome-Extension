// Vercel serverless function - Safe Browsing proxy
// The API key lives in Vercel environment variables, never in extension code.

const apiKey = process.env.GSB_TOKEN;
const SAFE_BROWSING_URL = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;

const THREAT_TYPES = [
  "MALWARE",
  "SOCIAL_ENGINEERING",
  "UNWANTED_SOFTWARE",
  "POTENTIALLY_HARMFUL_APPLICATION",
];

export default async function handler(req, res) {
  // Allow preflight requests from Chrome extensions
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Detector-Token");

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  // Validate shared secret when configured
  const expectedToken = process.env.DETECTOR_TOKEN;
  if (expectedToken) {
    const token = req.headers["x-detector-token"];
    if (token !== expectedToken) {
      return res.status(401).json({ error: "Unauthorized" });
    }
  }

  const { url } = req.body;

  // Validate URL: must be a string, within length limits, and http/https only.
  // This prevents quota exhaustion from garbage/oversized payloads and blocks
  // non-HTTP schemes (javascript:, ftp:, etc.) from being forwarded upstream.
  if (!url || typeof url !== "string" || url.length > 2048) {
    return res.status(400).json({ error: "url must be a non-empty string under 2048 characters" });
  }
  try {
    const parsedUrl = new URL(url);
    if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
      return res.status(400).json({ error: "url must use http or https scheme" });
    }
  } catch (_) {
    return res.status(400).json({ error: "url is not a valid URL" });
  }

  // ── Test URL simulation ──────────────────────────────────
  // Only active when ENABLE_TEST_SLUGS=true in Vercel environment variables.
  // Requests for URLs containing these slugs return fake threat data so the
  // full extension pipeline can be tested without needing a real malicious site.
  if (process.env.ENABLE_TEST_SLUGS === "true") {
    const TEST_SLUGS = {
      "pd-test-malware":   "MALWARE",
      "pd-test-phishing":  "SOCIAL_ENGINEERING",
      "pd-test-unwanted":  "UNWANTED_SOFTWARE",
      "pd-test-harmful":   "POTENTIALLY_HARMFUL_APPLICATION",
    };
    for (const [slug, threatType] of Object.entries(TEST_SLUGS)) {
      if (url.includes(slug)) {
        return res.status(200).json({
          matches: [{ threatType, platformType: "ANY_PLATFORM", threatEntryType: "URL" }],
        });
      }
    }
  }
  // ────────────────────────────────────────────────────────

  if (!apiKey) {
    return res.status(500).json({ error: "Token not configured" });
  }

  try {
    const response = await fetch(SAFE_BROWSING_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client: {
          clientId: "phishing-detector-extension",
          clientVersion: "1.0.0",
        },
        threatInfo: {
          threatTypes: THREAT_TYPES,
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }],
        },
      }),
    });

    if (!response.ok) {
      return res.status(502).json({ error: "Safe Browsing API error", status: response.status });
    }

    const data = await response.json();
    return res.status(200).json(data);
  } catch (err) {
    console.error("[proxy] fetch failed:", err);
    return res.status(502).json({ error: "Failed to reach Safe Browsing API" });
  }
}
