// Vercel serverless function - Safe Browsing v4 threatListUpdates:fetch proxy
// Downloads hash prefix lists for local pre-filtering, keeping API key server-side.

const apiKey = process.env.GSB_TOKEN;
const UPDATE_URL = `https://safebrowsing.googleapis.com/v4/threatListUpdates:fetch?key=${apiKey}`;

export default async function handler(req, res) {
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

  if (!apiKey) {
    return res.status(500).json({ error: "Token not configured" });
  }

  const { listUpdateRequests } = req.body || {};
  if (!Array.isArray(listUpdateRequests) || listUpdateRequests.length === 0) {
    return res.status(400).json({ error: "listUpdateRequests must be a non-empty array" });
  }

  try {
    const response = await fetch(UPDATE_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client: {
          clientId: "vanta-security-extension",
          clientVersion: "1.0.0",
        },
        listUpdateRequests,
      }),
    });

    if (!response.ok) {
      return res.status(502).json({ error: "Safe Browsing API error", status: response.status });
    }

    const data = await response.json();
    return res.status(200).json(data);
  } catch (err) {
    console.error("[update-proxy] fetch failed:", err);
    return res.status(502).json({ error: "Failed to reach Safe Browsing API" });
  }
}
