/**
 * IOC Normalization Utility
 * Converts raw IOC values into a consistent, lowercase, trimmed format.
 * This prevents duplicate records for the same indicator.
 *
 * Examples:
 *   "HTTP://Fake-Login.com/"  → "http://fake-login.com"  (url)
 *   "  Attack.COM  "          → "attack.com"             (domain)
 *   " 192.168.1.1 "           → "192.168.1.1"            (ip)
 */

const normalizeIOC = (value, type) => {
  if (!value || typeof value !== "string") return "";

  let normalized = value.trim().toLowerCase();

  switch (type) {
    case "url":
      // Remove trailing slash from URLs
      normalized = normalized.replace(/\/+$/, "");
      break;

    case "domain":
      // Strip any accidental http:// or https:// prefix from domains
      normalized = normalized
        .replace(/^https?:\/\//, "")
        .replace(/\/.*$/, "") // remove any path after the domain
        .replace(/\.$/, "");  // remove trailing dot
      break;

    case "ip":
      // Just trim — IP addresses should only need whitespace removed
      break;

    case "email":
      // Email addresses: lowercase is enough
      break;

    case "hash":
      // Hashes: lowercase is enough
      break;

    default:
      break;
  }

  return normalized;
};

module.exports = normalizeIOC;
