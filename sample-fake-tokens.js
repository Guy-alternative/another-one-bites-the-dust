// sample-fake-tokens.js
// ---------------------------------------------------------------------------------
// WARNING: These are FAKE, NON-FUNCTIONAL tokens intended only for testing scanners.
// They mimic real GitHub token prefixes/lengths so an AppSec secret scanner should flag them.
// ---------------------------------------------------------------------------------

// 1) Fine-grained Personal Access Token (prefix: github_pat_...)
// Pattern: github_pat_<22chars>_<59chars>  (example pattern used by scanners)
export const GITHUB_FINE_GRAINED_PAT = "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";

// 2) GitHub App installation / server token (example server-to-server / installation token prefix)
// Many GitHub-issued tokens use 3-letter prefixes (ghs_, ghu_, etc.). This is a fake example.
export const GITHUB_APP_TOKEN = "ghs_a1B2c3D4e5F6g7H8I9J0K1L2M3N4O5P6Q7R8S9";

// 3) GitHub OAuth Access Token (prefix: gho_...)
export const GITHUB_OAUTH_TOKEN = "gho_X1Y2Z3A4B5C6D7E8F9G0H1I2J3K4L5M6N7O8P9";

// 4) GitHub Personal Access Token (classic) (prefix: ghp_...)
export const GITHUB_PERSONAL_ACCESS_TOKEN = "ghp_ABCDEF1234567890abcdef1234567890abcd";

// Optional: a small helper that would inadvertently expose tokens if run (kept here to illustrate risky patterns)
export function printTokens() {
  // DON'T do this with real tokens — this is just to show where a leak would occur
  console.log("FINE_GRAINED_PAT:", GITHUB_FINE_GRAINED_PAT);
  console.log("APP_TOKEN:", GITHUB_APP_TOKEN);
  console.log("OAUTH_TOKEN:", GITHUB_OAUTH_TOKEN);
  console.log("CLASSIC_PAT:", GITHUB_PERSONAL_ACCESS_TOKEN);
}
