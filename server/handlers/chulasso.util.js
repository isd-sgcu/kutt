// Pure, dependency-free helpers for the ChulaSSO integration so they can be
// unit-tested without loading env/db. See chulasso.util.test.js.

// Does the authenticated user's roles satisfy the allow-list?
// allowedCsv blank/empty => any authenticated Chula account is allowed.
function roleAllowed(roles, allowedCsv) {
  const allow = String(allowedCsv || "")
    .split(",")
    .map(r => r.trim().toLowerCase())
    .filter(Boolean);
  if (allow.length === 0) return true;
  const have = (Array.isArray(roles) ? roles : [])
    .map(r => String(r).trim().toLowerCase());
  return have.some(r => allow.includes(r));
}

module.exports = { roleAllowed };
