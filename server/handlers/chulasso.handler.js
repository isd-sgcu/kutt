// ChulaSSO 2.0 authentication (custom ticket flow — NOT OIDC).
// Docs: https://account.it.chula.ac.th/html/docs
//   1. Redirect the browser to {BASE}/login?service={callback}&app_id={id}
//   2. ChulaSSO redirects back to {callback}?ticket={id}
//   3. Validate server-side: POST {BASE}/serviceValidation with headers
//      DeeAppId / DeeAppSecret / DeeTicket -> JSON profile { email, roles, ... }
// On success we find-or-create a verified Kutt user (mirrors the OIDC handler
// in passport.js) and issue the normal Kutt session cookie.
const bcrypt = require("bcryptjs");

const { roleAllowed } = require("./chulasso.util");
const query = require("../queries");
const utils = require("../utils");
const env = require("../env");

const CustomError = utils.CustomError;

// Step 1 — send the browser to ChulaSSO with our callback as `service`.
async function start(req, res) {
  const params = new URLSearchParams({
    service: utils.getSiteURL() + "/login/chulasso",
    app_id: env.CHULASSO_APP_ID,
    serviceName: env.CHULASSO_SERVICE_NAME || env.SITE_NAME,
  });
  res.redirect(`${env.CHULASSO_BASE}/login?${params.toString()}`);
}

// Step 3 — validate the returned ticket and log the user in.
async function callback(req, res) {
  const ticket = req.query.ticket;
  if (!ticket) {
    throw new CustomError("ChulaSSO did not return a ticket.", 400);
  }

  const response = await fetch(`${env.CHULASSO_BASE}/serviceValidation`, {
    method: "POST",
    headers: {
      DeeAppId: env.CHULASSO_APP_ID,
      DeeAppSecret: env.CHULASSO_APP_SECRET,
      DeeTicket: String(ticket),
    },
  });

  if (!response.ok) {
    throw new CustomError("ChulaSSO ticket validation failed.", 401);
  }

  const profile = await response.json();
  const email = profile && profile.email;
  if (!email) {
    throw new CustomError("ChulaSSO profile did not include an email.", 400);
  }

  if (!roleAllowed(profile.roles, env.CHULASSO_ALLOWED_ROLES)) {
    throw new CustomError("Your Chula account is not permitted to use this service.", 403);
  }

  let user = await query.user.find({ email });

  // First login for this account: create it, pre-verified (no email/password flow).
  if (!user) {
    const salt = await bcrypt.genSalt(12);
    const password = await bcrypt.hash(utils.generateRandomPassword(), salt);
    const created = await query.user.add({ email, password });
    user = await query.user.update(created, {
      verified: true,
      verification_token: null,
      verification_expires: null,
    });
  }

  if (user.banned) {
    throw new CustomError("You're banned from using this website.", 403);
  }

  const token = utils.signToken(user);
  utils.setToken(res, token);
  res.redirect("/");
}

module.exports = { start, callback, roleAllowed };
