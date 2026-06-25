// Run: node server/handlers/chulasso.util.test.js
const assert = require("node:assert");
const { roleAllowed } = require("./chulasso.util");

// empty allow-list => any authenticated account is allowed
assert.strictEqual(roleAllowed(["student"], ""), true);
assert.strictEqual(roleAllowed([], ""), true);
assert.strictEqual(roleAllowed(undefined, ""), true);

// allow-list set => must intersect
assert.strictEqual(roleAllowed(["student"], "student,faculty"), true);
assert.strictEqual(roleAllowed(["faculty"], "student,faculty"), true);
assert.strictEqual(roleAllowed(["alumni"], "student,faculty"), false);
assert.strictEqual(roleAllowed([], "student"), false);
assert.strictEqual(roleAllowed(undefined, "student"), false);

// case + whitespace tolerant
assert.strictEqual(roleAllowed(["Student"], " student "), true);
assert.strictEqual(roleAllowed(["STUDENT"], "student"), true);

console.log("chulasso.util ok");
