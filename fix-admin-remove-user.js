const fs = require("fs");
const path = "public/admin.html";
let s = fs.readFileSync(path, "utf8").replace(/\r\n/g, "\n");

if (s.includes("escapeForInlineAttr")) { console.log("Already patched."); process.exit(0); }

const re = /function escapeHtml\(value\) \{[\s\S]*?\n    \}\n/;
const m = s.match(re);
if (!m) { console.log("escapeHtml function not found - paste me more context."); process.exit(1); }

const helper = m[0] +
  "\n    // Safe inside both a single-quoted JS string and a double-quoted HTML attribute.\n" +
  "    function escapeForInlineAttr(value) {\n" +
  "        return String(value === null || value === undefined ? \x27\x27 : value)\n" +
  "            .replace(/\\\\/g, \x27\\\\\\\\\x27)\n" +
  "            .replace(/\x27/g, \"\\\\\x27\")\n" +
  "            .replace(/\"/g, \x27&quot;\x27)\n" +
  "            .replace(/</g, \x27&lt;\x27)\n" +
  "            .replace(/>/g, \x27&gt;\x27);\n" +
  "    }\n";
s = s.replace(re, helper);

const siteRe = /removeUser\(\$\{u\.id\}, \x27\$\{escapeHtml\(u\.username\)\}\x27/g;
const count = (s.match(siteRe) || []).length;
s = s.replace(siteRe, "removeUser(${u.id}, \x27${escapeForInlineAttr(u.username)}\x27");

fs.writeFileSync(path, s);
console.log("Patched admin.html, fixed " + count + " onclick site(s).");
