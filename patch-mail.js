const fs = require('fs');
let s = fs.readFileSync('server.js', 'utf8').replace(/\r\n/g, '\n');
if (s.includes('EMAIL_PASS = (process.env.EMAIL_PASS')) { console.log('Already patched.'); process.exit(0); }
const a = "require('dotenv').config();\n";
const b = "console.error('Email error:', emailErr.message);";
if (!s.includes(a) || !s.includes(b)) { console.log('Expected lines not found - tell me and I will give you another way.'); process.exit(1); }
s = s.replace(a, a +
  "process.env.EMAIL_USER = (process.env.EMAIL_USER || '').replace(/[\"'\\s]/g, '');\n" +
  "process.env.EMAIL_PASS = (process.env.EMAIL_PASS || '').replace(/[\"'\\s]/g, '');\n");
s = s.replace(b, "console.error('Email error:', emailErr.message, '| EMAIL_USER length:', (process.env.EMAIL_USER || '').length, '| EMAIL_PASS length:', (process.env.EMAIL_PASS || '').length);");
fs.writeFileSync('server.js', s);
console.log('Patched server.js');
