const fs = require('fs');
let s = fs.readFileSync('server.js', 'utf8').replace(/\r\n/g, '\n');
let changed = 0;

const dot = "require('dotenv').config();\n";
if (!s.includes("process.env.EMAIL_PASS = (process.env.EMAIL_PASS")) {
  if (!s.includes(dot)) { console.log('Expected line not found in server.js'); process.exit(1); }
  s = s.replace(dot, dot +
    "process.env.EMAIL_USER = (process.env.EMAIL_USER || '').replace(/[\"'\\s]/g, '');\n" +
    "process.env.EMAIL_PASS = (process.env.EMAIL_PASS || '').replace(/[\"'\\s]/g, '');\n");
  changed++;
}

const logOld = "console.error('Email error:', emailErr.message);";
if (s.includes(logOld)) {
  s = s.replace(logOld, "console.error('Email error:', emailErr.message, '| EMAIL_USER length:', (process.env.EMAIL_USER || '').length, '| EMAIL_PASS length:', (process.env.EMAIL_PASS || '').length);");
  changed++;
}

const msgOld = "error: 'Could not send the verification email. Check EMAIL_USER / EMAIL_PASS on the server and try again.'";
if (s.includes(msgOld)) {
  s = s.replace(msgOld, "error: `Could not send the verification email (${emailErr.code || 'error'} | EMAIL_USER ${(process.env.EMAIL_USER || '').length} chars, EMAIL_PASS ${(process.env.EMAIL_PASS || '').length} chars)`");
  changed++;
}

if (!changed) { console.log('Already up to date.'); process.exit(0); }
fs.writeFileSync('server.js', s);
console.log('Patched server.js (' + changed + ' change' + (changed > 1 ? 's' : '') + ')');
