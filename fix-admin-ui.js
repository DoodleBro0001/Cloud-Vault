const fs = require('fs');
let s = fs.readFileSync('public/admin.html', 'utf8');
const old = "document.getElementById('authPortal').style.display = 'flex';\n        document.getElementById('dashboardPanel').style.display = 'none';";
const now = "document.getElementById('authPortal').style.display = 'block';\n        document.body.style.alignItems = 'center';\n        document.getElementById('dashboardPanel').style.display = 'none';";
if (s.includes('authPortal\x27).style.display = \x27block\x27')) { console.log('Already patched.'); process.exit(0); }
if (!s.includes(old)) { console.log('Exact text not found - paste me the lines around terminateAdminSession() and I\x27ll adjust.'); process.exit(1); }
fs.writeFileSync('public/admin.html', s.replace(old, now));
console.log('Patched admin.html');
