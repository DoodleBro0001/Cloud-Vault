const fs = require("fs");
const path = "public/admin.html";
let h = fs.readFileSync(path, "utf8").replace(/\r\n/g, "\n");

const siteRe = /removeUser\(\$\{u\.id\}, \x27\$\{(escapeHtml|escapeForInlineAttr)\(u\.username\)\}\x27, this\)/g;
const siteCount = (h.match(siteRe) || []).length;
h = h.replace(siteRe, "removeUser(${u.id}, \x27${$1(u.username)}\x27, \x27${u.role}\x27, this)");

const oldFnRe = /async function removeUser\(userId, username, buttonEl\) \{[\s\S]*?\n    \}\n/;
const newFn =
`async function removeUser(userId, username, role, buttonEl) {
        let password = null;
        if (role === \x27admin\x27) {
            if (!confirm(\`"\${username}" is an ADMIN account. Removing it deletes their admin access too. Continue?\`)) return;
            password = prompt(\x27Enter YOUR OWN admin password to confirm this removal:\x27);
            if (!password) return;
        } else {
            if (!confirm(\`Remove user "\${username}"? Their files will remain in the system logs.\`)) return;
        }
        const token = localStorage.getItem(\x27vaultAdminSessionToken\x27);
        try {
            const res = await fetch(\`/api/admin/users/\${userId}\`, {
                method: \x27DELETE\x27,
                headers: { \x27Authorization\x27: \`Bearer \${token}\`, \x27Content-Type\x27: \x27application/json\x27 },
                body: JSON.stringify(password ? { password } : {})
            });
            const data = await res.json();
            if (data.success) {
                const row = document.querySelector(\`tr[data-user-id="\${userId}"]\`);
                if (row) row.remove();
                const sb = document.getElementById(\x27sbuser-\x27 + userId);
                if (sb) sb.style.opacity = \x270.4\x27;
                if (_currentUserId == userId) showAdminSection(\x27dashboard\x27);
                alert(\`User "\${username}" removed.\`);
            } else alert(\x27Failed: \x27 + data.error);
        } catch (e) { alert(\x27Error: \x27 + e.message); }
    }
`;
if (!oldFnRe.test(h)) {
    if (h.includes("async function removeUser(userId, username, role, buttonEl)")) {
        console.log("admin.html: already patched.");
    } else {
        console.log("admin.html: removeUser() function not found - paste me that function.");
        process.exit(1);
    }
} else {
    h = h.replace(oldFnRe, newFn);
}
fs.writeFileSync(path, h);
console.log(`admin.html: updated ${siteCount} onclick site(s) and the removeUser() function.`);
