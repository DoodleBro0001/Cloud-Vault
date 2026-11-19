const fs = require("fs");
const path = "server.js";
let s = fs.readFileSync(path, "utf8").replace(/\r\n/g, "\n");

if (s.includes("ADMIN_REMOVE_ADMIN")) { console.log("server.js: already patched."); process.exit(0); }

const old = `app.delete('/api/admin/users/:id', authenticateToken, requireAdmin, (req, res) => {
    db.run(
        \`UPDATE users SET is_removed = 1, removed_at = CURRENT_TIMESTAMP WHERE id = ? AND role != 'admin'\`,
        [req.params.id],
        function (err) {
            if (err) return res.status(500).json({ success: false, error: 'DB error' });
            if (this.changes === 0) return res.status(404).json({ success: false, error: 'User not found or cannot remove admin' });
            // Also soft-delete all their files and block login
            db.run(\`UPDATE files SET is_deleted = 1, upload_status = 'OWNER_REMOVED' WHERE user_id = ? AND is_deleted = 0\`, [req.params.id]);
            logAudit({ userId: req.user.id, username: req.user.username, action: 'ADMIN_REMOVE_USER', ip: req.ip, userAgent: req.headers['user-agent'], status: 'SUCCESS' });
            res.json({ success: true });
        }
    );
});`;

if (!s.includes(old)) {
    console.log("server.js: exact route text not found - paste me your DELETE /api/admin/users/:id route.");
    process.exit(1);
}

const now = `app.delete('/api/admin/users/:id', authenticateToken, requireAdmin, async (req, res) => {
    const targetId = req.params.id;
    const { password } = req.body || {};

    try {
        const targetRs = await exec('SELECT id, username, role FROM users WHERE id = ?', [targetId]);
        if (!targetRs.rows.length) return res.status(404).json({ success: false, error: 'User not found' });
        const targetRole = targetRs.rows[0][2];

        if (targetRole === 'admin') {
            if (!password) return res.status(400).json({ success: false, error: 'Password confirmation is required to remove an admin account.' });

            const meRs = await exec('SELECT password_hash FROM users WHERE id = ?', [req.user.id]);
            if (!meRs.rows.length) return res.status(500).json({ success: false, error: 'DB error' });
            const ok = await bcrypt.compare(password, meRs.rows[0][0]);
            if (!ok) return res.status(401).json({ success: false, error: 'Incorrect password.' });

            const countRs = await exec("SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_removed = 0");
            if (Number(countRs.rows[0][0]) <= 1) {
                return res.status(400).json({ success: false, error: 'Cannot remove the last remaining admin account.' });
            }
        }

        const upd = await exec('UPDATE users SET is_removed = 1, removed_at = CURRENT_TIMESTAMP WHERE id = ?', [targetId]);
        if (!upd.rowsAffected) return res.status(404).json({ success: false, error: 'User not found' });

        // Also soft-delete all their files and block login
        await exec("UPDATE files SET is_deleted = 1, upload_status = 'OWNER_REMOVED' WHERE user_id = ? AND is_deleted = 0", [targetId]);
        logAudit({
            userId: req.user.id, username: req.user.username,
            action: targetRole === 'admin' ? 'ADMIN_REMOVE_ADMIN' : 'ADMIN_REMOVE_USER',
            ip: req.ip, userAgent: req.headers['user-agent'], status: 'SUCCESS'
        });
        res.json({ success: true });
    } catch (e) {
        console.error('Remove user error:', e.message);
        res.status(500).json({ success: false, error: 'DB error' });
    }
});`;

fs.writeFileSync(path, s.replace(old, now));
console.log("server.js: patched the DELETE /api/admin/users/:id route.");
