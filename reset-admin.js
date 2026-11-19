require('dotenv').config();
const bcrypt = require('bcryptjs');
const { client, exec } = require('./db');

const [username, password] = process.argv.slice(2);
if (!username || !password || password.length < 12) {
    console.error('Usage: node reset-admin.js <admin-username> <new-password (min 12 chars)>');
    process.exit(1);
}

(async () => {
    const hash = await bcrypt.hash(password, 12);
    const rs = await exec(
        "UPDATE users SET password_hash = ? WHERE lower(username) = lower(?) AND role = 'admin'",
        [hash, username.trim()]
    );
    console.log(rs.rowsAffected ? 'Admin password updated.' : 'No admin found with that username. Run: node list_users.js');
})().catch(e => { console.error('Error:', e.message); process.exitCode = 1; }).finally(() => client.close());
