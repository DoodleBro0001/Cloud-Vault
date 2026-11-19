// Usage: node create_admin.js <username> <password> [email]
require('dotenv').config();
const bcrypt = require('bcryptjs');
const { client, exec } = require('./db');
const { initSchema } = require('./schema');

const [username, password, email = 'admin@cloudvault.com'] = process.argv.slice(2);

if (!username || !password || password.length < 12) {
    console.error('Usage: node create_admin.js <username> <password (min 12 chars)> [email]');
    process.exit(1);
}

(async () => {
    try {
        await initSchema(client);
        const hash = await bcrypt.hash(password, 12);
        const rs = await exec(
            `INSERT INTO users (username, first_name, last_name, personal_email, mobile_number, region_code, password_hash, role, is_verified)
             VALUES (?, 'Admin', 'User', ?, '0000000000', 'LK', ?, 'admin', 1)`,
            [username.trim().toLowerCase(), email.trim().toLowerCase(), hash]
        );
        console.log('✅ Admin created successfully! ID:', Number(rs.lastInsertRowid));
    } catch (e) {
        console.error('Error:', e.message);
        process.exitCode = 1;
    } finally {
        client.close();
    }
})();
