require('dotenv').config();
const { client, exec } = require('./db');

(async () => {
    try {
        const rs = await exec('SELECT id, username, personal_email, role FROM users');
        console.table(rs.rows.map(r => ({ id: r[0], username: r[1], personal_email: r[2], role: r[3] })));
    } catch (e) {
        console.error('Database error:', e.message);
    } finally {
        client.close();
    }
})();
