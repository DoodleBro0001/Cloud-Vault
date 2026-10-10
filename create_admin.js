const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./secure_vault_v2.db');

bcrypt.hash('Admin@1234', 12).then(hash => {
    db.run(
        `INSERT INTO users (username, first_name, last_name, personal_email, mobile_number, region_code, password_hash, role, is_verified)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        ['admin', 'Admin', 'User', 'admin@cloudvault.com', '0000000000', 'LK', hash, 'admin', 1],
        function(err) {
            if (err) console.error('Error:', err.message);
            else console.log('✅ Admin created successfully! ID:', this.lastID);
            db.close();
        }
    );
});