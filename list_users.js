const sqlite3 = require('sqlite3').verbose();

const db = new sqlite3.Database('./secure_vault_v2.db');

db.all(
    `SELECT id, username, personal_email, role FROM users`,
    [],
    (err, rows) => {
        if (err) {
            console.error("Database error:", err.message);
        } else {
            console.table(rows);
        }
        db.close();
    }
);