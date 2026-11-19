const STATEMENTS = [
    `CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        first_name TEXT, last_name TEXT,
        personal_email TEXT UNIQUE,
        mobile_number TEXT, region_code TEXT,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        public_key TEXT, encrypted_private_key TEXT,
        is_verified INTEGER DEFAULT 0,
        verification_token TEXT,
        verification_token_expiry DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        is_removed INTEGER DEFAULT 0,
        removed_at DATETIME
    )`,
    `CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER, file_name TEXT, file_path TEXT,
        file_size INTEGER, wrapped_key TEXT, iv TEXT,
        is_deleted INTEGER DEFAULT 0,
        upload_status TEXT DEFAULT 'ACTIVE',
        sha256 TEXT,
        scan_status TEXT DEFAULT 'PENDING',
        scan_result TEXT, scanned_at DATETIME,
        threat_level TEXT DEFAULT NULL,
        uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )`,
    `CREATE TABLE IF NOT EXISTS file_shares (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id INTEGER,
        shared_with_user_id INTEGER,
        shared_by_user_id INTEGER,
        wrapped_key TEXT,
        is_reshared INTEGER DEFAULT 0,
        shared_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE,
        FOREIGN KEY(shared_with_user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(file_id, shared_with_user_id)
    )`,
    `CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER, username TEXT, action TEXT,
        file_id INTEGER, original_filename TEXT,
        ip_address TEXT, user_agent TEXT, status TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`,
    // Encrypted file bytes live here (serverless hosts have no persistent disk).
    `CREATE TABLE IF NOT EXISTS file_blobs (
        path TEXT PRIMARY KEY,
        data BLOB NOT NULL
    )`
];

async function initSchema(client) {
    await client.batch(STATEMENTS, 'write');
}

module.exports = { initSchema };
