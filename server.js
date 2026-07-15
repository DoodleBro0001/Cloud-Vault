require('dotenv').config(); // Absolute top to ensure process.env variables load first
const express = require('express');
const multer = require('multer');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// ======================================
// SERVER & GLOBAL INITIALIZATION
// ======================================
const app = express(); 
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'fallback_secret_for_development';

// ======================================
// CORS SETUP (Handles all methods including DELETE and OPTIONS)
// ======================================
app.use(cors({
    origin: '*', 
    methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    optionsSuccessStatus: 204
}));

// ======================================
// INCREASED BODY SIZE LIMITS & STATIC ASSETS
// ======================================
app.use(express.json({ limit: '10gb' }));
app.use(express.urlencoded({ limit: '10gb', extended: true }));
app.use(express.static('public'));

// ======================================
// Upload Folder
// ======================================
const UPLOADS_DIR = path.join(__dirname, 'uploads');

if (!fs.existsSync(UPLOADS_DIR)) {
    fs.mkdirSync(UPLOADS_DIR);
}

// ======================================
// Database Schema Setup (SEQUENTIAL ORDER WITH FOREIGN KEYS ENABLED)
// ======================================
const db = new sqlite3.Database('./secure_vault_v2.db');

// Enable foreign key constraints in SQLite engine
db.run("PRAGMA foreign_keys = ON;");

db.serialize(() => {
    
    // 1. Create Upgraded Users Table First (Supports Metadata Tracing & Google OAuth)
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,                -- Acts as system-wide unique identifier/handle
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            personal_email TEXT UNIQUE NOT NULL,
            mobile_number TEXT NOT NULL,
            region_code TEXT NOT NULL,           -- e.g., "US", "LK", "GB"
            password_hash TEXT NULL,             -- Nullable if authenticating purely via Google OAuth
            google_id TEXT UNIQUE NULL,          -- Maps sub identifier tokens returned by Google Identity
            public_key TEXT NOT NULL,            -- Exported JWK Public String
            encrypted_private_key TEXT NOT NULL, -- Client-side wrapped Private Key String
            role TEXT DEFAULT 'user',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `, (err) => {
        if (err) {
            console.error("Error creating upgraded users table:", err.message);
        } else {
            console.log("1. Upgraded Users table verified.");
        }
    });

    // 2. Create Files Table Second (Ensures Foreign Key relation resolves cleanly)
    db.run(`
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            file_name TEXT,
            file_path TEXT,
            file_size INTEGER,
            wrapped_key TEXT,
            iv TEXT,
            uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    `, (err) => {
        if (err) {
            console.error("Error creating files table:", err.message);
        } else {
            console.log("2. Files table verified.");
        }
    });

    // 3. Create Shared Keys Table Third (Handles multi-recipient access mappings)
    db.run(`
        CREATE TABLE IF NOT EXISTS file_shares (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER,
            shared_with_user_id INTEGER,
            wrapped_key TEXT, -- The file's AES key, wrapped with the RECIPIENT's public RSA key
            shared_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE,
            FOREIGN KEY(shared_with_user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(file_id, shared_with_user_id) -- Prevents duplicate sharing mappings
        )
    `, (err) => {
        if (err) {
            console.error("Error creating file_shares table:", err.message);
        } else {
            console.log("3. File_shares table verified. Database schema completely coupled.");
        }
    });

}); // Correctly closes db.serialize

// ======================================
// Multer Setup - INCREASED FILE SIZE LIMIT
// ======================================
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, UPLOADS_DIR);
    },
    filename: function (req, file, cb) {
        const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + '.enc';
        cb(null, uniqueName);
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 10 * 1024 * 1024 * 1024 // 10 GB
    }
});

// ======================================
// JWT Middleware
// ======================================
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, error: 'Authorization header token missing' });
    }

    jwt.verify(token, SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({
                success: false,
                error: 'Invalid or expired token context structure'
            });
        }

        req.user = user;
        next();
    });
}

// ======================================
// UPGRADED REGISTER ROUTE WITH IDENTITY DATA & COMPLEXITY CONTROLS
// ======================================
app.post('/api/register', async (req, res) => {
    const { 
        username, first_name, last_name, personal_email, 
        mobile_number, region_code, password, 
        publicKey, encryptedPrivateKey 
    } = req.body;

    // 1. Completeness Verification Block
    if (!username || !first_name || !last_name || !personal_email || !mobile_number || !region_code || !password || !publicKey || !encryptedPrivateKey) {
        return res.status(400).json({
            success: false,
            error: 'Identity enrollment denied: Missing profiling metrics or core cryptographic primitives.'
        });
    }

    // 2. High-Protection Password Policy Rule (Min 10 chars, Multi-Class complexity)
    const passwordPolicyRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{10,}$/;
    if (!passwordPolicyRegex.test(password)) {
        return res.status(400).json({
            success: false,
            error: 'Security Complexity Error: Password must be at least 10 characters long, containing uppercase letters, lowercase letters, numbers, and specialized characters.'
        });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 12); // High iteration factor workload protection

        db.run(
            `INSERT INTO users (
                username, first_name, last_name, personal_email, 
                mobile_number, region_code, password_hash, public_key, encrypted_private_key
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                username.trim().toLowerCase(), 
                first_name.trim(), 
                last_name.trim(), 
                personal_email.trim().toLowerCase(), 
                mobile_number.trim(), 
                region_code.trim().toUpperCase(), 
                hashedPassword, 
                publicKey, 
                encryptedPrivateKey
            ],
            function(err) {
                if (err) {
                    console.error("Registration insertion trace breakdown:", err.message);
                    return res.status(500).json({
                        success: false,
                        error: 'Registration conflict: Username handle or personal email tracking index is already claimed inside this vault cluster.'
                    });
                }
                res.json({ success: true });
            }
        );
    } catch (e) {
        res.status(500).json({ success: false, error: 'Internal enrollment failure processing exception context: ' + e.message });
    }
});

// ======================================
// Login Route delivering Keys
// ======================================
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
         return res.status(400).json({ success: false, error: "Missing identity credentials" });
    }

    db.get(
        `SELECT * FROM users WHERE username = ?`,
        [username.trim()],
        async (err, user) => {
            if (err || !user) {
                return res.status(401).json({ success: false, error: "Invalid credentials mismatch" });
            }

            const validPassword = await bcrypt.compare(password, user.password_hash);
            if (!validPassword) {
                return res.status(401).json({ success: false, error: "Invalid credentials mismatch" });
            }

            const token = jwt.sign(
                { id: user.id, username: user.username, role: user.role },
                SECRET,
                { expiresIn: '24h' }
            );

            res.json({
                success: true,
                token,
                user: {
                    id: user.id,
                    username: user.username,
                    role: user.role,
                    publicKey: user.public_key,
                    encryptedPrivateKey: user.encrypted_private_key
                }
            });
        }
    );
});

// ======================================
// Upload File Endpoint 
// ======================================
app.post(
    '/api/upload',
    authenticateToken,
    upload.single('file'),
    (req, res) => {
        const { wrappedKey, iv, fileName } = req.body;

        if (!req.file) {
            return res.status(400).json({
                success: false,
                error: 'No binary payload stream uploaded'
            });
        }

        if (!wrappedKey || !iv || !fileName) {
            // Clean up downloaded file from disk if accompanying metadata parameters failed validation
            if (fs.existsSync(req.file.path)) {
                fs.unlinkSync(req.file.path);
            }
            return res.status(400).json({
                success: false,
                error: 'Missing cryptographic wrappedKey, iv indexing mapping, or destination fileName'
            });
        }

        const filePath = req.file.path;
        const fileSize = req.file.size;

        db.run(
            `INSERT INTO files 
             (user_id, file_name, wrapped_key, iv, file_path, file_size) 
             VALUES (?, ?, ?, ?, ?, ?)`,
            [
                req.user.id,
                fileName,
                wrappedKey,
                iv,
                filePath,
                fileSize
            ],
            function(err) {
                if (err) {
                    if (fs.existsSync(filePath)) {
                        fs.unlink(filePath, (unlinkErr) => {
                            if (unlinkErr) console.error('Failed to clean up file artifact block:', unlinkErr);
                        });
                    }

                    return res.status(500).json({
                        success: false,
                        error: 'Database mapping tracking exception: ' + err.message
                    });
                }

                res.json({
                    success: true,
                    fileId: this.lastID,
                    fileSize: fileSize
                });
            }
        );
    }
);

// ======================================
// Get User Files Route (Includes Owned & Shared Files)
// ======================================
app.get(
    '/api/files',
    authenticateToken,
    (req, res) => {
        const userId = req.user.id;

        const query = `
            SELECT f.id, f.file_name, f.file_size, f.uploaded_at, f.iv,
                   COALESCE(s.wrapped_key, f.wrapped_key) AS wrapped_key,
                   CASE WHEN f.user_id = ? THEN 'owner' ELSE 'shared' END AS access_type
            FROM files f
            LEFT JOIN file_shares s ON f.id = s.file_id AND s.shared_with_user_id = ?
            WHERE f.user_id = ? OR s.shared_with_user_id = ?
        `;

        db.all(query, [userId, userId, userId, userId], (err, rows) => {
            if (err) {
                console.error("Database selection error layout:", err.message);
                return res.status(500).json({ success: false, error: err.message });
            }

            const cleanRows = rows.map(row => ({
                id: row.id,
                file_name: row.file_name,
                wrapped_key: row.wrapped_key, // Correct fallback key for recipient or owner
                iv: row.iv,
                file_size: row.file_size,
                access_type: row.access_type,
                uploaded_at: row.uploaded_at || new Date().toISOString()
            }));

            res.json(cleanRows);
        });
    }
);

// ======================================
// Download File Endpoint (With Shared Mappings Validation)
// ======================================
app.get(
    '/api/download/:id',
    authenticateToken,
    (req, res) => {
        const userId = req.user.id;
        const fileId = req.params.id;

        const query = `
            SELECT f.id, f.file_name, f.file_path, f.file_size, f.iv,
                   COALESCE(s.wrapped_key, f.wrapped_key) AS wrapped_key
            FROM files f
            LEFT JOIN file_shares s ON f.id = s.file_id AND s.shared_with_user_id = ?
            WHERE f.id = ? AND (f.user_id = ? OR s.shared_with_user_id = ?)
        `;

        db.get(query, [userId, fileId, userId, userId], (err, row) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }

            if (!row) {
                return res.status(403).json({ error: 'Access denied or target transaction record matching index not found' });
            }

            if (!fs.existsSync(row.file_path)) {
                return res.status(404).json({ error: 'File missing from underlying persistent hardware volume' });
            }

            // Expose the targeted wrapped key variant via Response Headers for custom frontend decoupling if needed
            res.setHeader('X-Wrapped-Key', row.wrapped_key);
            res.setHeader('X-IV', row.iv);
            
            res.setHeader('Content-Type', 'application/octet-stream');
            res.setHeader(
                'Content-Disposition',
                `attachment; filename="${encodeURIComponent(row.file_name)}"`
            );

            const stream = fs.createReadStream(row.file_path);
            
            // Defensive catch array prevents runtime tracking drops from killing the node master thread
            stream.on('error', (streamErr) => {
                console.error('File storage volume tracking error sequence:', streamErr.message);
                if (!res.headersSent) {
                    res.status(500).json({ success: false, error: "Disk storage input reading fault exception." });
                }
            });

            stream.pipe(res);
        });
    }
);

// ======================================
// Get Recipient Public Key by Username
// ======================================
app.get('/api/users/public-key/:username', authenticateToken, (req, res) => {
    db.get(
        `SELECT id, public_key FROM users WHERE username = ?`,
        [req.params.username.trim()],
        (err, row) => {
            if (err) return res.status(500).json({ success: false, error: err.message });
            if (!row) return res.status(404).json({ success: false, error: 'User not found' });
            
            res.json({
                userId: row.id,
                publicKey: row.public_key
            });
        }
    );
});

// ======================================
// Share File (Save newly wrapped key)
// ======================================
app.post('/api/files/share', authenticateToken, (req, res) => {
    const { fileId, sharedWithUserId, wrappedKey } = req.body;

    if (!fileId || !sharedWithUserId || !wrappedKey) {
        return res.status(400).json({ success: false, error: 'Missing sharing parameters' });
    }

    // Verify the logged-in user actually owns the file they are trying to share
    db.get(`SELECT id FROM files WHERE id = ? AND user_id = ?`, [fileId, req.user.id], (err, row) => {
        if (err) return res.status(500).json({ success: false, error: err.message });
        if (!row) return res.status(403).json({ success: false, error: 'Unauthorized: You do not own this file' });

        db.run(
            `INSERT INTO file_shares (file_id, shared_with_user_id, wrapped_key) VALUES (?, ?, ?)`,
            [fileId, sharedWithUserId, wrappedKey],
            function(shareErr) {
                if (shareErr) return res.status(500).json({ success: false, error: 'File already shared with this user' });
                res.json({ success: true });
            }
        );
    });
});

// ======================================
// DELETE FILE Endpoint (Safe Async Operations)
// ======================================
app.delete(
    '/api/delete/:id',
    authenticateToken,
    (req, res) => {
        db.get(
            `SELECT * FROM files 
             WHERE id = ? 
             AND user_id = ?`,
            [req.params.id, req.user.id],
            (err, row) => {
                if (err) {
                    return res.status(500).json({ success: false, error: err.message });
                }

                if (!row) {
                    return res.status(404).json({ success: false, error: 'Target mapping asset element not found' });
                }

                if (fs.existsSync(row.file_path)) {
                    fs.unlink(row.file_path, (unlinkErr) => {
                        if (unlinkErr) {
                            console.error('Error removing file asset from disk structure:', unlinkErr.message);
                        }
                        executeDatabaseDelete();
                    });
                } else {
                    executeDatabaseDelete();
                }

                function executeDatabaseDelete() {
                    db.run(
                        `DELETE FROM files WHERE id = ?`,
                        [req.params.id],
                        function(dbErr) {
                            if (dbErr) {
                                return res.status(500).json({
                                    success: false,
                                    error: dbErr.message
                                });
                            }

                            res.json({
                                success: true
                            });
                        }
                    );
                }
            }
        );
    }
);

// ======================================
// Admin - Get All Users
// ======================================
app.get(
    '/api/admin/users',
    authenticateToken,
    (req, res) => {
        if (req.user.role !== 'admin') {
            return res.status(403).json({
                success: false,
                error: 'Access denied: Administrative execution privileges required'
            });
        }

        db.all(
            `SELECT id, username, role, created_at FROM users`,
            [],
            (err, rows) => {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }
                res.json(rows);
            }
        );
    }
);

// ======================================
// SERVER RUN TIME WORKLOAD START
// ======================================
const server = app.listen(PORT, () => {
    console.log(`Server running cleanly at http://localhost:${PORT}`);
    console.log('Max file upload size capacity verified: 10 GB');
});

server.timeout = 600000; // 10 minutes extended threshold limit