require('dotenv').config();
const express = require('express');
const multer = require('multer');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { execFile } = require('child_process');

const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'http://localhost:3000';

if (!SECRET || SECRET.length < 32) {
    console.error('FATAL: JWT_SECRET is missing or too short (min 32 chars).');
    process.exit(1);
}

const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

transporter.verify((error) => {
    if (error) console.error('❌ Email server error:', error);
    else console.log('✅ Email server ready');
});

const app = express();

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://unpkg.com", "https://cdn.jsdelivr.net"],
            scriptSrcAttr: ["'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "blob:"],
            connectSrc: ["'self'", "blob:"]
        }
    }
}));

app.use(cors({
    origin: ALLOWED_ORIGIN,
    methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    exposedHeaders: ['X-Wrapped-Key', 'X-IV', 'Content-Disposition'],
    optionsSuccessStatus: 204
}));

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ limit: '2mb', extended: true }));
app.use((req, res, next) => { res.setTimeout(1800000); next(); });

const PUBLIC_DIR = path.join(__dirname, 'Public');
if (fs.existsSync(PUBLIC_DIR)) app.use(express.static(PUBLIC_DIR));

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, max: 20,
    standardHeaders: true, legacyHeaders: false,
    message: { success: false, error: 'Too many login attempts. Try again later.' }
});

const uploadLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, max: 60,
    standardHeaders: true, legacyHeaders: false,
    message: { success: false, error: 'Too many uploads. Try again later.' }
});

app.get('/', (req, res) => {
    const indexPath = path.join(PUBLIC_DIR, 'index.html');
    if (fs.existsSync(indexPath)) res.sendFile(indexPath);
    else res.status(404).send('Frontend not found.');
});

const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const db = new sqlite3.Database('./secure_vault_v2.db');
db.run('PRAGMA foreign_keys = ON;');

function addColumnIfMissing(table, columnDef) {
    db.run(`ALTER TABLE ${table} ADD COLUMN ${columnDef}`, (err) => {
        if (err && !/duplicate column name/i.test(err.message))
            console.error(`Migration error:`, err.message);
    });
}

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
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
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER, file_name TEXT, file_path TEXT,
        file_size INTEGER, wrapped_key TEXT, iv TEXT,
        is_deleted INTEGER DEFAULT 0,
        upload_status TEXT DEFAULT 'ACTIVE',
        sha256 TEXT,
        scan_status TEXT DEFAULT 'PENDING',
        scan_result TEXT, scanned_at DATETIME,
        uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS file_shares (
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
    )`);
    addColumnIfMissing('file_shares', 'shared_by_user_id INTEGER');
    addColumnIfMissing('file_shares', 'is_reshared INTEGER DEFAULT 0');

    db.run(`CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER, username TEXT, action TEXT,
        file_id INTEGER, original_filename TEXT,
        ip_address TEXT, user_agent TEXT, status TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    addColumnIfMissing('users', 'verification_token_expiry DATETIME');
    addColumnIfMissing('files', 'threat_level TEXT DEFAULT NULL');
    addColumnIfMissing('users', 'is_removed INTEGER DEFAULT 0');
    addColumnIfMissing('users', 'removed_at DATETIME');
});

function logAudit({ userId, username, action, fileId, filename, ip, userAgent, status }) {
    db.run(
        `INSERT INTO audit_logs (user_id, username, action, file_id, original_filename, ip_address, user_agent, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [userId||null, username||null, action, fileId||null, filename||null, ip||null, userAgent||null, status]
    );
}

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, error: 'Authorization token missing' });
    jwt.verify(token, SECRET, (err, user) => {
        if (err) return res.status(403).json({ success: false, error: 'Invalid or expired token' });
        req.user = user;
        next();
    });
}

function requireAdmin(req, res, next) {
    if (!req.user || req.user.role !== 'admin')
        return res.status(403).json({ success: false, error: 'Admin access required' });
    next();
}

const MAX_UPLOAD_BYTES = 10 * 1024 * 1024 * 1024; // 10GB

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        try {
            if (!req.user || !req.user.id) return cb(new Error('User authentication missing'));
            const userFolder = path.join(UPLOADS_DIR, `user_${req.user.id}`);
            if (!fs.existsSync(userFolder)) fs.mkdirSync(userFolder, { recursive: true });
            cb(null, userFolder);
        } catch (err) { cb(err); }
    },
    filename: function (req, file, cb) { cb(null, crypto.randomUUID() + '.enc'); }
});

const upload = multer({ storage, limits: { fileSize: MAX_UPLOAD_BYTES } });

// ======================================
// REGISTER
// ======================================
function ensureUserFolder(userId) {
    const folder = path.join(UPLOADS_DIR, `user_${userId}`);
    if (!fs.existsSync(folder)) fs.mkdirSync(folder, { recursive: true });
    return folder;
}

app.post('/api/register', async (req, res) => {
    const { username, first_name, last_name, personal_email, mobile_number, region_code, password, publicKey, encryptedPrivateKey } = req.body;

    if (!username || !first_name || !last_name || !personal_email || !mobile_number || !region_code || !password || !publicKey || !encryptedPrivateKey)
        return res.status(400).json({ success: false, error: 'Missing required registration fields.' });

    try {
        const hashedPassword = await bcrypt.hash(password, 12);
        const verificationCode = crypto.randomBytes(3).toString('hex').toUpperCase();
        const verificationExpiry = new Date(Date.now() + 15 * 60 * 1000).toISOString();
        const cleanEmail = personal_email.trim().toLowerCase();
        const cleanEncryptedPrivateKey = typeof encryptedPrivateKey === 'object' ? JSON.stringify(encryptedPrivateKey) : String(encryptedPrivateKey).trim();
        const cleanPublicKey = typeof publicKey === 'object' ? JSON.stringify(publicKey) : String(publicKey).trim();

        db.run(
            `INSERT INTO users (username, first_name, last_name, personal_email, mobile_number, region_code, password_hash, role, public_key, encrypted_private_key, is_verified, verification_token, verification_token_expiry)
             VALUES (?, ?, ?, ?, ?, ?, ?, 'user', ?, ?, 0, ?, ?)`,
            [username.trim().toLowerCase(), first_name.trim(), last_name.trim(), cleanEmail, mobile_number.trim(), region_code.trim().toUpperCase(), hashedPassword, cleanPublicKey, cleanEncryptedPrivateKey, verificationCode, verificationExpiry],
            async function (err) {
                if (err) return res.status(409).json({ success: false, error: 'Username or email is already registered.' });
                try {
                    await transporter.sendMail({
                        from: `"Cloud Vault Security" <${process.env.EMAIL_USER}>`,
                        to: cleanEmail,
                        subject: 'Your Cloud Vault Verification Code',
                        html: `<div style="font-family:Arial,sans-serif;padding:20px;"><h2>Welcome to Cloud Vault!</h2><p>Your verification code is:</p><div style="font-size:32px;font-weight:bold;letter-spacing:5px;color:#2563eb;margin:20px 0;">${verificationCode}</div><p>This code expires in <strong>15 minutes</strong>.</p></div>`
                    });
                } catch (emailErr) { console.error('Email error:', emailErr.message); }
                // Pre-create user folder so it exists before first upload
                ensureUserFolder(this.lastID);
                res.json({ success: true, email: cleanEmail, message: 'Registration initiated! Please check your email for the verification code.' });
            }
        );
    } catch (e) {
        res.status(500).json({ success: false, error: 'Internal server error during registration.' });
    }
});

// ======================================
// VERIFY CODE
// ======================================
app.post('/api/verify-code', (req, res) => {
    const { email, code } = req.body;
    if (!email || !code) return res.status(400).json({ success: false, error: 'Email and code required.' });

    const cleanEmail = email.trim().toLowerCase();
    const cleanCode = code.trim().toUpperCase();

    db.get(
        `SELECT id, verification_token_expiry FROM users WHERE personal_email = ? AND verification_token = ? AND is_verified = 0`,
        [cleanEmail, cleanCode],
        (err, user) => {
            if (err) return res.status(500).json({ success: false, error: 'Database error.' });
            if (!user) return res.status(400).json({ success: false, error: 'Invalid verification code or email.' });
            if (user.verification_token_expiry && new Date() > new Date(user.verification_token_expiry))
                return res.status(400).json({ success: false, error: 'Verification code expired. Please register again.' });
            db.run(`UPDATE users SET is_verified = 1, verification_token = NULL, verification_token_expiry = NULL WHERE id = ?`, [user.id], (updateErr) => {
                if (updateErr) return res.status(500).json({ success: false, error: 'Failed to activate account.' });
                res.json({ success: true, message: 'Account verified! You can now log in.' });
            });
        }
    );
});

// ======================================
// LOGIN
// ======================================
app.post('/api/login', loginLimiter, (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ success: false, error: 'Missing credentials' });

    db.get(`SELECT * FROM users WHERE username = ?`, [username.trim().toLowerCase()], async (err, user) => {
        const genericError = () => res.status(401).json({ success: false, error: 'Invalid credentials' });
        if (err || !user) return genericError();
        if (!user.password_hash) return res.status(401).json({ success: false, error: 'Invalid login method.' });

        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) return genericError();

        if (user.is_verified === 0)
            return res.status(403).json({ success: false, error: 'Account not verified. Please check your email.' });
        if (user.is_removed === 1)
            return res.status(403).json({ success: false, error: 'This account has been suspended by an administrator.' });

        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            SECRET,
            { expiresIn: '24h' }
        );

        ensureUserFolder(user.id);
        logAudit({ userId: user.id, username: user.username, action: 'LOGIN', ip: req.ip, userAgent: req.headers['user-agent'], status: 'SUCCESS' });

        res.json({
            success: true, token,
            user: {
                id: user.id,
                username: user.username,
                role: user.role,
                publicKey: user.public_key,
                encryptedPrivateKey: user.encrypted_private_key ? user.encrypted_private_key.trim() : null
            }
        });
    });
});

// ======================================
// GET OWN PROFILE
// ======================================
app.get('/api/profile', authenticateToken, (req, res) => {
    db.get(
        `SELECT id, username, first_name, last_name, personal_email, region_code, role, created_at FROM users WHERE id = ?`,
        [req.user.id],
        (err, row) => {
            if (err) return res.status(500).json({ success: false, error: 'Database error' });
            if (!row) return res.status(404).json({ success: false, error: 'User not found' });
            res.json({ success: true, user: row });
        }
    );
});

// ======================================
// UPLOAD ENCRYPTED FILE
// ======================================
app.post('/api/upload', authenticateToken, uploadLimiter, upload.single('file'), (req, res) => {
    const { wrappedKey, iv, fileName } = req.body;
    if (!req.file) return res.status(400).json({ success: false, error: 'No file uploaded' });
    if (!wrappedKey || !iv || !fileName) {
        if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
        return res.status(400).json({ success: false, error: 'Missing wrappedKey, iv, or fileName' });
    }

    const filePath = req.file.path;
    const fileSize = req.file.size;
    const storedFilename = path.basename(req.file.path);
    const folderName = path.basename(path.dirname(req.file.path));

    const hash = crypto.createHash('sha256');
    hash.update(fs.readFileSync(filePath));
    const sha256 = hash.digest('hex');

    db.run(
        `INSERT INTO files (user_id, file_name, file_path, file_size, sha256, wrapped_key, iv, scan_status) VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING')`,
        [req.user.id, fileName, filePath, fileSize, sha256, wrappedKey, iv],
        function (err) {
            if (err) {
                if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
                return res.status(500).json({ success: false, error: 'Database error saving file.' });
            }
            const fileId = this.lastID;
            logAudit({ userId: req.user.id, username: req.user.username, action: 'UPLOAD', fileId, filename: fileName, ip: req.ip, userAgent: req.headers['user-agent'], status: 'SUCCESS' });
            res.json({ success: true, fileId, fileSize, folder: folderName, storedFilename });
            scanFile(fileId, filePath).catch((e) => console.error('Auto-scan failed:', e.message));
        }
    );
});

// ======================================
// GET FILES LIST
// ======================================
app.get('/api/files', authenticateToken, (req, res) => {
    const userId = req.user.id;
    db.all(
        `SELECT f.id, f.file_name, f.file_size, f.iv, f.uploaded_at, f.scan_status,
                CASE
                    WHEN f.user_id = ? THEN f.wrapped_key
                    ELSE (SELECT fs.wrapped_key FROM file_shares fs
                          WHERE fs.file_id = f.id AND fs.shared_with_user_id = ? LIMIT 1)
                END AS wrapped_key,
                CASE WHEN f.user_id = ? THEN 'owner' ELSE 'shared' END AS access_type
         FROM files f
         WHERE f.is_deleted = 0
           AND (
               f.user_id = ?
               OR EXISTS (
                   SELECT 1 FROM file_shares fs2
                   WHERE fs2.file_id = f.id
                     AND fs2.shared_with_user_id = ?
               )
           )
         ORDER BY f.uploaded_at DESC`,
        [userId, userId, userId, userId, userId],
        (err, rows) => {
            if (err) return res.status(500).json({ success: false, error: 'Database error retrieving files' });
            res.json(rows || []);
        }
    );
});

// ======================================
// DOWNLOAD FILE
// ======================================
app.get('/api/download/:id', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const fileId = req.params.id;
    db.get(
        `SELECT f.id, f.file_name, f.file_path, f.file_size, f.iv, f.scan_status,
                CASE
                    WHEN f.user_id = ? THEN f.wrapped_key
                    ELSE (SELECT fs.wrapped_key FROM file_shares fs WHERE fs.file_id = f.id AND fs.shared_with_user_id = ?)
                END AS wrapped_key
         FROM files f
         WHERE f.id = ?
           AND (f.user_id = ? OR EXISTS (SELECT 1 FROM file_shares fs2 WHERE fs2.file_id = f.id AND fs2.shared_with_user_id = ?))
           AND (f.is_deleted IS NULL OR f.is_deleted = 0)`,
        [userId, userId, fileId, userId, userId],
        (err, row) => {
            if (err) return res.status(500).json({ success: false, error: 'Database error' });
            if (!row) return res.status(404).json({ success: false, error: 'File not found or access denied' });
            if (row.scan_status === 'INFECTED') return res.status(423).json({ success: false, error: 'File is flagged and blocked.' });
            if (!fs.existsSync(row.file_path)) return res.status(404).json({ success: false, error: 'File missing from storage.' });

            res.setHeader('X-Wrapped-Key', row.wrapped_key);
            res.setHeader('X-IV', row.iv);
            res.setHeader('Content-Type', 'application/octet-stream');
            res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(row.file_name)}"`);

            const stream = fs.createReadStream(row.file_path);
            stream.on('error', () => { if (!res.headersSent) res.status(500).json({ success: false, error: 'Error reading file.' }); });
            logAudit({ userId, username: req.user.username, action: 'DOWNLOAD', fileId, filename: row.file_name, ip: req.ip, userAgent: req.headers['user-agent'], status: 'SUCCESS' });
            stream.pipe(res);
        }
    );
});

// ======================================
// GET FILES I SHARED (sent)
// ======================================
app.get('/api/shares/sent', authenticateToken, (req, res) => {
    db.all(
        `SELECT fs.id AS share_id, fs.file_id, fs.shared_at, fs.is_reshared,
                f.file_name, f.file_size, f.uploaded_at, f.scan_status,
                u.username AS shared_with_username, u.personal_email AS shared_with_email,
                sb.username AS shared_by_username
         FROM file_shares fs
         JOIN files f ON fs.file_id = f.id
         JOIN users u ON fs.shared_with_user_id = u.id
         LEFT JOIN users sb ON fs.shared_by_user_id = sb.id
         WHERE fs.shared_by_user_id = ? AND (f.is_deleted IS NULL OR f.is_deleted = 0)
         ORDER BY fs.shared_at DESC`,
        [req.user.id],
        (err, rows) => {
            if (err) return res.status(500).json({ success: false, error: 'Database error' });
            res.json(rows || []);
        }
    );
});

// ======================================
// GET FILES SHARED WITH ME (received)
// ======================================
app.get('/api/shares/received', authenticateToken, (req, res) => {
    db.all(
        `SELECT fs.id AS share_id, fs.file_id, fs.shared_at, fs.wrapped_key, fs.is_reshared,
                f.file_name, f.file_size, f.iv, f.uploaded_at, f.scan_status,
                owner.username AS owner_username, owner.personal_email AS owner_email,
                sender.username AS shared_by_username
         FROM file_shares fs
         JOIN files f ON fs.file_id = f.id
         JOIN users owner ON f.user_id = owner.id
         LEFT JOIN users sender ON fs.shared_by_user_id = sender.id
         WHERE fs.shared_with_user_id = ? AND (f.is_deleted IS NULL OR f.is_deleted = 0)
         ORDER BY fs.shared_at DESC`,
        [req.user.id],
        (err, rows) => {
            if (err) return res.status(500).json({ success: false, error: 'Database error' });
            res.json(rows || []);
        }
    );
});

// ======================================
// GET RECIPIENT PUBLIC KEY
// ======================================
app.get('/api/users/public-key/:username', authenticateToken, (req, res) => {
    db.get(
        `SELECT id, public_key FROM users WHERE username = ?`,
        [req.params.username.trim().toLowerCase()],
        (err, row) => {
            if (err) return res.status(500).json({ success: false, error: 'Database error' });
            if (!row) return res.status(404).json({ success: false, error: 'User not found' });
            res.json({ userId: row.id, publicKey: row.public_key });
        }
    );
});

// ======================================
// SAVE SHARED WRAPPED KEY
// ======================================
app.post('/api/files/share', authenticateToken, (req, res) => {
    const { fileId, sharedWithUserId, wrappedKey } = req.body;
    if (!fileId || !sharedWithUserId || !wrappedKey)
        return res.status(400).json({ success: false, error: 'Missing parameters for sharing' });

    if (Number(sharedWithUserId) === Number(req.user.id))
        return res.status(400).json({ success: false, error: 'You cannot share a file with yourself.' });

    // Check if recipient already received this file (prevent re-sharing to same user)
    db.get(
        `SELECT id FROM file_shares WHERE file_id = ? AND shared_with_user_id = ?`,
        [fileId, sharedWithUserId],
        (checkErr, existing) => {
            if (existing) return res.status(400).json({ success: false, error: 'This file is already shared with that user.' });

            // Determine if requester is the original owner or a resharer
            db.get(
                `SELECT f.id, f.user_id FROM files f
                 WHERE f.id = ? AND (
                     f.user_id = ?
                     OR EXISTS (SELECT 1 FROM file_shares fs WHERE fs.file_id = f.id AND fs.shared_with_user_id = ?)
                 )`,
                [fileId, req.user.id, req.user.id],
                (err, row) => {
                    if (err) return res.status(500).json({ success: false, error: 'Database error' });
                    if (!row) return res.status(403).json({ success: false, error: 'You do not have access to this file' });

                    const isReshared = row.user_id !== req.user.id ? 1 : 0;

                    db.run(
                        `INSERT INTO file_shares (file_id, shared_with_user_id, shared_by_user_id, wrapped_key, is_reshared)
                         VALUES (?, ?, ?, ?, ?)`,
                        [fileId, sharedWithUserId, req.user.id, wrappedKey, isReshared],
                        function (shareErr) {
                            if (shareErr) return res.status(500).json({ success: false, error: 'Database error saving share' });
                            logAudit({ userId: req.user.id, username: req.user.username, action: isReshared ? 'RESHARE' : 'SHARE', fileId, ip: req.ip, userAgent: req.headers['user-agent'], status: 'SUCCESS' });
                            res.json({ success: true, isReshared });
                        }
                    );
                }
            );
        }
    );
});

// ======================================
// HARD DELETE (user — removes disk file, marks DB, keeps admin log)
// ======================================
app.delete('/api/delete/:id', authenticateToken, (req, res) => {
    const fileId = req.params.id;
    const userId = req.user.id;
    db.get(`SELECT file_path, file_name FROM files WHERE id = ? AND user_id = ? AND (is_deleted IS NULL OR is_deleted = 0)`, [fileId, userId], (err, f) => {
        if (err) return res.status(500).json({ success: false, error: 'Database error' });
        if (!f) return res.status(404).json({ success: false, error: 'File not found or unauthorized' });
        // Remove physical file from disk
        try { if (fs.existsSync(f.file_path)) fs.unlinkSync(f.file_path); } catch (e) { console.error('Disk delete error:', e.message); }
        // Mark deleted in DB — keep row so admin can see deletion log
        db.run(
            `UPDATE files SET is_deleted = 1, upload_status = 'DELETED_BY_USER', file_path = '' WHERE id = ?`,
            [fileId],
            function (err2) {
                if (err2) return res.status(500).json({ success: false, error: 'Database error' });
                // Remove all share records for this file
                db.run(`DELETE FROM file_shares WHERE file_id = ?`, [fileId]);
                logAudit({ userId, username: req.user.username, action: 'DELETE', fileId, filename: f.file_name, ip: req.ip, userAgent: req.headers['user-agent'], status: 'SUCCESS' });
                res.json({ success: true, message: 'File permanently deleted' });
            }
        );
    });
});

// ======================================
// REMOVE MY SHARE ACCESS (receiver only)
// ======================================
app.delete('/api/shares/:fileId', authenticateToken, (req, res) => {
    const fileId = req.params.fileId;
    const userId = req.user.id;
    db.run(
        `DELETE FROM file_shares WHERE file_id = ? AND shared_with_user_id = ?`,
        [fileId, userId],
        function (err) {
            if (err) return res.status(500).json({ success: false, error: 'Database error' });
            if (this.changes === 0) return res.status(404).json({ success: false, error: 'Share record not found' });
            logAudit({ userId, username: req.user.username, action: 'REMOVE_SHARE_ACCESS', fileId, ip: req.ip, userAgent: req.headers['user-agent'], status: 'SUCCESS' });
            res.json({ success: true, message: 'Share access removed' });
        }
    );
});

// ======================================
// SCAN FILE (ClamAV)
// ======================================
function scanFile(fileId, filePath) {
    return new Promise((resolve) => {
        const scanBinary = process.env.CLAMSCAN_BIN || 'clamdscan';
        execFile(scanBinary, ['--no-summary', filePath], { timeout: 120000 }, (error, stdout, stderr) => {
            let status, result;
            if (error && error.code === 1) {
                status = 'INFECTED';
                result = stdout || stderr || 'Threat detected';
            } else if (error) {
                status = 'UNAVAILABLE';
                result = 'Scanner offline: ' + error.message;
            } else {
                status = 'CLEAN';
                result = stdout || 'No threats detected';
            }
            db.run(
                `UPDATE files SET scan_status = ?, scan_result = ?, scanned_at = CURRENT_TIMESTAMP WHERE id = ?`,
                [status, result, fileId],
                (err) => { if (err) console.error('Scan update failed:', err.message); resolve({ status, result }); }
            );
        });
    });
}
// ======================================
// ADMIN: METRICS
// ======================================
app.get('/api/admin/metrics', authenticateToken, requireAdmin, (req, res) => {
    // Always include ALL users even removed ones (soft-never-delete for admin)
    db.all(`SELECT id, username, first_name, last_name, personal_email, role, created_at, is_removed, removed_at FROM users ORDER BY created_at DESC`, [], (err, users) => {
        if (err) return res.status(500).json({ success: false, error: 'DB error' });
        // Include deleted files for admin audit — never send file_path
        db.all(`SELECT id, user_id, file_name, file_size, uploaded_at, scan_status, scan_result, threat_level, is_deleted, upload_status, scanned_at FROM files ORDER BY uploaded_at DESC`, [], (err2, files) => {
            if (err2) return res.status(500).json({ success: false, error: 'DB error' });
            db.get(`SELECT SUM(file_size) AS totalStorageBytes, COUNT(*) AS totalFiles FROM files WHERE is_deleted = 0`, [], (err3, storage) => {
                const scanBreakdown = {};
                files.forEach(f => { scanBreakdown[f.scan_status] = (scanBreakdown[f.scan_status] || 0) + 1; });
                res.json({
                    success: true,
                    users,
                    files,
                    summary: {
                        totalUsers: users.length,
                        totalFiles: storage ? storage.totalFiles : 0,
                        totalStorageBytes: storage ? storage.totalStorageBytes || 0 : 0,
                        scanBreakdown
                    }
                });
            });
        });
    });
});

// ======================================
// ADMIN: ONLINE USERS (last 10 min = online)
// ======================================
app.get('/api/admin/online-users', authenticateToken, requireAdmin, (req, res) => {
    db.all(
        `SELECT u.id, u.username,
                MAX(al.created_at) AS last_seen,
                CASE WHEN MAX(al.created_at) >= datetime('now', '-10 minutes') THEN 1 ELSE 0 END AS is_online
         FROM users u
         LEFT JOIN audit_logs al ON al.user_id = u.id
         GROUP BY u.id ORDER BY last_seen DESC`,
        [],
        (err, rows) => {
            if (err) return res.status(500).json({ success: false, error: 'DB error' });
            res.json({ success: true, users: rows });
        }
    );
});

// ======================================
// ADMIN: AUDIT LOGS
// ======================================
app.get('/api/admin/logs', authenticateToken, requireAdmin, (req, res) => {
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    db.all(`SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ?`, [limit], (err, rows) => {
        if (err) return res.status(500).json({ success: false, error: 'DB error' });
        res.json({ success: true, logs: rows });
    });
});

// ======================================
// ADMIN: TRAFFIC (from audit_logs last 24h)
// ======================================
app.get('/api/admin/traffic', authenticateToken, requireAdmin, (req, res) => {
    db.all(
        `SELECT action AS path, status AS method,
                COUNT(*) AS hits,
                NULL AS avg_ms,
                SUM(CASE WHEN status != 'SUCCESS' THEN 1 ELSE 0 END) AS error_count
         FROM audit_logs
         WHERE created_at >= datetime('now', '-24 hours')
         GROUP BY action ORDER BY hits DESC`,
        [],
        (err, rows) => {
            if (err) return res.status(500).json({ success: false, error: 'DB error' });
            res.json({ success: true, routes: rows });
        }
    );
});

// ======================================
// ADMIN: SCAN FILE (on-demand)
// ======================================
app.post('/api/admin/scan/:id', authenticateToken, requireAdmin, (req, res) => {
    const fileId = req.params.id;
    db.get(`SELECT id, file_path FROM files WHERE id = ? AND is_deleted = 0`, [fileId], (err, file) => {
        if (err || !file) return res.status(404).json({ success: false, error: 'File not found' });
        scanFileAdmin(fileId, file.file_path).then(result => {
            res.json({ success: true, scan_status: result.status, threat_level: result.threat_level, details: result });
        }).catch(e => res.status(500).json({ success: false, error: e.message }));
    });
});

// ======================================
// ADMIN SCAN FUNCTION (extended)
// ======================================
function scanFileAdmin(fileId, filePath) {
    return new Promise((resolve) => {
        if (!fs.existsSync(filePath)) {
            const r = { status: 'ERROR', result: 'File not found on disk', threat_level: 'UNKNOWN', sha256: null, file_size: null, mime_hint: null, scanned_at: new Date().toISOString() };
            db.run(`UPDATE files SET scan_status='ERROR', scan_result=?, threat_level='UNKNOWN', scanned_at=CURRENT_TIMESTAMP WHERE id=?`, [r.result, fileId]);
            return resolve(r);
        }

        // SHA256 hash
        const hashVal = crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
        const fileSize = fs.statSync(filePath).size;

        // Read first 8 bytes for magic number / MIME hint
        let mimeHint = 'unknown';
        try {
            const buf = Buffer.alloc(8);
            const fd = fs.openSync(filePath, 'r');
            fs.readSync(fd, buf, 0, 8, 0);
            fs.closeSync(fd);
            const hex = buf.toString('hex').toUpperCase();
            if (hex.startsWith('504B0304')) mimeHint = 'ZIP/DOCX/XLSX';
            else if (hex.startsWith('25504446')) mimeHint = 'PDF';
            else if (hex.startsWith('FFD8FF')) mimeHint = 'JPEG';
            else if (hex.startsWith('89504E47')) mimeHint = 'PNG';
            else if (hex.startsWith('4D5A')) mimeHint = 'PE-Executable';
            else if (hex.startsWith('7F454C46')) mimeHint = 'ELF-Executable';
            else mimeHint = 'ENCRYPTED/BINARY';
        } catch (e) {}

        // Entropy check (high entropy = possibly encrypted or packed)
        let entropy = 0;
        try {
            const data = fs.readFileSync(filePath);
            const freq = new Array(256).fill(0);
            for (const b of data) freq[b]++;
            for (const f of freq) { if (f > 0) { const p = f / data.length; entropy -= p * Math.log2(p); } }
        } catch (e) {}

        const highEntropy = entropy > 7.5;

        const scanBinary = process.env.CLAMSCAN_BIN || 'clamdscan';
        execFile(scanBinary, ['--no-summary', filePath], { timeout: 120000 }, (error, stdout, stderr) => {
            let status, clamResult, threat_level;

            if (error && error.code === 1) {
                status = 'INFECTED';
                clamResult = stdout || stderr || 'Threat detected by ClamAV';
                threat_level = 'HIGH';
            } else if (error) {
                // ClamAV offline — do heuristic only
                status = highEntropy ? 'SUSPICIOUS' : 'CLEAN';
                clamResult = 'ClamAV offline. Heuristic scan only.';
                threat_level = highEntropy ? 'MEDIUM' : 'LOW';
            } else {
                status = 'CLEAN';
                clamResult = stdout || 'No threats detected';
                threat_level = highEntropy ? 'LOW' : 'NONE';
            }

            const result = {
                status, result: clamResult, threat_level,
                sha256: hashVal, file_size: fileSize, mime_hint: mimeHint,
                entropy: entropy.toFixed(4), high_entropy: highEntropy,
                scanned_at: new Date().toISOString()
            };

            db.run(
                `UPDATE files SET scan_status=?, scan_result=?, threat_level=?, scanned_at=CURRENT_TIMESTAMP WHERE id=?`,
                [status, clamResult, threat_level, fileId],
                (err) => { if (err) console.error('Scan update failed:', err.message); resolve(result); }
            );
        });
    });
}

// ======================================
// ADMIN: SCAN REPORT DOWNLOAD
// ======================================
app.get('/api/admin/scan-report/:id', authenticateToken, requireAdmin, (req, res) => {
    db.get(`SELECT f.*, u.username, u.personal_email FROM files f JOIN users u ON f.user_id = u.id WHERE f.id = ?`, [req.params.id], (err, f) => {
        if (err || !f) return res.status(404).json({ success: false, error: 'File not found' });
        if (!f.scan_status || f.scan_status === 'PENDING') return res.status(400).json({ success: false, error: 'No scan report available. Scan the file first.' });

        const lines = [
            '============================================================',
            '          CLOUD VAULT — FILE SECURITY SCAN REPORT',
            '============================================================',
            `Report Generated : ${new Date().toISOString()}`,
            `File ID          : ${f.id}`,
            `File Name        : ${f.file_name}`,
            `File Size        : ${(f.file_size / 1024).toFixed(2)} KB`,
            `Owner            : ${f.username} (${f.personal_email})`,
            `Uploaded At      : ${f.uploaded_at}`,
            '',
            '--- SCAN RESULTS ----------------------------------------',
            `Scan Status      : ${f.scan_status}`,
            `Threat Level     : ${f.threat_level || 'N/A'}`,
            `Scanned At       : ${f.scanned_at || 'N/A'}`,
            `SHA-256 Hash     : ${f.sha256 || 'N/A'}`,
            '',
            '--- SCAN DETAIL -----------------------------------------',
            f.scan_result || 'No detail available.',
            '',
            '--- CHECKS PERFORMED ------------------------------------',
            '1. ClamAV Antivirus Scan',
            '2. SHA-256 File Integrity Hash',
            '3. Magic Byte / MIME Type Detection',
            '4. File Entropy Analysis (encrypted/packed detection)',
            '',
            '--- THREAT LEVEL KEY ------------------------------------',
            'NONE   = No threat detected, all checks passed',
            'LOW    = Clean but high entropy (likely encrypted payload)',
            'MEDIUM = ClamAV offline; heuristic only — review manually',
            'HIGH   = Active threat detected by antivirus engine',
            '============================================================',
            'END OF REPORT'
        ];

        const reportText = lines.join('\n');
        res.setHeader('Content-Type', 'text/plain');
        res.setHeader('Content-Disposition', `attachment; filename="scan-report-file-${f.id}.txt"`);
        res.send(reportText);
    });
});

// ======================================
// ADMIN: NOTIFY USER BY EMAIL
// ======================================
app.post('/api/admin/notify/:id', authenticateToken, requireAdmin, (req, res) => {
    db.get(`SELECT f.file_name, f.scan_status, f.threat_level, u.personal_email, u.username FROM files f JOIN users u ON f.user_id = u.id WHERE f.id = ?`, [req.params.id], async (err, f) => {
        if (err || !f) return res.status(404).json({ success: false, error: 'File not found' });
        try {
            await transporter.sendMail({
                from: `"Cloud Vault Security" <${process.env.EMAIL_USER}>`,
                to: f.personal_email,
                subject: '⚠️ Cloud Vault — Security Alert on Your File',
                html: `<div style="font-family:Arial,sans-serif;padding:20px;max-width:600px;">
                    <h2 style="color:#dc2626;">⚠️ Security Alert</h2>
                    <p>Dear <strong>${f.username}</strong>,</p>
                    <p>Our security system has detected a potential issue with one of your uploaded files:</p>
                    <table style="border-collapse:collapse;width:100%;margin:16px 0;">
                        <tr><td style="padding:8px;background:#f9fafb;font-weight:600;">File Name</td><td style="padding:8px;">${f.file_name}</td></tr>
                        <tr><td style="padding:8px;background:#f9fafb;font-weight:600;">Scan Status</td><td style="padding:8px;color:#dc2626;">${f.scan_status}</td></tr>
                        <tr><td style="padding:8px;background:#f9fafb;font-weight:600;">Threat Level</td><td style="padding:8px;">${f.threat_level || 'N/A'}</td></tr>
                    </table>
                    <p>Please log in to Cloud Vault and review this file immediately. The admin team may remove flagged files to protect the system.</p>
                    <p style="color:#6b7280;font-size:0.85rem;">This is an automated security notification from Cloud Vault.</p>
                </div>`
            });
            res.json({ success: true, message: `Security alert sent to ${f.personal_email}` });
        } catch (e) {
            res.status(500).json({ success: false, error: 'Email send failed: ' + e.message });
        }
    });
});

// ======================================
// ADMIN: REMOVE FILE
// ======================================
app.delete('/api/admin/files/:id', authenticateToken, requireAdmin, (req, res) => {
    db.get(`SELECT file_path FROM files WHERE id = ?`, [req.params.id], (err, f) => {
        if (err || !f) return res.status(404).json({ success: false, error: 'File not found' });
        db.run(`UPDATE files SET is_deleted = 1, upload_status = 'REMOVED_BY_ADMIN' WHERE id = ?`, [req.params.id], function (err2) {
            if (err2) return res.status(500).json({ success: false, error: 'DB error' });
            try { if (fs.existsSync(f.file_path)) fs.unlinkSync(f.file_path); } catch (e) {}
            logAudit({ userId: req.user.id, username: req.user.username, action: 'ADMIN_REMOVE_FILE', fileId: req.params.id, ip: req.ip, userAgent: req.headers['user-agent'], status: 'SUCCESS' });
            res.json({ success: true });
        });
    });
});

// ======================================
// ADMIN: REMOVE USER
// ======================================
app.delete('/api/admin/users/:id', authenticateToken, requireAdmin, (req, res) => {
    db.run(
        `UPDATE users SET is_removed = 1, removed_at = CURRENT_TIMESTAMP WHERE id = ? AND role != 'admin'`,
        [req.params.id],
        function (err) {
            if (err) return res.status(500).json({ success: false, error: 'DB error' });
            if (this.changes === 0) return res.status(404).json({ success: false, error: 'User not found or cannot remove admin' });
            // Also soft-delete all their files and block login
            db.run(`UPDATE files SET is_deleted = 1, upload_status = 'OWNER_REMOVED' WHERE user_id = ? AND is_deleted = 0`, [req.params.id]);
            logAudit({ userId: req.user.id, username: req.user.username, action: 'ADMIN_REMOVE_USER', ip: req.ip, userAgent: req.headers['user-agent'], status: 'SUCCESS' });
            res.json({ success: true });
        }
    );
});

// ======================================
// ADMIN: GET SINGLE USER DETAILS (files, shares, logs)
// ======================================
app.get('/api/admin/user/:id', authenticateToken, requireAdmin, (req, res) => {
    const uid = req.params.id;
    db.get(`SELECT id, username, first_name, last_name, personal_email, mobile_number, region_code, role, created_at FROM users WHERE id = ?`, [uid], (err, user) => {
        if (err || !user) return res.status(404).json({ success: false, error: 'User not found' });
        db.all(`SELECT id, file_name, file_size, uploaded_at, scan_status, threat_level, is_deleted, upload_status FROM files WHERE user_id = ? ORDER BY uploaded_at DESC`, [uid], (e2, files) => {
            db.all(`SELECT fs.file_id, fs.shared_at, fs.is_reshared, f.file_name, u.username AS shared_with FROM file_shares fs JOIN files f ON fs.file_id = f.id JOIN users u ON fs.shared_with_user_id = u.id WHERE fs.shared_by_user_id = ? ORDER BY fs.shared_at DESC`, [uid], (e3, sent) => {
                db.all(`SELECT fs.file_id, fs.shared_at, fs.is_reshared, f.file_name, u.username AS shared_by FROM file_shares fs JOIN files f ON fs.file_id = f.id JOIN users u ON fs.shared_by_user_id = u.id WHERE fs.shared_with_user_id = ? ORDER BY fs.shared_at DESC`, [uid], (e4, received) => {
                    db.all(`SELECT action, file_id, original_filename, ip_address, status, created_at FROM audit_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 100`, [uid], (e5, logs) => {
                        res.json({ success: true, user, files: files || [], sent: sent || [], received: received || [], logs: logs || [] });
                    });
                });
            });
        });
    });
});

// ======================================
// ADMIN: CREATE NEW ADMIN
// ======================================
app.post('/api/admin/create-admin', authenticateToken, requireAdmin, async (req, res) => {
    const { username, password, email } = req.body;
    if (!username || !password || !email)
        return res.status(400).json({ success: false, error: 'username, password and email are required' });
    try {
        const hash = await bcrypt.hash(password, 12);
        db.run(
            `INSERT INTO users (username, first_name, last_name, personal_email, mobile_number, region_code, password_hash, role, is_verified)
             VALUES (?, 'Admin', 'User', ?, '0000000000', 'ADMIN', ?, 'admin', 1)`,
            [username.trim().toLowerCase(), email.trim().toLowerCase(), hash],
            function (err) {
                if (err) return res.status(409).json({ success: false, error: 'Username or email already exists' });
                logAudit({ userId: req.user.id, username: req.user.username, action: 'CREATE_ADMIN', ip: req.ip, userAgent: req.headers['user-agent'], status: 'SUCCESS' });
                res.json({ success: true, message: `Admin "${username}" created successfully`, id: this.lastID });
            }
        );
    } catch (e) {
        res.status(500).json({ success: false, error: 'Server error' });
    }
});

// ======================================
// ADMIN: DEEP SCAN FILE
// ======================================
app.post('/api/admin/deepscan/:id', authenticateToken, requireAdmin, (req, res) => {
    const fileId = req.params.id;
    db.get(`SELECT id, file_path, file_name, file_size FROM files WHERE id = ? AND is_deleted = 0`, [fileId], (err, file) => {
        if (err || !file) return res.status(404).json({ success: false, error: 'File not found' });
        deepScanFile(fileId, file).then(result => {
            res.json({ success: true, scan_status: result.status, threat_level: result.threat_level, details: result });
        }).catch(e => res.status(500).json({ success: false, error: e.message }));
    });
});

function deepScanFile(fileId, file) {
    return new Promise((resolve) => {
        const filePath = file.file_path;
        if (!fs.existsSync(filePath)) {
            const r = { status: 'ERROR', threat_level: 'UNKNOWN', result: 'File not found on disk', deep: true };
            db.run(`UPDATE files SET scan_status='ERROR', scan_result=?, threat_level='UNKNOWN', scanned_at=CURRENT_TIMESTAMP WHERE id=?`, [r.result, fileId]);
            return resolve(r);
        }

        const data = fs.readFileSync(filePath);
        const sha256 = crypto.createHash('sha256').update(data).digest('hex');
        const md5 = crypto.createHash('md5').update(data).digest('hex');
        const fileSize = data.length;

        // MIME detection
        const hex = data.slice(0, 8).toString('hex').toUpperCase();
        let mimeHint = 'ENCRYPTED/BINARY';
        if (hex.startsWith('504B0304')) mimeHint = 'ZIP/DOCX/XLSX';
        else if (hex.startsWith('25504446')) mimeHint = 'PDF';
        else if (hex.startsWith('FFD8FF')) mimeHint = 'JPEG';
        else if (hex.startsWith('89504E47')) mimeHint = 'PNG';
        else if (hex.startsWith('4D5A')) mimeHint = 'PE-Executable (DANGER)';
        else if (hex.startsWith('7F454C46')) mimeHint = 'ELF-Executable (DANGER)';
        else if (hex.startsWith('CAFEBABE')) mimeHint = 'Java Class';

        // Entropy
        const freq = new Array(256).fill(0);
        for (const b of data) freq[b]++;
        let entropy = 0;
        for (const f of freq) { if (f > 0) { const p = f / data.length; entropy -= p * Math.log2(p); } }
        const highEntropy = entropy > 7.5;

        // Null byte ratio (packed/obfuscated)
        const nullBytes = freq[0];
        const nullRatio = nullBytes / fileSize;

        // Suspicious string patterns in raw bytes
        const raw = data.toString('latin1');
        const suspiciousPatterns = [
            { pattern: /eval\s*\(/gi, label: 'eval() call' },
            { pattern: /exec\s*\(/gi, label: 'exec() call' },
            { pattern: /base64_decode/gi, label: 'base64_decode' },
            { pattern: /powershell/gi, label: 'PowerShell reference' },
            { pattern: /cmd\.exe/gi, label: 'cmd.exe reference' },
            { pattern: /net\.exe/gi, label: 'net.exe reference' },
            { pattern: /<script/gi, label: 'Embedded <script> tag' },
            { pattern: /javascript:/gi, label: 'javascript: URI' },
            { pattern: /EICAR-STANDARD-ANTIVIRUS-TEST-FILE/gi, label: 'EICAR test string' },
            { pattern: /WScript\.Shell/gi, label: 'WScript.Shell' },
            { pattern: /ActiveXObject/gi, label: 'ActiveXObject' },
            { pattern: /CreateObject/gi, label: 'CreateObject' },
        ];
        const found = suspiciousPatterns.filter(p => p.pattern.test(raw)).map(p => p.label);

        // File extension mismatch check
        const extMismatch = (mimeHint.includes('Executable') || mimeHint.includes('Java'));

        let threat_level = 'NONE';
        let status = 'CLEAN';
        const flags = [...found];
        if (highEntropy) flags.push('High entropy (>7.5 bits)');
        if (nullRatio > 0.3) flags.push(`High null byte ratio (${(nullRatio * 100).toFixed(1)}%)`);
        if (extMismatch) flags.push('Executable MIME type');

        if (flags.length >= 3 || extMismatch) { threat_level = 'HIGH'; status = 'INFECTED'; }
        else if (flags.length >= 1 || highEntropy) { threat_level = 'MEDIUM'; status = 'SUSPICIOUS'; }
        else { threat_level = 'LOW'; }

        const result = {
            status, threat_level, deep: true,
            sha256, md5, file_size: fileSize, mime_hint: mimeHint,
            entropy: entropy.toFixed(4), high_entropy: highEntropy,
            null_byte_ratio: nullRatio.toFixed(4),
            suspicious_patterns_found: found,
            flags,
            scanned_at: new Date().toISOString()
        };

        const resultText = `DEEP SCAN: ${status} | Flags: ${flags.join('; ') || 'None'} | MIME: ${mimeHint} | Entropy: ${entropy.toFixed(4)}`;
        db.run(
            `UPDATE files SET scan_status=?, scan_result=?, threat_level=?, scanned_at=CURRENT_TIMESTAMP WHERE id=?`,
            [status, resultText, threat_level, fileId],
            () => resolve(result)
        );
    });
}

// ======================================
// ERROR HANDLER
// ======================================
app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) return res.status(400).json({ success: false, error: 'Upload error: ' + err.message });
    if (err) { console.error('Server Error:', err.message); return res.status(500).json({ success: false, error: 'Internal server error' }); }
    next();
});

// ======================================
// START SERVER
// ======================================
const server = app.listen(PORT, () => {
    console.log('========================================');
    console.log(`Cloud Vault : http://localhost:${PORT}`);
    console.log('========================================');
});

server.on('error', (err) => console.error('Server error:', err));
server.timeout = 1800000;