const path = require('path');
const { createClient } = require('@libsql/client');

let waitUntil = () => {};
try { ({ waitUntil } = require('@vercel/functions')); } catch (e) {}

const remoteUrl = process.env.TURSO_DATABASE_URL;
if (process.env.VERCEL && !remoteUrl) {
    throw new Error('TURSO_DATABASE_URL is required on Vercel (the filesystem is not persistent).');
}

const url = remoteUrl ||
    (process.env.DATA_DIR
        ? 'file:' + path.join(process.env.DATA_DIR, 'secure_vault_v2.db')
        : 'file:./secure_vault_v2.db');

const client = createClient({ url, authToken: process.env.TURSO_AUTH_TOKEN });

// Whole numbers must be bound as INTEGER (not REAL) for LIMIT, ids, sizes, etc.
const normArgs = (args = []) => args.map(v =>
    typeof v === 'number' && Number.isInteger(v) ? BigInt(v) :
    v === undefined ? null : v);

const toObject = (rs, row) => {
    const o = {};
    rs.columns.forEach((c, i) => { o[c] = row[i]; });
    return o;
};

const exec = (sql, args) => client.execute({ sql, args: normArgs(args) });
const batch = (stmts) => client.batch(
    stmts.map(s => ({ sql: s.sql, args: normArgs(s.args) })), 'write');

function parse(params, cb) {
    return typeof params === 'function' ? [[], params] : [params || [], cb];
}

// sqlite3-compatible callback API (db.run / db.get / db.all) on top of libSQL,
// so the route code keeps working unchanged. `this.lastID` / `this.changes` supported.
const db = {
    run(sql, params, cb) {
        [params, cb] = parse(params, cb);
        const p = exec(sql, params).then(
            rs => { if (cb) setImmediate(() => cb.call({ lastID: Number(rs.lastInsertRowid || 0), changes: rs.rowsAffected }, null)); },
            err => { if (cb) setImmediate(() => cb.call({}, err)); else console.error('DB error:', err.message); }
        );
        if (!cb) waitUntil(p); // keep fire-and-forget writes (audit logs) alive on serverless
    },
    get(sql, params, cb) {
        [params, cb] = parse(params, cb);
        exec(sql, params).then(
            rs => setImmediate(() => cb(null, rs.rows.length ? toObject(rs, rs.rows[0]) : undefined)),
            err => setImmediate(() => cb(err))
        );
    },
    all(sql, params, cb) {
        [params, cb] = parse(params, cb);
        exec(sql, params).then(
            rs => setImmediate(() => cb(null, rs.rows.map(r => toObject(rs, r)))),
            err => setImmediate(() => cb(err))
        );
    }
};

module.exports = { client, db, exec, batch };
