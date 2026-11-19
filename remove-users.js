require('dotenv').config();
const { client, exec } = require('./db');

const args = process.argv.slice(2).filter(a => a !== '--yes');
const yes = process.argv.includes('--yes');
const [cmd, target] = args;

const rows = async (sql, a) => {
    const rs = await exec(sql, a);
    return rs.rows.map(r => Object.fromEntries(rs.columns.map((c, i) => [c, r[i]])));
};

async function removeUser(u) {
    const files = await rows('SELECT id, file_path FROM files WHERE user_id = ?', [u.id]);
    for (const f of files) {
        await exec('DELETE FROM file_blobs WHERE path = ?', [f.file_path]);
        await exec('DELETE FROM file_shares WHERE file_id = ?', [f.id]);
    }
    await exec('DELETE FROM file_shares WHERE shared_with_user_id = ? OR shared_by_user_id = ?', [u.id, u.id]);
    await exec('DELETE FROM files WHERE user_id = ?', [u.id]);
    await exec('UPDATE audit_logs SET user_id = NULL WHERE user_id = ?', [u.id]);
    await exec('DELETE FROM users WHERE id = ?', [u.id]);
}

(async () => {
    const cols = 'id, username, personal_email AS email, role, is_verified AS verified';
    let list;
    if (cmd === 'list') {
        console.table(await rows(`SELECT ${cols} FROM users ORDER BY id`));
        return;
    } else if (cmd === 'user' && target) {
        list = await rows(`SELECT ${cols} FROM users WHERE lower(username) = lower(?) OR lower(personal_email) = lower(?)`, [target, target]);
    } else if (cmd === 'unverified') {
        list = await rows(`SELECT ${cols} FROM users WHERE is_verified = 0 AND role != 'admin'`);
    } else if (cmd === 'all') {
        list = await rows(`SELECT ${cols} FROM users WHERE role != 'admin'`);
    } else {
        console.log('Usage: node remove-users.js list | user <username-or-email> | unverified | all   (add --yes to actually delete)');
        return;
    }

    if (!list.length) { console.log('No matching users.'); return; }
    console.log(yes ? 'Removing:' : 'These users WOULD be removed (add --yes to do it):');
    console.table(list);
    if (!yes) return;
    for (const u of list) await removeUser(u);
    console.log(`Removed ${list.length} user(s) and their files/shares.`);
})().catch(e => { console.error('Error:', e.message); process.exitCode = 1; }).finally(() => client.close());
