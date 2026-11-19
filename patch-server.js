const fs = require('fs');
let s = fs.readFileSync('server.js', 'utf8').replace(/\r\n/g, '\n');
const oldLine = "} catch (emailErr) { console.error('Email error:', emailErr.message); }";
if (s.includes('Could not send the verification email')) { console.log('Already patched.'); process.exit(0); }
if (!s.includes(oldLine)) { console.log('Line not found - tell me and I will give you another way.'); process.exit(1); }
s = s.replace(oldLine, `} catch (emailErr) {
                    console.error('Email error:', emailErr.message);
                    const userId = this.lastID;
                    return db.run('DELETE FROM users WHERE id = ?', [userId], () =>
                        res.status(502).json({ success: false, error: 'Could not send the verification email. Check EMAIL_USER / EMAIL_PASS on the server and try again.' }));
                }`);
fs.writeFileSync('server.js', s);
console.log('Patched server.js');
