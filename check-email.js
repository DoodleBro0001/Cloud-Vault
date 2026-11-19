require('dotenv').config();
const fs = require('fs');
const nodemailer = require('nodemailer');
const { EMAIL_USER, EMAIL_PASS } = process.env;
const srv = fs.readFileSync('server.js', 'utf8');
console.log('Folder        :', process.cwd());
console.log('EMAIL_USER    :', EMAIL_USER || 'MISSING');
console.log('EMAIL_PASS    :', EMAIL_PASS ? EMAIL_PASS.length + ' chars' + (EMAIL_PASS === 'abcdefghijklmnop' ? '  <-- PLACEHOLDER, not real' : '') : 'MISSING');
console.log('server.js fix :', srv.includes('Could not send the verification email') ? 'yes (errors will show on the page)' : 'NO (old file, failures are hidden)');
nodemailer.createTransport({ host: 'smtp.gmail.com', port: 465, secure: true, auth: { user: EMAIL_USER, pass: EMAIL_PASS } })
  .sendMail({ from: EMAIL_USER, to: EMAIL_USER, subject: 'Cloud Vault test', text: 'It works' })
  .then(i => console.log('SMTP RESULT   : SENT -', i.response))
  .catch(e => console.log('SMTP RESULT   : FAILED -', e.code, e.message));
