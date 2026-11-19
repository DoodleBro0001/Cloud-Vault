require('dotenv').config();
require('./db').exec("delete from users where is_verified = 0 and role = 'user'").then(() => { console.log('Cleared unverified accounts.'); process.exit(0); });
