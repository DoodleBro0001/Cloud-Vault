# Secure Vault

A zero-knowledge encrypted file vault. Files are encrypted in the browser before upload, so the server only ever stores ciphertext. It includes email-verified registration, encrypted file sharing between users, an admin dashboard and audit logging.

Built with Node.js, Express and Turso (libSQL), and deployed on Vercel.

## Features

- **End-to-end encryption**: files are encrypted in the browser with AES-256-GCM. The file key is wrapped with the user's RSA-OAEP public key.
- **Private keys never leave the browser unencrypted**: the RSA private key is encrypted with a key derived from the user's password (PBKDF2, 310,000 iterations, random per-user salt) and is only decrypted in memory after login.
- **Secure sharing**: sharing a file re-wraps its AES key for the recipient's public key. The server never sees the file key.
- **Email verification**: new accounts must confirm a 6-character code sent by email (valid for 15 minutes).
- **Admin dashboard**: user and file metrics, activity and traffic views, online users, file scans (SHA-256, magic-number and entropy checks), scan reports, and user/file removal.
- **Audit log**: logins, uploads, downloads and shares are recorded with IP address and user agent.
- **Security hardening**: bcrypt password hashing, JWT authentication, Helmet security headers with a Content Security Policy, CORS allow-list and rate limiting.

## Tech stack

| Layer | Technology |
|---|---|
| Server | Node.js, Express 5 |
| Database | Turso (libSQL / SQLite) |
| Auth | JSON Web Tokens, bcryptjs |
| Email | Nodemailer (Gmail SMTP) |
| Client crypto | Web Crypto API (AES-GCM, RSA-OAEP, PBKDF2) |
| Hosting | Vercel |

## Project structure

```
secure-vault/
├── server.js            Express app and API routes (exported for Vercel)
├── db.js                libSQL client with a sqlite3-style callback API
├── schema.js            Database tables, created automatically on first request
├── public/
│   ├── index.html       User interface
│   ├── admin.html       Admin dashboard
│   └── crypto-logic.js  Browser-side encryption engine
├── create_admin.js      Create an admin account
├── reset-admin.js       Reset an admin password
├── remove-users.js      List or remove users
├── list_users.js        List users
├── vercel.json          Security headers for static pages
└── .env.example         Required environment variables
```

## Environment variables

Copy `.env.example` to `.env` for local development. On Vercel, add the same values under **Settings → Environment Variables**.

| Variable | Description |
|---|---|
| `JWT_SECRET` | Long random string (at least 32 characters) used to sign login tokens |
| `ALLOWED_ORIGIN` | Site address allowed by CORS, for example `https://your-project.vercel.app` |
| `EMAIL_USER` | Gmail address that sends verification emails |
| `EMAIL_PASS` | Gmail **app password** (16 characters). Your normal password will not work |
| `TURSO_DATABASE_URL` | Turso database URL, starting with `libsql://` |
| `TURSO_AUTH_TOKEN` | Turso database token |

Generate a secret:

```bash
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
```

If the two `TURSO_` variables are not set, the app falls back to a local SQLite file (`secure_vault_v2.db`). This works for local development only, and the app refuses to start on Vercel without Turso.

## Run locally

```bash
git clone https://github.com/dharshanchandrasegar2-dotcom/secure-vault-vercel.git
cd secure-vault-vercel
npm install
cp .env.example .env        # then fill in your values
node create_admin.js admin "YourStrongPassword12" you@example.com
npm start
```

Open `http://localhost:3000`. The admin dashboard is at `http://localhost:3000/admin.html`.

## Deploy to Vercel

1. Create a database at [turso.tech](https://turso.tech) and copy its URL and token.
2. Install and log in to the Vercel CLI:

   ```bash
   npm i -g vercel
   vercel login
   ```

3. Deploy once to create the project, then add the six environment variables in the Vercel dashboard.
4. Deploy to production:

   ```bash
   vercel --prod
   ```

Variable changes only apply to deployments created after the change, so redeploy after editing them.

## Admin scripts

Run these from the project folder. They use the same database as the live site.

```bash
node create_admin.js <username> <password> [email]    # password: 12+ characters
node reset-admin.js <admin-username> <new-password>
node list_users.js
node remove-users.js list
node remove-users.js user <username-or-email> [--yes]
node remove-users.js unverified [--yes]
node remove-users.js all [--yes]                       # everyone except admins
```

`remove-users.js` only previews what it would delete until you add `--yes`. Removing a user also deletes their files and shares.

## Limitations

- **Upload size is 4 MB per file.** Vercel Functions reject request bodies larger than 4.5 MB. Supporting much larger files would need direct-to-storage uploads and chunked encryption.
- **Antivirus scanning is not available.** ClamAV cannot run on Vercel, so uploads show a scan status of `UNAVAILABLE` and admin scans are heuristic only.
- **Rate limiting is per server instance.** On a serverless host the counters are not shared between instances.
- **Password recovery is not possible.** Because private keys are encrypted with the user's password, a forgotten password means the user's existing files cannot be decrypted. This is a property of the zero-knowledge design.

## Security notes

- Never commit `.env` or any `.db` file. Both are listed in `.gitignore`.
- Use a Gmail app password, and rotate any secret that has been shared or exposed.
- Choose a unique admin password of at least 12 characters.

## License

ISC
