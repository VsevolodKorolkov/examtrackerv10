# Exam Tracker — Cloudflare D1 edition

Files:
- index.html — frontend
- functions/api/* — Cloudflare Pages Functions API
- functions/_lib.js — auth/database helpers
- schema.sql — D1 schema
- wrangler.jsonc — D1 binding configuration

Cloudflare binding name expected by the code: DB
D1 database: userdb

Deployment:
1. Run schema.sql in D1 Studio for userdb.
2. Upload/commit all files to the GitHub repository root.
3. Deploy the repository as a Cloudflare Pages project.
4. In Pages Settings -> Bindings, confirm D1 binding variable DB points to userdb.
5. Redeploy after adding/changing the binding.

The app stores password hashes, not plaintext passwords. Sessions use an HttpOnly Secure cookie.
