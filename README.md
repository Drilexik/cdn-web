# Custom CDN Server

This is a simple Node.js/Express application that functions as a custom content delivery network (CDN) with optional password protection.

## Features

- File metadata stored in SQLite (`better-sqlite3`).
- Admin-protected upload endpoint using a static password from `.env`.
- Password-protected downloads with nickname verification.
- Failed-attempt tracking and temporary IP bans.
- Discord webhook alerts for security events.

## Setup

1. Copy the example env file and provide your own values:
   ```
   cp .env.example .env
   # then edit .env
   ```
2. Install dependencies:
   ```bash
   npm install express better-sqlite3 dotenv multer bcrypt uuid axios
   ```
3. Start the server:
   ```bash
   node server.js
   ```

> Upon startup the app will create a `data/` directory at the project root containing:
> - `uploads/` – all stored blobs
> - `files.db` – SQLite database
>
> The server also serves a visitor page at `/` and an admin dashboard at `/admin` (both located under `public/`).

4. Upload files via POST `/upload` with form-data fields:
   - `file`: the file to upload
   - `nickname`: string
   - `password` (optional): if provided, file is locked
   - Include header `x-admin-password` with the admin password.

5. Download files:
   - Public (unlocked): `GET /download/:id`
   - Locked: `POST /download/:id` with JSON `{ password, nickname }`

6. Additional admin APIs:
   - `GET /api/files` returns JSON list of all files (id, originalName, nickname, isLocked, uploadDate).
   - `DELETE /api/files/:id` deletes a file (requires `x-admin-password` header).

## Notes

- Failed attempts per IP/file combo are tracked; after 3 wrong tries the IP is banned for 10 minutes.
- Alerts are sent to the Discord webhook if configured.
