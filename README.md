Feel free to edit it and use it on your own.
![Preview](https://i.ibb.co/RGFKjMvC/image.png)

CDN Based files sharing platform with administration and logging to discord

## Features

- File metadata stored in SQLite (`better-sqlite3`).
- Admin-protected upload endpoint using a static password from `.env`.
- Password-protected downloads.
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
   npm install
   ```
3. Start the server:
   ```bash
   node server.js
   ```

> The server also serves a visitor page at `/` and an admin dashboard at `/admin` (both located under `public/`).

4. Download files:
   - Public (unlocked): `GET /download/:id`
   - Locked: `POST /download/:id` with JSON `{ password }`

6. Additional admin APIs:
   - `GET /api/files` returns JSON list of all files (id, originalName, nickname, isLocked, uploadDate).
   - `DELETE /api/files/:id` deletes a file (requires `x-admin-password` header).

## Notes

- Failed attempts per IP/file combo are tracked; after 3 wrong tries the IP is banned for 10 minutes.
- Alerts are sent to the Discord webhook if configured.
