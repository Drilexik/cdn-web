require('dotenv').config();

const express = require('express');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const Database = require('better-sqlite3');
const axios = require('axios');

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL;

const app = express();
app.set('trust proxy', true);
app.use(express.json());
app.use(express.static('public')); // serve visitor and admin pages

// explicit admin page route
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// make sure data directories exist
const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR);
}
if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR);
}

// sqlite setup
const db = new Database(path.join(DATA_DIR, 'files.db'));
db.prepare(`
    CREATE TABLE IF NOT EXISTS file_meta (
        id TEXT PRIMARY KEY,
        filename TEXT NOT NULL,
        originalName TEXT NOT NULL,
        nickname TEXT NOT NULL,
        passwordHash TEXT,
        isLocked INTEGER NOT NULL,
        uploadDate INTEGER NOT NULL
    )
`).run();

// prepared statements
const insertFile = db.prepare(`
    INSERT INTO file_meta (id, filename, originalName, nickname, passwordHash, isLocked, uploadDate)
    VALUES (@id,@filename,@originalName,@nickname,@passwordHash,@isLocked,@uploadDate)
`);
const getFileById = db.prepare(`SELECT * FROM file_meta WHERE id = ?`);

// simple admin middleware
function adminOnly(req, res, next) {
    const pw = req.headers['x-admin-password'] || req.body.adminPassword;
    if (!ADMIN_PASSWORD || pw !== ADMIN_PASSWORD) {
        return res.status(401).json({ error: 'unauthorized' });
    }
    next();
}

// ban tracking
const attemptMap = new Map();

function makeKey(ip, fileId) {
    return `${ip}-${fileId}`;
}

function recordFailure(ip, fileId) {
    const key = makeKey(ip, fileId);
    const now = Date.now();
    const entry = attemptMap.get(key) || { attempts: 0, bannedUntil: null };
    if (entry.bannedUntil && entry.bannedUntil > now) {
        // already banned
        return false;
    }
    entry.attempts += 1;
    let justBanned = false;
    if (entry.attempts >= 3) {
        entry.bannedUntil = now + 10 * 60 * 1000; // 10 minutes
        justBanned = true;
    }
    attemptMap.set(key, entry);
    return justBanned;
}

function isBanned(ip, fileId) {
    const key = makeKey(ip, fileId);
    const entry = attemptMap.get(key);
    if (!entry) return false;
    if (entry.bannedUntil && entry.bannedUntil > Date.now()) {
        return true;
    }
    // reset if ban expired
    if (entry.bannedUntil && entry.bannedUntil <= Date.now()) {
        attemptMap.delete(key);
    }
    return false;
}

// discord alert helper
async function sendDiscordAlert({ ip, userAgent = 'unknown', timestamp, filename = 'unknown', providedNickname = '', status }) {
    if (!DISCORD_WEBHOOK_URL) return; // nothing to do

    // choose color based on status
    let color = 0xFFA500; // orange default
    if (status.toLowerCase().includes('ban')) {
        color = 0xFF0000; // red
    }

    const embed = {
        title: 'CDN Alert',
        color,
        fields: [
            { name: 'IP', value: ip, inline: true },
            { name: 'User-Agent', value: userAgent, inline: true },
            { name: 'Time', value: timestamp, inline: false },
            { name: 'Filename', value: filename, inline: false },
            { name: 'Nickname', value: providedNickname, inline: true },
            { name: 'Status', value: status, inline: true }
        ]
    };

    try {
        await axios.post(DISCORD_WEBHOOK_URL, { embeds: [embed] });
    } catch (err) {
        console.error('failed to send discord alert', err.message);
    }
}

// download notification helper (non-blocking)
function sendDiscordDownloadNotification({ filename, userInfo = 'Public Access', ip = 'unknown', userAgent = 'unknown', timestamp }) {
    if (!DISCORD_WEBHOOK_URL) return;
    const color = 0x00AA00; // green
    const embed = {
        title: 'File Downloaded',
        color,
        fields: [
            { name: 'Filename', value: filename || 'unknown', inline: false },
            { name: 'User', value: userInfo, inline: true },
            { name: 'IP', value: ip, inline: true },
            { name: 'Browser', value: userAgent, inline: false },
            { name: 'Time', value: timestamp || new Date().toISOString(), inline: false }
        ]
    };

    // fire-and-forget; catch errors so it never crashes the server
    (async () => {
        try {
            await axios.post(DISCORD_WEBHOOK_URL, { embeds: [embed] });
        } catch (err) {
            console.error('discord download notify failed', err && err.message);
        }
    })();
}

// multer setup
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => {
        const id = uuidv4();
        // we'll use id as filename with original extension
        const ext = path.extname(file.originalname);
        cb(null, id + ext);
    }
});
const upload = multer({ storage });

// admin upload route
app.post('/api/upload', adminOnly, upload.single('file'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'no file' });
    }

    const nickname = req.body.nickname || 'anonymous';
    const password = req.body.password;
    let hash = null;
    let locked = 0;
    if (password) {
        hash = await bcrypt.hash(password, 10);
        locked = 1;
    }

    const id = uuidv4();
    const storedFilename = req.file.filename;
    const originalName = req.file.originalname;
    const uploadDate = Date.now();

    insertFile.run({
        id,
        filename: storedFilename,
        originalName,
        nickname,
        passwordHash: hash,
        isLocked: locked,
        uploadDate
    });

    res.json({ id });
});

// public download (if not locked)
app.get('/download/:id', (req, res) => {
    const file = getFileById.get(req.params.id);
    if (!file) return res.status(404).send('not found');
    if (file.isLocked) {
        return res.status(403).send('locked');
    }
    const fullPath = path.join(UPLOAD_DIR, file.filename);
    res.download(fullPath, file.originalName, (err) => {
        if (err) {
            console.error('download error', err && err.message);
            return;
        }
        // on successful serve, notify Discord (non-blocking)
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || req.ip;
        const userAgent = req.headers['user-agent'] || 'unknown';
        sendDiscordDownloadNotification({
            filename: file.originalName,
            userInfo: 'Public Access',
            ip,
            userAgent,
            timestamp: new Date().toISOString()
        });
    });
});

// admin API to list files
app.get('/api/files', (req, res) => {
    const rows = db.prepare(`SELECT id, originalName, nickname, isLocked, uploadDate FROM file_meta`).all();
    res.json(rows);
});

// delete file endpoint
app.delete('/api/files/:id', adminOnly, (req, res) => {
    const id = req.params.id;
    const file = getFileById.get(id);
    if (!file) return res.status(404).json({ error: 'not found' });

    const fullPath = path.join(UPLOAD_DIR, file.filename);
    try {
        if (fs.existsSync(fullPath)) {
            fs.unlinkSync(fullPath);
        }
    } catch (err) {
        console.error('error deleting file', err);
    }

    db.prepare(`DELETE FROM file_meta WHERE id = ?`).run(id);
    res.json({ success: true });
});

// locked download
app.post('/download/:id', async (req, res) => {
    const ip = req.ip;
    const fileId = req.params.id;

    const file = getFileById.get(fileId);
    if (!file) return res.status(404).send('not found');

    if (isBanned(ip, fileId)) {
        // log alert with filename now known
        sendDiscordAlert({
            ip,
            userAgent: req.headers['user-agent'] || 'unknown',
            timestamp: new Date().toISOString(),
            filename: file.originalName,
            providedNickname: req.body.nickname || '',
            status: 'Timeout/Ban Issued'
        });
        return res.status(429).json({ error: 'too many attempts, try later' });
    }

    if (!file.isLocked) {
        // fall back to GET route
        return res.redirect(`/download/${fileId}`);
    }

    const { password, nickname } = req.body;
    if (!password || !nickname) {
        return res.status(400).json({ error: 'password and nickname required' });
    }

    // verify nickname
    if (nickname !== file.nickname) {
        const bannedNow = recordFailure(ip, fileId);
        await sendDiscordAlert({
            ip,
            userAgent: req.headers['user-agent'] || 'unknown',
            timestamp: new Date().toISOString(),
            filename: file.originalName,
            providedNickname: nickname,
            status: 'Wrong Password'
        });
        if (bannedNow) {
            await sendDiscordAlert({
                ip,
                userAgent: req.headers['user-agent'] || 'unknown',
                timestamp: new Date().toISOString(),
                filename: file.originalName,
                providedNickname: nickname,
                status: 'Timeout/Ban Issued'
            });
        }
        return res.status(403).json({ error: 'invalid credentials' });
    }

    const match = await bcrypt.compare(password, file.passwordHash);
    if (!match) {
        const bannedNow = recordFailure(ip, fileId);
        await sendDiscordAlert({
            ip,
            userAgent: req.headers['user-agent'] || 'unknown',
            timestamp: new Date().toISOString(),
            filename: file.originalName,
            providedNickname: nickname,
            status: 'Wrong Password'
        });
        if (bannedNow) {
            await sendDiscordAlert({
                ip,
                userAgent: req.headers['user-agent'] || 'unknown',
                timestamp: new Date().toISOString(),
                filename: file.originalName,
                providedNickname: nickname,
                status: 'Timeout/Ban Issued'
            });
        }
        return res.status(403).json({ error: 'invalid credentials' });
    }

    // success, reset attempts
    attemptMap.delete(makeKey(ip, fileId));
    const fullPath = path.join(UPLOAD_DIR, file.filename);
    res.download(fullPath, file.originalName, (err) => {
        if (err) {
            console.error('download error', err && err.message);
            return;
        }
        // notify Discord about successful authenticated download
        const ipAddr = req.headers['x-forwarded-for'] || req.socket.remoteAddress || req.ip;
        const userAgent = req.headers['user-agent'] || 'unknown';
        sendDiscordDownloadNotification({
            filename: file.originalName,
            userInfo: nickname || file.nickname || 'unknown',
            ip: ipAddr,
            userAgent,
            timestamp: new Date().toISOString()
        });
    });
});

// generic error handler
app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ error: 'server error' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server listening on ${PORT}`));
