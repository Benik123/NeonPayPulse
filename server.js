require('dotenv').config();
const express = require('express');
const session = require('express-session');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit'); 
const helmet = require('helmet');
const cors = require('cors');
const { body, validationResult } = require('express-validator');

const app = express();
const PORT = process.env.PORT || 3000;

// Důležité pro Railway a cloudové proxy, aby správně fungovaly limity a IP adresy
app.set('trust proxy', 1);

app.disable('x-powered-by');

const allowedOrigins = [
    'http://127.0.0.1:5500', 
    'http://localhost:5500', 
    'http://localhost:3000', 
    'http://127.0.0.1:3000',
    'https://neonpaypulse.com',
    'https://www.neonpaypulse.com'
];

app.use(cors({
    origin: (origin, callback) => {
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) === -1 && !origin.endsWith('.up.railway.app')) {
            return callback(new Error('CORS blokace: Nepovolený původ.'), false);
        }
        return callback(null, true);
    },
    credentials: true
}));

app.use(helmet({
    contentSecurityPolicy: false,
    frameguard: { action: 'deny' },
    referrerPolicy: { policy: 'same-origin' }
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, 'public')));

const isProduction = process.env.NODE_ENV === 'production';

app.use(session({
    secret: process.env.SESSION_SECRET || 'tajny_klic_pro_lokal',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        maxAge: 24 * 60 * 60 * 1000,
        httpOnly: true,
        secure: isProduction,
        sameSite: isProduction ? 'strict' : 'lax'
    }
}));

app.use((req, res, next) => {
    if (req.body && typeof req.body === 'object') {
        for (let key in req.body) {
            if (Array.isArray(req.body[key])) {
                req.body[key] = req.body[key][0];
            }
        }
    }
    next();
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, error: 'Příliš mnoho neúspěšných pokusů o přihlášení. Zkuste to prosím za 15 minut.' }
});

const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, error: 'Příliš mnoho registračních pokusů z této IP adresy. Zkuste to za hodinu.' }
});

const earnLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 15, 
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, error: 'Příliš mnoho požadavků. Zpomal prosím.' }
});

const resetLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 3,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, error: 'Příliš mnoho pokusů o reset hesla. Zkuste to za hodinu.' }
});

const csrfProtection = (req, res, next) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
        return next();
    }

    const origin = req.get('origin');
    const referer = req.get('referer');
    
    if (!origin && !referer) {
        return next();
    }

    const isValidOrigin = origin && (allowedOrigins.some(allowed => origin.startsWith(allowed)) || origin.endsWith('.up.railway.app'));
    const isValidReferer = referer && (allowedOrigins.some(allowed => referer.startsWith(allowed)) || referer.endsWith('.up.railway.app'));

    if (!isValidOrigin && !isValidReferer) {
        const clientIp = req.ip || 'unknown';
        db.run(`INSERT INTO security_logs (ip, event, details) VALUES (?, ?, ?)`, [clientIp, 'CSRF_VIOLATION', `Origin: ${origin}, Referer: ${referer}`]);
        return res.status(403).json({ success: false, error: 'CSRF ochrana: Neplatný původ požadavku.' });
    }

    next();
};

app.use(csrfProtection);

app.get('/dashboard.html', (req, res, next) => {
    if (!req.session.username) {
        return res.redirect('/login.html');
    }
    next();
});

const dbFile = path.join(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbFile, (err) => {
    if (err) {
        console.error('Chyba při otevírání databáze:', err.message);
    } else {
        console.log('Připojeno k SQLite databázi.');
    }
});

db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email TEXT UNIQUE,
    password TEXT,
    balance REAL DEFAULT 0.00,
    hasBooster INTEGER DEFAULT 0,
    referralCode TEXT,
    referredBy TEXT,
    lastDailyDate TEXT,
    lastClickAd INTEGER DEFAULT 0,
    lastVideo INTEGER DEFAULT 0,
    lastSurvey INTEGER DEFAULT 0,
    lastIp TEXT,
    failedLoginAttempts INTEGER DEFAULT 0,
    lockUntil DATETIME DEFAULT NULL
)`);

db.run(`CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    action TEXT,
    amount REAL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

db.run(`CREATE TABLE IF NOT EXISTS password_resets (
    email TEXT,
    token TEXT,
    expiresAt DATETIME
)`);

db.run(`CREATE TABLE IF NOT EXISTS security_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    event TEXT,
    details TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

app.post('/api/delete-account', async (req, res) => {
    if (!req.session.username) return res.status(401).json({ success: false, error: 'Nepřihlášen' });
    const { password } = req.body;
    db.get(`SELECT password FROM users WHERE username = ?`, [req.session.username], async (err, user) => {
        if (err || !user) return res.json({ success: false, error: 'Uživatel nenalezen.' });
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.json({ success: false, error: 'Nesprávné heslo.' });
        db.run(`DELETE FROM users WHERE username = ?`, [req.session.username], () => {
            req.session.destroy();
            res.json({ success: true });
        });
    });
});

app.post('/api/register', registerLimiter, [
    body('username').trim().escape().isLength({ min: 3, max: 20 }).withMessage('Uživatelské jméno musí mít 3 až 20 znaků.'),
    body('email').isEmail().normalizeEmail().withMessage('Zadej platnou emailovou adresu.'),
    body('password').isLength({ min: 6 }).withMessage('Heslo musí mít alespoň 6 znaků.')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.json({ success: false, error: errors.array()[0].msg });
    }

    const { username, email, password, refCode, website } = req.body; 
    
    if (website) {
        db.run(`INSERT INTO security_logs (ip, event, details) VALUES (?, ?, ?)`, [req.ip || 'unknown', 'BOT_DETECTED', `Registration bot trap triggered`]);
        return res.status(403).json({ success: false, error: 'Detekován bot.' });
    }

    const clientIp = req.ip || 'unknown';

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const myRefCode = username + Math.floor(1000 + Math.random() * 9000);

        const query = `INSERT INTO users (username, email, password, balance, hasBooster, referralCode, referredBy, lastDailyDate, lastClickAd, lastVideo, lastSurvey, lastIp) VALUES (?, ?, ?, 0.00, 0, ?, ?, NULL, 0, 0, 0, ?)`;
        
        db.run(query, [username, email, hashedPassword, myRefCode, refCode || null, clientIp], function(err) {
            if (err) {
                return res.json({ success: false, error: 'Uživatelské jméno nebo email je již obsazený.' });
            }

            db.run(`INSERT INTO logs (username, action, amount) VALUES (?, ?, ?)`, [username, 'registracia', 0]);

            req.session.username = username;
            res.json({ success: true });
        });
    } catch (error) {
        res.json({ success: false, error: 'Chyba při zpracování hesla.' });
    }
});

app.post('/api/login', loginLimiter, [
    body('username').trim().escape().notEmpty().withMessage('Zadej uživatelské jméno.'),
    body('password').notEmpty().withMessage('Zadej heslo.')
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.json({ success: false, error: errors.array()[0].msg });
    }

    const { username, password } = req.body;
    const clientIp = req.ip || 'unknown';

    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (err || !user) {
            return res.json({ success: false, error: 'Nesprávné uživatelské jméno nebo heslo.' });
        }

        if (user.lockUntil && new Date(user.lockUntil) > new Date()) {
            return res.status(429).json({ success: false, error: 'Účet je dočasně uzamčen kvůli příliš mnoha neúspěšným pokusům. Zkuste to za 15 minut.' });
        }

        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            const failedAttempts = (user.failedLoginAttempts || 0) + 1;
            let lockTime = null;

            if (failedAttempts >= 5) {
                lockTime = new Date(Date.now() + 15 * 60 * 1000).toISOString();
                db.run(`UPDATE users SET failedLoginAttempts = ?, lockUntil = ? WHERE username = ?`, [failedAttempts, lockTime, username]);
            } else {
                db.run(`UPDATE users SET failedLoginAttempts = ? WHERE username = ?`, [failedAttempts, username]);
            }

            db.run(`INSERT INTO security_logs (ip, event, details) VALUES (?, ?, ?)`, [clientIp, 'FAILED_LOGIN', `Failed login for: ${username} (Attempt ${failedAttempts})`]);
            return res.json({ success: false, error: 'Nesprávné uživatelské jméno nebo heslo.' });
        }

        db.run(`UPDATE users SET lastIp = ?, failedLoginAttempts = 0, lockUntil = NULL WHERE username = ?`, [clientIp, username]);

        req.session.username = username;
        res.json({ success: true });
    });
});

app.post('/api/request-password-reset', resetLimiter, [
    body('email').isEmail().normalizeEmail().withMessage('Zadej platnou emailovou adresu.')
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.json({ success: false, error: errors.array()[0].msg });
    }

    const { email } = req.body;
    
    db.get(`SELECT username FROM users WHERE email = ?`, [email], (err, user) => {
        if (!user) {
            return res.json({ success: true, message: 'Pokud je e-mail registrován, byl na něj odeslán odkaz pro obnovení.' });
        }

        const token = crypto.randomBytes(20).toString('hex');
        const expiresAt = new Date(Date.now() + 3600000).toISOString();

        db.run(`INSERT INTO password_resets (email, token, expiresAt) VALUES (?, ?, ?)`, [email, token, expiresAt], () => {
            console.log(`[RESET HESLA] Odkaz pro ${email}: http://localhost:3000/reset-password.html?token=${token}`);
            res.json({ success: true, message: 'Pokud je e-mail registrován, byl na něj odeslán odkaz pro obnovení.' });
        });
    });
});

app.post('/api/reset-password', [
    body('token').notEmpty().withMessage('Chybí token.'),
    body('newPassword').isLength({ min: 6 }).withMessage('Nové heslo musí mít alespoň 6 znaků.')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.json({ success: false, error: errors.array()[0].msg });
    }

    const { token, newPassword } = req.body;

    db.get(`SELECT * FROM password_resets WHERE token = ? AND expiresAt > ?`, [token, new Date().toISOString()], async (err, row) => {
        if (!row) {
            return res.json({ success: false, error: 'Neplatný nebo již vypršený token pro obnovu hesla.' });
        }

        try {
            const hashedPassword = await bcrypt.hash(newPassword, 10);
            db.run(`UPDATE users SET password = ? WHERE email = ?`, [hashedPassword, row.email], () => {
                db.run(`DELETE FROM password_resets WHERE token = ?`, [token]);
                res.json({ success: true, message: 'Heslo bylo úspěšně změněno! Nyní se můžeš přihlásit.' });
            });
        } catch (error) {
            res.json({ success: false, error: 'Chyba při zpracování nového hesla.' });
        }
    });
});

app.post('/api/logout', (req, res) => {
    req.session.destroy(() => {
        res.json({ success: true });
    });
});

app.get('/api/user', (req, res) => {
    if (!req.session.username) {
        return res.status(401).json({ success: false, error: 'Nepřihlášen' });
    }

    db.get(`SELECT username, email, balance, hasBooster, referralCode FROM users WHERE username = ?`, [req.session.username], (err, user) => {
        if (err || !user) {
            return res.status(404).json({ success: false, error: 'Uživatel nenalezen' });
        }
        res.json({
            success: true,
            username: user.username,
            email: user.email,
            balance: Number(user.balance.toFixed(2)),
            hasBooster: user.hasBooster,
            referralCode: user.referralCode || 'Neznámý'
        });
    });
});

app.post('/api/buy-vip', earnLimiter, (req, res) => {
    if (!req.session.username) return res.status(401).json({ success: false, error: 'Nepřihlášen' });

    const vipPrice = 200.00;

    db.get(`SELECT balance, hasBooster FROM users WHERE username = ?`, [req.session.username], (err, user) => {
        if (err || !user) return res.json({ success: false, error: 'Uživatel nenalezen.' });

        if (user.hasBooster === 1) {
            return res.json({ success: false, error: 'VIP balíček již máš aktivní!' });
        }

        if (user.balance < vipPrice) {
            return res.json({ success: false, error: `Nemáš dostatek peněz. VIP stojí ${vipPrice} Kč, tvůj zůstatek je ${user.balance} Kč.` });
        }

        const newBalance = Number((user.balance - vipPrice).toFixed(2));

        db.run(`UPDATE users SET balance = ?, hasBooster = 1 WHERE username = ?`, [newBalance, req.session.username], (updateErr) => {
            if (updateErr) return res.json({ success: false, error: 'Chyba databáze při nákupu VIP.' });

            db.run(`INSERT INTO logs (username, action, amount) VALUES (?, ?, ?)`, [req.session.username, 'nákup-vip', -vipPrice]);

            res.json({
                success: true,
                newBalance: newBalance,
                message: 'Gratuluji! VIP balíček byl úspěšně aktivován.'
            });
        });
    });
});

app.get('/api/referral-stats', (req, res) => {
    if (!req.session.username) return res.status(401).json({ success: false });

    db.get(`SELECT referralCode FROM users WHERE username = ?`, [req.session.username], (err, user) => {
        if (!user || !user.referralCode) return res.json({ success: false, l1Count: 0, l2Count: 0, totalReferred: 0 });

        db.all(`SELECT username, referralCode, referredBy FROM users`, [], (err, allUsers) => {
            if (err) return res.json({ success: false, l1Count: 0, l2Count: 0, totalReferred: 0 });

            const level1 = allUsers.filter(u => u.referredBy === user.referralCode);
            const level1Codes = level1.map(u => u.referralCode).filter(Boolean);
            const level2 = allUsers.filter(u => level1Codes.includes(u.referredBy));

            res.json({
                success: true,
                l1Count: level1.length,
                l2Count: level2.length,
                totalReferred: level1.length + level2.length
            });
        });
    });
});

app.get('/api/logs', (req, res) => {
    if (!req.session.username) {
        return res.status(401).json({ success: false, error: 'Nepřihlášen' });
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    db.get(`SELECT COUNT(*) as count FROM logs WHERE username = ?`, [req.session.username], (err, countRow) => {
        if (err) {
            return res.json({ success: false, error: 'Chyba databáze' });
        }

        const totalLogs = countRow ? countRow.count : 0;
        const totalPages = Math.ceil(totalLogs / limit) || 1;

        db.all(`SELECT action, amount, timestamp FROM logs WHERE username = ? ORDER BY id DESC LIMIT ? OFFSET ?`, [req.session.username, limit, offset], (err, rows) => {
            if (err) {
                return res.json({ success: false, error: 'Chyba databáze' });
            }
            res.json({ 
                success: true, 
                logs: rows,
                totalPages: totalPages 
            });
        });
    });
});

const userLastEarnAttempt = new Map();

app.post('/api/earn', earnLimiter, (req, res) => {
    if (!req.session.username) return res.status(401).json({ success: false, error: 'Nepřihlášen' });

    const { actionType, website } = req.body; 
    if (website) {
        db.run(`INSERT INTO security_logs (ip, event, details) VALUES (?, ?, ?)`, [req.ip || 'unknown', 'BOT_TRAP_EARN', `Earn bot trap triggered by: ${req.session.username}`]);
        return res.status(403).json({ success: false, error: 'Detekován podvodný skript.' });
    }

    const now = Date.now();
    const clientIp = req.ip || 'unknown';

    const lastAttempt = userLastEarnAttempt.get(req.session.username) || 0;
    if (now - lastAttempt < 1000) { 
        return res.status(429).json({ success: false, error: 'Příliš rychlá akce. Zpomal.' });
    }
    userLastEarnAttempt.set(req.session.username, now);

    const configs = {
        'click-ad': { reward: 1.00, cooldown: 3, message: 'Odměna za reklamu byla přičtena!', col: 'lastClickAd' },
        'video': { reward: 2.00, cooldown: 10, message: 'Sledování videa dokončeno!', col: 'lastVideo' },
        'survey': { reward: 20.00, cooldown: 60, message: 'Úspěšně vyplněný dotazník!', col: 'lastSurvey' },
        'daily-bonus': { reward: 5.00, cooldown: 0, message: 'Denní bonus vyzvednut!', col: 'lastDailyDate' }
    };

    if (!configs[actionType]) {
        db.run(`INSERT INTO security_logs (ip, event, details) VALUES (?, ?, ?)`, [clientIp, 'INVALID_EARN_ACTION', `User ${req.session.username} tried: ${actionType}`]);
        return res.json({ success: false, error: 'Neznámá akce.' });
    }

    db.get(`SELECT * FROM users WHERE username = ?`, [req.session.username], (err, user) => {
        if (err || !user) return res.json({ success: false, error: 'Uživatel nenalezen.' });

        if (actionType === 'daily-bonus') {
            const todayStr = new Date().toISOString().split('T')[0];
            if (user.lastDailyDate === todayStr) {
                return res.json({ success: false, error: 'Denní bonus sis již dnes vyzvedl! Přijď zase zítra po půlnoci.' });
            }
            db.run(`UPDATE users SET lastDailyDate = ?, lastIp = ? WHERE username = ?`, [todayStr, clientIp, req.session.username]);
        } else {
            const config = configs[actionType];
            const lastTime = user[config.col] || 0;
            const elapsedSeconds = (now - lastTime) / 1000;

            if (elapsedSeconds < config.cooldown) {
                const waitTime = Math.ceil(config.cooldown - elapsedSeconds);
                return res.json({ success: false, error: `Příliš brzy! Počkej ještě ${waitTime} sekund.` });
            }

            db.run(`UPDATE users SET ${config.col} = ?, lastIp = ? WHERE username = ?`, [now, clientIp, req.session.username]);
        }

        let baseReward = configs[actionType].reward;
        if (user.hasBooster === 1) {
            baseReward *= 2; 
        }

        const userShare = Number((baseReward * 0.50).toFixed(2));
        const level1Share = Number((baseReward * 0.10).toFixed(2));
        const level2Share = Number((baseReward * 0.05).toFixed(2));
        const newBalance = Number((user.balance + userShare).toFixed(2));

        db.run(`UPDATE users SET balance = ? WHERE username = ?`, [newBalance, req.session.username], (updateErr) => {
            if (updateErr) return res.json({ success: false, error: 'Chyba databáze.' });

            db.run(`INSERT INTO logs (username, action, amount) VALUES (?, ?, ?)`, [req.session.username, actionType, userShare]);

            if (user.referredBy) {
                db.get(`SELECT username, balance, referredBy FROM users WHERE referralCode = ?`, [user.referredBy], (err, level1User) => {
                    if (level1User) {
                        const newL1Balance = Number((level1User.balance + level1Share).toFixed(2));
                        db.run(`UPDATE users SET balance = ? WHERE username = ?`, [newL1Balance, level1User.username]);

                        if (level1User.referredBy) {
                            db.get(`SELECT username, balance FROM users WHERE referralCode = ?`, [level1User.referredBy], (err, level2User) => {
                                if (level2User) {
                                    const newL2Balance = Number((level2User.balance + level2Share).toFixed(2));
                                    db.run(`UPDATE users SET balance = ? WHERE username = ?`, [newL2Balance, level2User.username]);
                                }
                            });
                        }
                    }
                });
            }

            res.json({
                success: true,
                newBalance: newBalance,
                message: `${configs[actionType].message} Získáváš ${userShare} Kč.`
            });
        });
    });
});

app.use((err, req, res, next) => {
    console.error('[NEOŠETŘENÁ CHYBA]', err.stack);
    res.status(500).json({ success: false, error: 'Nastala neošetřená chyba na serveru.' });
});

// Správné nastavení spuštění pro Railway na '0.0.0.0'
app.listen(PORT, '0.0.0.0', () => {
    console.log(`NeonPayPulse server úspěšně běží na adrese: http://0.0.0.0:${PORT}`);
});