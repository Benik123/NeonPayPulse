console.log("TEST: SERVER SE SPUSTIL A TENTO SOUBOR BĚŽÍ!");
require('dotenv').config();
const express = require('express');
const session = require('express-session');
// Poznámka: connect-sqlite3 obvykle vyžaduje lokální soubor, 
// ale pro provoz v cloudu na Turso ho pro session můžeme nechat padat do paměti nebo do souboru, 
// případně ho upravíme. Teď ho tu necháme, aby ti nepadaly importy.
const SQLiteStore = require('connect-sqlite3')(session);
const path = require('path');
const { createClient } = require('@libsql/client'); // <--- Nová Turso knihovna
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit'); 
const helmet = require('helmet');
const cors = require('cors');
const { body, validationResult } = require('express-validator');

const app = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(cors({
    origin: '*',
    credentials: true
}));

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com"],
            scriptSrcAttr: ["'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            frameAncestors: ["'none'"]
        }
    },
    frameguard: { action: 'deny' },
    referrerPolicy: { policy: 'same-origin' },
    hidePoweredBy: true
}));

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// --- PŘIPOJENÍ K TURSO CLOUD DATABÁZI ---
if (!process.env.TURSO_DATABASE_URL || !process.env.TURSO_AUTH_TOKEN) {
    console.error("CHYBA: V proměnných prostředí chybí TURSO_DATABASE_URL nebo TURSO_AUTH_TOKEN!");
}

const db = createClient({
    url: process.env.TURSO_DATABASE_URL || "libsql://neonpaypulse-ben123.aws-ap-northeast-1.turso.io",
    authToken: process.env.TURSO_AUTH_TOKEN || "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJhIjoicnciLCJleHAiOjIwMzE2ODAzMjcsImlhdCI6MTc4NzQyNzUyNywiaWQiOiIwMWEwMmFmOS00ZTAxLTcwZWYtOTA2My01ZDM0NjQ1NGU1Y2EiLCJraWQiOiJzMFM1OWZLYkk0d3V3VGdwdDNCMmpPRmVxY19ZNmRfajYwZEFVcDBlcUd3IiwicmlkIjoiOWUyMjFhNzMtM2MyNy00M2MxLWJhYWItODY0NjA5MzUyYjc3In0.q595-uJfP4jYLqAAEIagHt4WvX3HliPWvCoksv8TBKqy8o6Nw54lsnC38zkS-VPon0taPliOxnDCHTmS0omdAw",
});

console.log("===> POUŽÍVÁM TURSO CLOUD DATABÁZI");

// --- OKAMŽITÁ INICIALIZACE TABULEK V CLOUDU ---
async function initDatabase() {
    try {
        await db.execute(`
            CREATE TABLE IF NOT EXISTS users (
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
                lastGameTask INTEGER DEFAULT 0,
                lastWebTask INTEGER DEFAULT 0,
                lastRegTask INTEGER DEFAULT 0,
                lastReviewTask INTEGER DEFAULT 0,
                lastSocialTask INTEGER DEFAULT 0,
                lastIp TEXT,
                failedLoginAttempts INTEGER DEFAULT 0,
                lockUntil DATETIME DEFAULT NULL
            );
        `);

        await db.execute(`
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                action TEXT,
                amount REAL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        `);

        await db.execute(`
            CREATE TABLE IF NOT EXISTS payouts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                amount REAL,
                method TEXT,
                details TEXT,
                status TEXT DEFAULT 'pending',
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        `);

        await db.execute(`
            CREATE TABLE IF NOT EXISTS password_resets (
                email TEXT,
                token TEXT,
                expiresAt DATETIME
            );
        `);

        await db.execute(`
            CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                event TEXT,
                details TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        `);

        console.log("===> TABULKY V TURSO DATABÁZI BYLY ÚSPĚŠNĚ VYTVOŘENY/OVĚŘENY");
    } catch (err) {
        console.error("Chyba při inicializaci tabulek v Turso:", err);
    }
}

initDatabase();

app.use(session({
    store: new SQLiteStore({ 
        db: 'sessions.sqlite', 
        dir: dataDir 
    }),
    secret: process.env.SESSION_SECRET || 'tajny_klic_pro_lokal',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        maxAge: 24 * 60 * 60 * 1000,
        httpOnly: true,
        secure: isProduction,
        sameSite: isProduction ? 'strict' : 'lax'
    }
}))

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

const payoutLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 3,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, error: 'Příliš mnoho žádostí o výplatu z této IP adresy.' }
});

const contactLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 3,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, error: 'Příliš mnoho zpráv z této IP adresy. Zkuste to za hodinu.' }
});

const resetLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 3,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, error: 'Příliš mnoho pokusů o reset hesla. Zkuste to za hodinu.' }
});

const sensitiveActionLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, error: 'Příliš mnoho požadavků. Zkuste to za chvíli.' }
});

db.run('PRAGMA journal_mode = WAL');

function saveDatabase() {
    return true;
}

app.use((req, res, next) => {
    if (!req.session.csrfToken) {
        req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    }
    res.locals.csrfToken = req.session.csrfToken;
    next();
});

const csrfProtection = (req, res, next) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
        return next();
    }
    const clientToken = req.headers['x-csrf-token'] || (req.body && req.body._csrf);
    if (!clientToken || clientToken !== req.session.csrfToken) {
        return res.status(403).json({ success: false, error: 'Neplatný nebo chybějící CSRF token.' });
    }
    next();
};

app.use(csrfProtection);

app.get('/api/csrf-token', (req, res) => {
    res.json({ success: true, csrfToken: req.session.csrfToken });
});

app.get('/ping', (req, res) => {
    res.send('PONG - Server žije!');
});

app.get('/dashboard.html', (req, res, next) => {
    if (!req.session.username) {
        return res.redirect('/login.html');
    }
    next();
});

app.get('/api/admin/security-logs', (req, res) => {
    const adminKey = req.headers['x-admin-key'];
    if (!adminKey || adminKey !== (process.env.ADMIN_SECRET || 'tajny_admin_klic')) {
        return res.status(403).json({ success: false, error: 'Přístup odepřen.' });
    }

    const logs = db.prepare(`SELECT * FROM security_logs ORDER BY id DESC LIMIT 50`).all();
    res.json({ success: true, logs: logs || [] });
});

app.post('/api/contact', contactLimiter, [
    body('name').trim().escape().notEmpty().withMessage('Chybí jméno.'),
    body('email').isEmail().normalizeEmail().withMessage('Neplatný e-mail.'),
    body('message').trim().escape().isLength({ min: 10, max: 1000 }).withMessage('Zpráva musí mít 10 až 1000 znaků.')
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.json({ success: false, error: errors.array()[0].msg });
    }

    const { name, email, message } = req.body;
    const clientIp = req.ip || 'unknown';

    db.prepare(`INSERT INTO security_logs (ip, event, details) VALUES (?, ?, ?)`).run(
        clientIp, 'CONTACT_FORM', `Message from ${email} (${name})`
    );
    saveDatabase();

    res.json({ success: true, message: 'Děkujeme! Vaše zpráva byla úspěšně odeslána týmu podpoře.' });
});

app.post('/api/delete-account', sensitiveActionLimiter, async (req, res) => {
    if (!req.session.username) {
        return res.status(401).json({ success: false, error: 'Nepřihlášen' });
    }
    
    const { password } = req.body;
    const user = db.prepare(`SELECT password FROM users WHERE username = ?`).get(req.session.username);

    if (!user) {
        return res.json({ success: false, error: 'Uživatel nenalezen.' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
        return res.json({ success: false, error: 'Nesprávné heslo.' });
    }

    try {
        db.prepare(`DELETE FROM users WHERE username = ?`).run(req.session.username);
        saveDatabase();
        req.session.destroy();
        res.json({ success: true });
    } catch (err) {
        res.json({ success: false, error: 'Chyba při mazání účtu.' });
    }
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
    const clientIp = req.ip || 'unknown';

    if (website) {
        db.prepare(`INSERT INTO security_logs (ip, event, details) VALUES (?, ?, ?)`).run(clientIp, 'BOT_DETECTED', `Registration bot trap triggered`);
        saveDatabase();
        return res.status(403).json({ success: false, error: 'Detekován bot.' });
    }

    const ipCheck = db.prepare(`SELECT COUNT(*) as count FROM users WHERE lastIp = ?`).get(clientIp);
    if (ipCheck && ipCheck.count >= 3) {
        db.prepare(`INSERT INTO security_logs (ip, event, details) VALUES (?, ?, ?)`).run(clientIp, 'MULTI_ACCOUNT_BLOCK', `Too many accounts from IP: ${clientIp}`);
        saveDatabase();
        return res.status(403).json({ success: false, error: 'Z této IP adresy již bylo zaregistrováno maximální množství účtů.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const myRefCode = username + Math.floor(1000 + Math.random() * 9000);

        db.prepare(`INSERT INTO users (username, email, password, balance, hasBooster, referralCode, referredBy, lastDailyDate, lastClickAd, lastVideo, lastSurvey, lastIp) VALUES (?, ?, ?, 0.00, 0, ?, ?, NULL, 0, 0, 0, ?)`).run( 
            username, email, hashedPassword, myRefCode, refCode || null, clientIp
        );
    
        db.prepare(`INSERT INTO logs (username, action, amount) VALUES (?, ?, ?)`).run(username, 'registracia', 0);

        saveDatabase();
        req.session.username = username;
        res.json({ success: true });
    } catch (err) {
        console.error("CHYBA V REGISTRACI:", err.message);
        if (err.message.includes('UNIQUE constraint failed')) {
            if (err.message.includes('users.username')) {
                return res.json({ success: false, error: 'Uživatelské jméno je již obsazené.' });
            }
            if (err.message.includes('users.email')) {
                return res.json({ success: false, error: 'E-mailová adresa je již zaregistrovaná.' });
            }
            return res.json({ success: false, error: 'Uživatelské jméno nebo email je již obsazený.' });
        }
        return res.json({ success: false, error: 'Chyba databáze: ' + err.message });
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
        if (!user) {
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
            
            saveDatabase();
            return res.json({ success: false, error: 'Nesprávné uživatelské jméno nebo heslo.' });
        }

        db.run(`UPDATE users SET lastIp = ?, failedLoginAttempts = 0, lockUntil = NULL WHERE username = ?`, [clientIp, username], () => {
            saveDatabase();
            req.session.username = username;
            res.json({ success: true });
        });
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
            saveDatabase();
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
            
            db.run(`UPDATE users SET password = ? WHERE email = ?`, [hashedPassword, row.email]);
            db.run(`DELETE FROM password_resets WHERE token = ?`, [token], () => {
                saveDatabase();
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

    db.get(`SELECT id, username, email, balance, hasBooster, referralCode FROM users WHERE username = ?`, [req.session.username], (err, user) => {
        if (err || !user) {
            return res.status(404).json({ success: false, error: 'Uživatel nenalezen' });
        }

        const currentBalance = user.balance !== null && user.balance !== undefined ? Number(user.balance) : 0.00;

        res.json({
            success: true,
            id: user.id,
            username: user.username,
            email: user.email,
            balance: Number(currentBalance.toFixed(2)),
            hasBooster: user.hasBooster || 0,
            referralCode: user.referralCode || 'Neznámý'
        });
    });
});

app.post('/api/buy-vip', earnLimiter, (req, res) => {
    if (!req.session.username) return res.status(401).json({ success: false, error: 'Nepřihlášen' });

    const { actionType } = req.body;

    const vipPrices = {
        'buy-vip-bronze': 89.00,
        'buy-vip-silver': 189.00,
        'buy-vip-gold': 289.00,
        'buy-vip': 200.00
    };

    const vipPrice = vipPrices[actionType] || 200.00;

    db.get(`SELECT balance, hasBooster FROM users WHERE username = ?`, [req.session.username], (err, user) => {
        if (!user) {
            return res.json({ success: false, error: 'Uživatel nenalezen.' });
        }
        if (user.hasBooster === 1) {
            return res.json({ success: false, error: 'VIP balíček již máš aktivní!' });
        }
        if (user.balance < vipPrice) {
            return res.json({ success: false, error: `Nemáš dostatek peněz. VIP stojí ${vipPrice} Kč, tvůj zůstatek je ${user.balance} Kč.` });
        }

        const newBalance = Number((user.balance - vipPrice).toFixed(2));

        db.run(`UPDATE users SET balance = ?, hasBooster = 1 WHERE username = ?`, [newBalance, req.session.username]);
        db.run(`INSERT INTO logs (username, action, amount) VALUES (?, ?, ?)`, [req.session.username, 'nákup-vip', -vipPrice], () => {
            saveDatabase();
            res.json({
                success: true,
                newBalance: newBalance,
                message: 'Gratuluji! VIP balíček byl úspěšně aktivován.'
            });
        });
    });
});

app.post('/api/request-payout', payoutLimiter, [
    body('method').notEmpty().withMessage('Chybí platební metoda.'),
    body('details').notEmpty().withMessage('Chybí platební údaje.')
], (req, res) => {
    if (!req.session.username) return res.status(401).json({ success: false, error: 'Nepřihlášen' });

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.json({ success: false, error: errors.array()[0].msg });
    }

    const { method, details } = req.body;
    const minPayoutCzk = 200.00;

    db.get(`SELECT balance FROM users WHERE username = ?`, [req.session.username], (err, user) => {
        if (!user) {
            return res.json({ success: false, error: 'Uživatel nenalezen.' });
        }
        if (user.balance < minPayoutCzk) {
            return res.json({ success: false, error: `Minimální částka pro výplatu je 200 Kč. Tvůj zůstatek je ${user.balance.toFixed(2)} Kč.` });
        }

        const payoutAmount = Number(user.balance.toFixed(2));
        const newBalance = 0.00;

        db.run(`UPDATE users SET balance = ? WHERE username = ?`, [newBalance, req.session.username]);
        db.run(`INSERT INTO payouts (username, amount, method, details, status) VALUES (?, ?, ?, ?, 'pending')`, [req.session.username, payoutAmount, method, details]);
        db.run(`INSERT INTO logs (username, action, amount) VALUES (?, ?, ?)`, [req.session.username, 'vyplata-zadost', -payoutAmount], () => {
            saveDatabase();
            res.json({
                success: true,
                newBalance: newBalance,
                message: 'Žádost o výplatu byla úspěšně odeslána k ručnímu auditu!'
            });
        });
    });
});

app.get('/api/referral-stats', (req, res) => {
    if (!req.session.username) return res.status(401).json({ success: false });

    const user = db.prepare(`SELECT referralCode FROM users WHERE username = ?`).get(req.session.username);

    if (!user || !user.referralCode) return res.json({ success: false, l1Count: 0, l2Count: 0, totalReferred: 0 });

    const allUsers = db.prepare(`SELECT username, referralCode, referredBy FROM users`).all();

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

app.get('/api/logs', (req, res) => {
    if (!req.session.username) {
        return res.status(401).json({ success: false, error: 'Nepřihlášen' });
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    const countRow = db.prepare(`SELECT COUNT(*) as count FROM logs WHERE username = ?`).get(req.session.username);
    
    const totalLogs = countRow ? countRow.count : 0;
    const totalPages = Math.ceil(totalLogs / limit) || 1;

    const rows = db.prepare(`SELECT action, amount, timestamp FROM logs WHERE username = ? ORDER BY id DESC LIMIT ? OFFSET ?`).all(req.session.username, limit, offset);

    res.json({ 
        success: true, 
        logs: rows,
        totalPages: totalPages 
    });
});

const userLastEarnAttempt = new Map();

app.post('/api/earn', earnLimiter, (req, res) => {
    if (!req.session.username) return res.status(401).json({ success: false, error: 'Nepřihlášen' });

    const { actionType, website } = req.body; 
    const clientIp = req.ip || 'unknown';

    if (website) {
        db.run(`INSERT INTO security_logs (ip, event, details) VALUES (?, ?, ?)`, [clientIp, 'BOT_TRAP_EARN', `Earn bot trap triggered by: ${req.session.username}`]);
        saveDatabase();
        return res.status(403).json({ success: false, error: 'Detekován podvodný skript.' });
    }

    const now = Date.now();
    const lastAttempt = userLastEarnAttempt.get(req.session.username) || 0;
    if (now - lastAttempt < 1000) { 
        return res.status(429).json({ success: false, error: 'Příliš rychlá akce. Zpomal.' });
    }
    userLastEarnAttempt.set(req.session.username, now);

    const configs = {
        'click-ad': { reward: 1.00, cooldown: 3, message: 'Odměna za reklamu byla přičtena!', col: 'lastClickAd' },
        'video': { reward: 2.00, cooldown: 10, message: 'Sledování videa dokončeno!', col: 'lastVideo' },
        'survey': { reward: 20.00, cooldown: 60, message: 'Úspěšně vyplněný dotazník!', col: 'lastSurvey' },
        'daily-bonus': { reward: 5.00, cooldown: 0, message: 'Denní bonus vyzvednut!', col: 'lastDailyDate' },
        'task-game-1': { reward: 500.00, cooldown: 300, message: 'Testování hry ověřeno a odměna přičtena!', col: 'lastGameTask' },
        'task-game': { reward: 500.00, cooldown: 300, message: 'Testování hry ověřeno a odměna přičtena!', col: 'lastGameTask' },
        'task-web-1': { reward: 100.00, cooldown: 120, message: 'Zpětná vazba na web úspěšně odeslána!', col: 'lastWebTask' },
        'task-reg-1': { reward: 150.00, cooldown: 120, message: 'Partnerská registrace ověřena!', col: 'lastRegTask' },
        'task-reg': { reward: 150.00, cooldown: 120, message: 'Partnerská registrace ověřena!', col: 'lastRegTask' },
        'task-review-1': { reward: 50.00, cooldown: 60, message: 'Recenze schválena a odměněna!', col: 'lastReviewTask' },
        'task-social-1': { reward: 3.00, cooldown: 5, message: 'Mikroúkol na sociální síti splněn!', col: 'lastSocialTask' }
    };

    if (!configs[actionType]) {
        db.run(`INSERT INTO security_logs (ip, event, details) VALUES (?, ?, ?)`, [clientIp, 'INVALID_EARN_ACTION', `User ${req.session.username} tried: ${actionType}`]);
        saveDatabase();
        return res.json({ success: false, error: 'Neznámá akce.' });
    }

    db.get(`SELECT * FROM users WHERE username = ?`, [req.session.username], (err, user) => {
        if (!user) return res.json({ success: false, error: 'Uživatel nenalezen.' });

        if (actionType === 'daily-bonus') {
            const todayStr = new Date().toISOString().split('T')[0];
            if (user.lastDailyDate === todayStr) {
                return res.json({ success: false, error: 'Denní bonus sis již dnes vyzvedl! Přijď zase zítra po půlnoci.' });
            }
        } else {
            const config = configs[actionType];
            const lastTime = user[config.col] || 0;
            const elapsedSeconds = (now - lastTime) / 1000;

            if (elapsedSeconds < config.cooldown) {
                const waitTime = Math.ceil(config.cooldown - elapsedSeconds);
                return res.json({ success: false, error: `Příliš brzy! Počkej ještě ${waitTime} sekund.` });
            }
        }

        let baseReward = configs[actionType].reward;
        if (user.hasBooster === 1) {
            baseReward *= 2; 
        }

        const userShare = Number((baseReward * 0.50).toFixed(2));
        const level1Share = Number((baseReward * 0.10).toFixed(2));
        const level2Share = Number((baseReward * 0.05).toFixed(2));
        const newBalance = Number((user.balance + userShare).toFixed(2));

        if (actionType === 'daily-bonus') {
            const todayStr = new Date().toISOString().split('T')[0];
            db.run(`UPDATE users SET lastDailyDate = ?, lastIp = ?, balance = ? WHERE username = ?`, [todayStr, clientIp, newBalance, req.session.username]);
        } else {
            const config = configs[actionType];
            db.run(`UPDATE users SET ${config.col} = ?, lastIp = ?, balance = ? WHERE username = ?`, [now, clientIp, newBalance, req.session.username]);
        }

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

        saveDatabase();
        return res.json({
            success: true,
            newBalance: newBalance,
            message: `${configs[actionType].message} Získáváš ${userShare} Kč.`
        });
    });
});

app.use((err, req, res, next) => {
    console.error('[NEOŠETŘENÁ CHYBA]', err.stack);
    res.status(500).json({ success: false, error: 'Nastala neošetřená chyba na serveru.' });
});

// Spuštění serveru
app.listen(PORT, '0.0.0.0', () => {
    console.log(`NeonPayPulse server úspěšně běží na adrese: http://0.0.0.0:${PORT}`);
});