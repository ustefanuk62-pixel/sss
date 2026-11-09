// Сервер сайта: раздаёт файлы из public + регистрация/вход (cookie) + счётчик + скачивание.
// Работает без установки пакетов (только встроенные модули Node.js).
// Данные пользователей хранятся в папке data/ рядом с этим файлом (создаётся сама).
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const mysql = require('mysql2/promise');

const ROOT = path.join(__dirname, 'public');
const OLD_DATA = path.join(__dirname, 'data'); // старое хранилище (только для переноса в базу)
const PORT = Number(process.env.SERVER_PORT || process.env.PORT || 3000);

// true  = скачивать песни могут только вошедшие пользователи
// false = скачивать могут все
const REQUIRE_LOGIN_FOR_DOWNLOAD = true;

const SESSION_DAYS = 30;
const COOKIE = 'sid';

const TYPES = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8', '.png': 'image/png', '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg', '.webp': 'image/webp', '.gif': 'image/gif',
  '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.mp3': 'audio/mpeg',
  '.m4a': 'audio/mp4', '.ogg': 'audio/ogg', '.wav': 'audio/wav', '.mp4': 'video/mp4',
};

/* ---------- подключение к MySQL ---------- */
// Данные для входа берутся из db.json (рядом с index.js) или из переменных окружения DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME.
let cfg = {};
try { cfg = JSON.parse(fs.readFileSync(path.join(__dirname, 'db.json'), 'utf8')); } catch (e) {}
const pool = mysql.createPool({
  host: process.env.DB_HOST || cfg.host,
  port: Number(process.env.DB_PORT || cfg.port || 3306),
  user: process.env.DB_USER || cfg.user,
  password: process.env.DB_PASSWORD || cfg.password,
  database: process.env.DB_NAME || cfg.database,
  charset: 'utf8mb4',
  waitForConnections: true,
  connectionLimit: 5,
  connectTimeout: 10000,
});

async function initDb() {
  await pool.query(`CREATE TABLE IF NOT EXISTS users (
    ukey VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL PRIMARY KEY,
    name VARCHAR(64) CHARACTER SET utf8mb4 NOT NULL,
    salt CHAR(32) NOT NULL,
    hash CHAR(128) NOT NULL,
    created BIGINT NOT NULL
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);
  await pool.query(`CREATE TABLE IF NOT EXISTS sessions (
    token_hash CHAR(64) NOT NULL PRIMARY KEY,
    ukey VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    exp BIGINT NOT NULL,
    INDEX (exp),
    INDEX (ukey)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  // Один раз переносим старых пользователей из data/users.json, если таблица пустая
  const [[{ n }]] = await pool.query('SELECT COUNT(*) AS n FROM users');
  const old = path.join(OLD_DATA, 'users.json');
  if (n === 0 && fs.existsSync(old)) {
    try {
      const list = JSON.parse(fs.readFileSync(old, 'utf8'));
      let moved = 0;
      for (const [k, u] of Object.entries(list)) {
        await pool.query('INSERT IGNORE INTO users (ukey, name, salt, hash, created) VALUES (?,?,?,?,?)',
          [k, u.name, u.salt, u.hash, u.created || Date.now()]);
        moved++;
      }
      console.log('Перенесено пользователей из data/users.json: ' + moved);
    } catch (e) { console.error('Не удалось перенести старых пользователей:', e.message); }
  }
  await pool.query('DELETE FROM sessions WHERE exp < ?', [Date.now()]);
}
setInterval(() => { pool.query('DELETE FROM sessions WHERE exp < ?', [Date.now()]).catch(() => {}); }, 3600 * 1000).unref();

/* ---------- пароли и сессии ---------- */
function hashPass(pass, salt) { return crypto.scryptSync(pass, salt, 64).toString('hex'); }
function sha(s) { return crypto.createHash('sha256').update(s).digest('hex'); }
async function newSession(userKey) {
  const token = crypto.randomBytes(32).toString('hex');
  await pool.query('INSERT INTO sessions (token_hash, ukey, exp) VALUES (?,?,?)',
    [sha(token), userKey, Date.now() + SESSION_DAYS * 86400 * 1000]);
  return token;
}
function parseCookies(req) {
  const out = {};
  String(req.headers.cookie || '').split(';').forEach(p => {
    const i = p.indexOf('='); if (i < 0) return;
    try { out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); } catch (e) {}
  });
  return out;
}
async function currentUser(req) {
  const t = parseCookies(req)[COOKIE]; if (!t) return null;
  const [rows] = await pool.query(
    'SELECT u.ukey, u.name FROM sessions s JOIN users u ON u.ukey = s.ukey WHERE s.token_hash = ? AND s.exp > ? LIMIT 1',
    [sha(t), Date.now()]);
  return rows.length ? { key: rows[0].ukey, name: rows[0].name } : null;
}
function isHttps(req) { return !!req.socket.encrypted || String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https'; }
function cookie(req, name, value, maxAgeSec, httpOnly) {
  return `${name}=${encodeURIComponent(value)}; Path=/; Max-Age=${maxAgeSec}; SameSite=Lax${httpOnly ? '; HttpOnly' : ''}${isHttps(req) ? '; Secure' : ''}`;
}

/* ---------- ограничения частоты ---------- */
const hits = new Map(); // ключ -> {n, reset}
function limited(key, max, windowMs, count) {
  const now = Date.now(); let h = hits.get(key);
  if (!h || h.reset < now) { h = { n: 0, reset: now + windowMs }; hits.set(key, h); }
  if (count) h.n++;
  return h.n > max;
}
setInterval(() => { const n = Date.now(); for (const [k, h] of hits) if (h.reset < n) hits.delete(k); }, 600 * 1000).unref();
function ipOf(req) { return String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '?'; }

/* ---------- API ---------- */
function send(res, code, obj, extra) {
  const body = JSON.stringify(obj);
  res.writeHead(code, Object.assign({ 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }, extra || {}));
  res.end(body);
}
function readBody(req, cb) {
  if (!/^application\/json/i.test(req.headers['content-type'] || '')) return cb(new Error('type'));
  let size = 0; const chunks = [];
  req.on('data', c => { size += c.length; if (size > 4096) { req.destroy(); cb(new Error('big')); cb = () => {}; } else chunks.push(c); });
  req.on('end', () => { try { cb(null, JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); } catch (e) { cb(new Error('json')); } });
  req.on('error', () => {});
}
const NAME_RE = /^[\p{L}\p{N}_.-]{3,20}$/u;
async function count() { const [[r]] = await pool.query('SELECT COUNT(*) AS n FROM users'); return r.n; }
function readBodyP(req) { return new Promise((ok, no) => readBody(req, (e, b) => e ? no(e) : ok(b))); }

async function api(req, res, p) {
  if (req.method === 'GET' && p === '/api/stats') return send(res, 200, { count: await count() });
  if (req.method === 'GET' && p === '/api/me') {
    const u = await currentUser(req);
    return send(res, 200, { user: u ? u.name : null, count: await count(), needLogin: REQUIRE_LOGIN_FOR_DOWNLOAD });
  }
  if (req.method !== 'POST') { res.writeHead(405, { Allow: 'GET, POST' }); return res.end(); }

  if (p === '/api/logout') {
    const t = parseCookies(req)[COOKIE];
    if (t) await pool.query('DELETE FROM sessions WHERE token_hash = ?', [sha(t)]);
    return send(res, 200, { ok: true }, { 'Set-Cookie': cookie(req, COOKIE, '', 0, true) });
  }
  if (p !== '/api/register' && p !== '/api/login') return send(res, 404, { error: 'Не найдено' });

  let b;
  try { b = await readBodyP(req); } catch (e) { return send(res, 400, { error: 'Неверный запрос' }); }
  const name = String(b.username || '').trim(), pass = String(b.password || '');
  const key = name.toLowerCase();

  if (p === '/api/register') {
    if (limited('reg:' + ipOf(req), 10, 3600 * 1000, true)) return send(res, 429, { error: 'Слишком много попыток. Попробуй позже.' });
    if (!NAME_RE.test(name)) return send(res, 400, { error: 'Логин: 3–20 символов, буквы, цифры, _ . -' });
    if (pass.length < 6 || pass.length > 128) return send(res, 400, { error: 'Пароль: от 6 до 128 символов' });
    const salt = crypto.randomBytes(16).toString('hex');
    try {
      await pool.query('INSERT INTO users (ukey, name, salt, hash, created) VALUES (?,?,?,?,?)',
        [key, name, salt, hashPass(pass, salt), Date.now()]);
    } catch (e) {
      if (e && e.code === 'ER_DUP_ENTRY') return send(res, 409, { error: 'Такой логин уже занят' });
      throw e;
    }
    const token = await newSession(key);
    return send(res, 200, { user: name, count: await count() }, { 'Set-Cookie': cookie(req, COOKIE, token, SESSION_DAYS * 86400, true) });
  }

  // вход
  if (limited('login:' + key, 8, 15 * 60 * 1000, false) || limited('loginip:' + ipOf(req), 30, 15 * 60 * 1000, false))
    return send(res, 429, { error: 'Слишком много неудачных попыток. Подожди 15 минут.' });
  const [rows] = await pool.query('SELECT name, salt, hash FROM users WHERE ukey = ? LIMIT 1', [key]);
  const u = rows.length ? rows[0] : null;
  const calc = Buffer.from(hashPass(pass.slice(0, 128), u ? u.salt : '00'.repeat(16)), 'hex');
  const real = u ? Buffer.from(u.hash, 'hex') : Buffer.alloc(64);
  if (!u || !crypto.timingSafeEqual(calc, real)) {
    limited('login:' + key, 8, 15 * 60 * 1000, true); limited('loginip:' + ipOf(req), 30, 15 * 60 * 1000, true);
    return send(res, 401, { error: 'Неверный логин или пароль' });
  }
  const token = await newSession(key);
  return send(res, 200, { user: u.name, count: await count() }, { 'Set-Cookie': cookie(req, COOKIE, token, SESSION_DAYS * 86400, true) });
}

/* ---------- скачивание ---------- */
const AUDIO_EXT = ['.mp3', '.m4a', '.ogg', '.wav', '.mp4'];
async function download(req, res, u) {
  if (REQUIRE_LOGIN_FOR_DOWNLOAD && !(await currentUser(req))) { res.writeHead(401, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('Войди в аккаунт, чтобы скачать'); }
  const m = /^t(\d{1,3})$/.exec(u.pathname.slice('/download/'.length));
  if (!m) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('Не найдено'); }
  let file = null, ext = '';
  for (const e of AUDIO_EXT) { const f = path.join(ROOT, 'assets', m[1] + e); if (fs.existsSync(f)) { file = f; ext = e; break; } }
  if (!file) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('Файл песни не найден'); }
  // имя файла берём из ?name=, но чистим от опасных символов
  let nice = String(u.searchParams.get('name') || '').replace(/[\u0000-\u001f\u007f"\\\/:*?<>|;]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 100) || ('song-' + m[1]);
  const ascii = nice.replace(/[^\x20-\x7e]/g, '_') + ext;
  const st = fs.statSync(file);
  res.writeHead(200, {
    'Content-Type': TYPES[ext] || 'application/octet-stream',
    'Content-Length': st.size,
    'Content-Disposition': `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(nice + ext)}`,
    'Cache-Control': 'private, no-store', 'X-Content-Type-Options': 'nosniff',
  });
  if (req.method === 'HEAD') return res.end();
  fs.createReadStream(file).pipe(res);
}

/* ---------- сервер ---------- */
const server = http.createServer((req, res) => {
  let u;
  try { u = new URL(req.url, 'http://localhost'); } catch (e) { res.writeHead(400); return res.end('Bad request'); }
  let urlPath;
  try { urlPath = decodeURIComponent(u.pathname); } catch (e) { res.writeHead(400); return res.end('Bad request'); }

  const fail = e => {
    console.error('Ошибка:', e && e.message);
    if (!res.headersSent) send(res, 500, { error: 'Ошибка базы данных. Попробуй позже.' }); else res.end();
  };
  if (urlPath.startsWith('/api/')) return api(req, res, urlPath).catch(fail);
  if (urlPath.startsWith('/download/') && (req.method === 'GET' || req.method === 'HEAD')) return download(req, res, u).catch(fail);

  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.writeHead(405, { Allow: 'GET, HEAD' });
    return res.end();
  }
  if (urlPath.endsWith('/')) urlPath += 'index.html';

  const file = path.normalize(path.join(ROOT, urlPath));
  if (file !== ROOT && !file.startsWith(ROOT + path.sep)) {
    res.writeHead(403);
    return res.end('Forbidden');
  }

  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('Не найдено');
    }
    const ext = path.extname(file).toLowerCase();
    const headers = {
      'Content-Type': TYPES[ext] || 'application/octet-stream',
      'Accept-Ranges': 'bytes',          // нужно, чтобы музыку можно было перематывать
      'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=300',
      'X-Content-Type-Options': 'nosniff',
    };

    const range = req.headers.range;
    if (range) {
      const m = /^bytes=(\d*)-(\d*)$/.exec(range);
      let start = 0, end = st.size - 1;
      if (m) {
        if (m[1] !== '') { start = parseInt(m[1], 10); if (m[2] !== '') end = parseInt(m[2], 10); }
        else if (m[2] !== '') { start = Math.max(0, st.size - parseInt(m[2], 10)); }
      }
      end = Math.min(end, st.size - 1);
      if (!m || isNaN(start) || start >= st.size || end < start) {
        res.writeHead(416, { 'Content-Range': 'bytes */' + st.size });
        return res.end();
      }
      res.writeHead(206, { ...headers, 'Content-Range': `bytes ${start}-${end}/${st.size}`, 'Content-Length': end - start + 1 });
      if (req.method === 'HEAD') return res.end();
      return fs.createReadStream(file, { start, end }).pipe(res);
    }

    res.writeHead(200, { ...headers, 'Content-Length': st.size });
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(file).pipe(res);
  });
});

// Сначала подключаемся к базе, потом запускаем сайт
initDb().then(() => {
  console.log('MySQL подключена');
}).catch(e => {
  console.error('НЕ УДАЛОСЬ подключиться к MySQL: ' + e.message + '\nПроверь db.json (хост, пользователь, пароль, база).');
}).finally(() => {
  server.listen(PORT, '0.0.0.0', () => console.log('Сайт запущен на порту ' + PORT));
});
