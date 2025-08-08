const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const { Pool } = require('pg');
const path = require('path');
const crypto = require('crypto');

/*
 * This application implements a step-tracking competition for Hepro AS.
 * Employees can record their daily steps without logging in, selecting
 * themselves and their location from drop-down lists. Admin users can
 * manage employees, locations, step entries and other administrators via
 * a protected interface. The server supports both SQLite (default) and
 * PostgreSQL (when the DATABASE_URL environment variable is defined) so
 * it can run locally and on platforms like Render.
 *
 * To keep the code concise, helper functions abstract most of the
 * differences between the two database backends.
 */

const app = express();
const PORT = process.env.PORT || 3000;
// Determine whether to use PostgreSQL. Only treat the database URL as
// PostgreSQL if it starts with the "postgres" scheme. This allows
// using file-based SQLite database URLs without triggering the PG code path.
const isPg = process.env.DATABASE_URL && process.env.DATABASE_URL.toLowerCase().startsWith('postgres');
let db;
let pgPool;

function generateSalt() {
  return crypto.randomBytes(16).toString('hex');
}
function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
}
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}
function parseCookies(req) {
  const header = req.headers.cookie;
  const cookies = {};
  if (!header) return cookies;
  header.split(';').forEach(part => {
    const [key, value] = part.trim().split('=');
    if (key && value !== undefined) cookies[key] = decodeURIComponent(value);
  });
  return cookies;
}

async function dbQuery(sql, params = []) {
  if (isPg) {
    const result = await pgPool.query(sql, params);
    return result.rows;
  }
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}
async function dbRun(sql, params = []) {
  if (isPg) {
    await pgPool.query(sql, params);
    return;
  }
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}

async function initDatabase() {
  if (isPg) {
    pgPool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
    });
    await dbRun('CREATE TABLE IF NOT EXISTS employees (id SERIAL PRIMARY KEY, name TEXT UNIQUE NOT NULL)');
    await dbRun('CREATE TABLE IF NOT EXISTS locations (id SERIAL PRIMARY KEY, name TEXT UNIQUE NOT NULL)');
    await dbRun('CREATE TABLE IF NOT EXISTS steps (id SERIAL PRIMARY KEY, employee_id INTEGER NOT NULL REFERENCES employees(id) ON DELETE CASCADE, location_id INTEGER NOT NULL REFERENCES locations(id) ON DELETE SET NULL, date DATE NOT NULL, steps INTEGER NOT NULL, UNIQUE (employee_id, date))');
    await dbRun('CREATE TABLE IF NOT EXISTS admin_users (id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, salt TEXT NOT NULL)');
    await dbRun('CREATE TABLE IF NOT EXISTS admin_sessions (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE, token TEXT UNIQUE NOT NULL, expires_at TIMESTAMP NOT NULL)');
  } else {
    db = new sqlite3.Database(path.join(__dirname, 'data.db'));
    await dbRun('CREATE TABLE IF NOT EXISTS employees (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL)');
    await dbRun('CREATE TABLE IF NOT EXISTS locations (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL)');
    await dbRun('CREATE TABLE IF NOT EXISTS steps (id INTEGER PRIMARY KEY AUTOINCREMENT, employee_id INTEGER NOT NULL, location_id INTEGER NOT NULL, date TEXT NOT NULL, steps INTEGER NOT NULL, UNIQUE (employee_id, date))');
    await dbRun('CREATE TABLE IF NOT EXISTS admin_users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, salt TEXT NOT NULL)');
    await dbRun('CREATE TABLE IF NOT EXISTS admin_sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, token TEXT UNIQUE NOT NULL, expires_at TEXT NOT NULL)');
  }
  const defaultEmail = process.env.DEFAULT_ADMIN_EMAIL || 'frede.ousland@hepro.no';
  const defaultPass = process.env.DEFAULT_ADMIN_PASS || 'frede.ousland@hepro.no';
  const admins = await dbQuery('SELECT COUNT(*) AS count FROM admin_users');
  const count = parseInt(admins[0].count || admins[0].COUNT || admins[0]['count'], 10);
  if (count === 0) {
    const salt = generateSalt();
    const passwordHash = hashPassword(defaultPass, salt);
    await dbRun('INSERT INTO admin_users (email, password_hash, salt) VALUES (?, ?, ?)', [defaultEmail, passwordHash, salt]);
  }
}

async function requireAdmin(req, res, next) {
  try {
    const cookies = parseCookies(req);
    const token = cookies['admin_token'];
    if (!token) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }
    const sessionRows = await dbQuery('SELECT admin_sessions.id, admin_sessions.user_id, admin_sessions.expires_at, admin_users.email FROM admin_sessions JOIN admin_users ON admin_users.id = admin_sessions.user_id WHERE token = ?', [token]);
    if (sessionRows.length === 0) {
      res.status(401).json({ error: 'Invalid session' });
      return;
    }
    const session = sessionRows[0];
    const now = new Date();
    const expiresAt = new Date(session.expires_at);
    if (expiresAt < now) {
      await dbRun('DELETE FROM admin_sessions WHERE id = ?', [session.id]);
      res.status(401).json({ error: 'Session expired' });
      return;
    }
    req.adminUser = { id: session.user_id, email: session.email };
    next();
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
}

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Public endpoints
app.get('/api/employees', async (req, res) => {
  try {
    const rows = await dbQuery('SELECT id, name FROM employees ORDER BY name');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.get('/api/locations', async (req, res) => {
  try {
    const rows = await dbQuery('SELECT id, name FROM locations ORDER BY name');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.post('/api/steps', async (req, res) => {
  try {
    const { employeeId, locationId, date, steps } = req.body || {};
    if (!employeeId || !locationId || !date || steps === undefined) {
      res.status(400).json({ error: 'Missing fields' });
      return;
    }
    const stepCount = parseInt(steps, 10);
    if (isNaN(stepCount) || stepCount < 0) {
      res.status(400).json({ error: 'Steps must be a non-negative integer' });
      return;
    }
    const entryDate = new Date(date);
    if (isNaN(entryDate.getTime())) {
      res.status(400).json({ error: 'Invalid date' });
      return;
    }
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    if (entryDate > today) {
      res.status(400).json({ error: 'Date cannot be in the future' });
      return;
    }
    const dateISO = entryDate.toISOString().substring(0, 10);
    if (isPg) {
      await dbRun(
        'INSERT INTO steps (employee_id, location_id, date, steps) VALUES ($1, $2, $3, $4) ON CONFLICT (employee_id, date) DO UPDATE SET steps = EXCLUDED.steps, location_id = EXCLUDED.location_id',
        [employeeId, locationId, dateISO, stepCount]
      );
    } else {
      const update = await dbRun('UPDATE steps SET steps = ?, location_id = ? WHERE employee_id = ? AND date = ?', [stepCount, locationId, employeeId, dateISO]);
      if (update && update.changes === 0) {
        await dbRun('INSERT INTO steps (employee_id, location_id, date, steps) VALUES (?, ?, ?, ?)', [employeeId, locationId, dateISO, stepCount]);
      }
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// Returns average steps per date and location. The average is calculated as the
// total number of steps divided by the number of employees belonging to that
// location (so employees that didn't log steps that day count as 0).
app.get('/api/averages', async (req, res) => {
  try {
    let rows;
    if (isPg) {
      // Postgres: join employees so count distinct employees per location
      rows = await dbQuery(
        `SELECT s.date AS date, l.name AS location,
                ROUND(SUM(s.steps)::numeric / NULLIF(COUNT(DISTINCT e.id),0), 2) AS average
         FROM steps s
         JOIN locations l ON l.id = s.location_id
         JOIN employees e ON e.location_id = l.id
         GROUP BY l.name, s.date
         ORDER BY s.date, l.name`
      );
    } else {
      // SQLite: count distinct employees per location for denominator
      rows = await dbQuery(
        `SELECT steps.date AS date,
                locations.name AS location,
                ROUND(SUM(steps.steps) * 1.0 / NULLIF(COUNT(DISTINCT employees.id),0), 2) AS average
         FROM steps
         JOIN locations ON locations.id = steps.location_id
         JOIN employees ON employees.location_id = locations.id
         GROUP BY locations.name, steps.date
         ORDER BY steps.date, locations.name`
      );
    }
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin authentication
app.post('/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      res.status(400).json({ error: 'Email and password required' });
      return;
    }
    const users = await dbQuery('SELECT id, password_hash, salt FROM admin_users WHERE email = ?', [email]);
    if (users.length === 0) {
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }
    const user = users[0];
    const hashed = hashPassword(password, user.salt);
    if (hashed !== user.password_hash) {
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }
    const token = generateToken();
    const expires = new Date(Date.now() + 24 * 60 * 60 * 1000);
    await dbRun('INSERT INTO admin_sessions (user_id, token, expires_at) VALUES (?, ?, ?)', [user.id, token, isPg ? expires.toISOString() : expires.toISOString()]);
    res.setHeader('Set-Cookie', `admin_token=${encodeURIComponent(token)}; Path=/; HttpOnly; Max-Age=${24 * 60 * 60}`);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.post('/admin/logout', requireAdmin, async (req, res) => {
  try {
    const cookies = parseCookies(req);
    const token = cookies['admin_token'];
    await dbRun('DELETE FROM admin_sessions WHERE token = ?', [token]);
    res.setHeader('Set-Cookie', 'admin_token=; Path=/; HttpOnly; Max-Age=0');
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.get('/admin/check', async (req, res) => {
  try {
    const cookies = parseCookies(req);
    const token = cookies['admin_token'];
    if (!token) {
      res.json({ loggedIn: false });
      return;
    }
    const rows = await dbQuery('SELECT expires_at FROM admin_sessions WHERE token = ?', [token]);
    if (rows.length === 0) {
      res.json({ loggedIn: false });
      return;
    }
    const expiresAt = new Date(rows[0].expires_at);
    if (expiresAt < new Date()) {
      res.json({ loggedIn: false });
      return;
    }
    res.json({ loggedIn: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: employees
app.get('/admin/employees', requireAdmin, async (req, res) => {
  try {
    const rows = await dbQuery('SELECT id, name FROM employees ORDER BY name');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.post('/admin/employees', requireAdmin, async (req, res) => {
  try {
    const { name } = req.body || {};
    if (!name || !name.trim()) {
      res.status(400).json({ error: 'Name is required' });
      return;
    }
    await dbRun('INSERT INTO employees (name) VALUES (?)', [name.trim()]);
    res.json({ success: true });
  } catch (err) {
    if (/unique/i.test(err.message)) {
      res.status(409).json({ error: 'Employee already exists' });
    } else {
      res.status(500).json({ error: err.message });
    }
  }
});
app.put('/admin/employees/:id', requireAdmin, async (req, res) => {
  try {
    const { name } = req.body || {};
    if (!name || !name.trim()) {
      res.status(400).json({ error: 'Name is required' });
      return;
    }
    await dbRun('UPDATE employees SET name = ? WHERE id = ?', [name.trim(), req.params.id]);
    res.json({ success: true });
  } catch (err) {
    if (/unique/i.test(err.message)) {
      res.status(409).json({ error: 'Employee already exists' });
    } else {
      res.status(500).json({ error: err.message });
    }
  }
});
app.delete('/admin/employees/:id', requireAdmin, async (req, res) => {
  try {
    await dbRun('DELETE FROM employees WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: locations
app.get('/admin/locations', requireAdmin, async (req, res) => {
  try {
    const rows = await dbQuery('SELECT id, name FROM locations ORDER BY name');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.post('/admin/locations', requireAdmin, async (req, res) => {
  try {
    const { name } = req.body || {};
    if (!name || !name.trim()) {
      res.status(400).json({ error: 'Name is required' });
      return;
    }
    await dbRun('INSERT INTO locations (name) VALUES (?)', [name.trim()]);
    res.json({ success: true });
  } catch (err) {
    if (/unique/i.test(err.message)) {
      res.status(409).json({ error: 'Location already exists' });
    } else {
      res.status(500).json({ error: err.message });
    }
  }
});
app.put('/admin/locations/:id', requireAdmin, async (req, res) => {
  try {
    const { name } = req.body || {};
    if (!name || !name.trim()) {
      res.status(400).json({ error: 'Name is required' });
      return;
    }
    await dbRun('UPDATE locations SET name = ? WHERE id = ?', [name.trim(), req.params.id]);
    res.json({ success: true });
  } catch (err) {
    if (/unique/i.test(err.message)) {
      res.status(409).json({ error: 'Location already exists' });
    } else {
      res.status(500).json({ error: err.message });
    }
  }
});
app.delete('/admin/locations/:id', requireAdmin, async (req, res) => {
  try {
    await dbRun('DELETE FROM locations WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: steps management
app.get('/admin/steps', requireAdmin, async (req, res) => {
  try {
    let rows;
    if (isPg) {
      rows = await dbQuery(
        `SELECT s.id, s.date, s.steps, e.id AS employee_id, e.name AS employee_name, l.id AS location_id, l.name AS location_name
         FROM steps s
         JOIN employees e ON e.id = s.employee_id
         JOIN locations l ON l.id = s.location_id
         ORDER BY s.date DESC, e.name ASC`
      );
    } else {
      rows = await dbQuery(
        `SELECT steps.id, steps.date, steps.steps, employees.id AS employee_id, employees.name AS employee_name, locations.id AS location_id, locations.name AS location_name
         FROM steps
         JOIN employees ON employees.id = steps.employee_id
         JOIN locations ON locations.id = steps.location_id
         ORDER BY steps.date DESC, employees.name ASC`
      );
    }
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.put('/admin/steps/:id', requireAdmin, async (req, res) => {
  try {
    const { steps, date, locationId, employeeId } = req.body || {};
    const fields = [];
    const params = [];
    if (steps !== undefined) {
      const s = parseInt(steps, 10);
      if (isNaN(s) || s < 0) {
        res.status(400).json({ error: 'Steps must be non-negative' });
        return;
      }
      fields.push('steps = ?');
      params.push(s);
    }
    if (date) {
      const d = new Date(date);
      if (isNaN(d.getTime())) {
        res.status(400).json({ error: 'Invalid date' });
        return;
      }
      const today = new Date();
      today.setHours(0, 0, 0, 0);
      if (d > today) {
        res.status(400).json({ error: 'Date cannot be in the future' });
        return;
      }
      fields.push('date = ?');
      params.push(d.toISOString().substring(0, 10));
    }
    if (locationId) {
      fields.push('location_id = ?');
      params.push(locationId);
    }
    if (employeeId) {
      fields.push('employee_id = ?');
      params.push(employeeId);
    }
    if (fields.length === 0) {
      res.status(400).json({ error: 'No fields to update' });
      return;
    }
    params.push(req.params.id);
    await dbRun(`UPDATE steps SET ${fields.join(', ')} WHERE id = ?`, params);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.delete('/admin/steps/:id', requireAdmin, async (req, res) => {
  try {
    await dbRun('DELETE FROM steps WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: users
app.get('/admin/users', requireAdmin, async (req, res) => {
  try {
    const rows = await dbQuery('SELECT id, email FROM admin_users ORDER BY email');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.post('/admin/users', requireAdmin, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      res.status(400).json({ error: 'Email and password required' });
      return;
    }
    const salt = generateSalt();
    const passwordHash = hashPassword(password, salt);
    await dbRun('INSERT INTO admin_users (email, password_hash, salt) VALUES (?, ?, ?)', [email, passwordHash, salt]);
    res.json({ success: true });
  } catch (err) {
    if (/unique/i.test(err.message)) {
      res.status(409).json({ error: 'Admin already exists' });
    } else {
      res.status(500).json({ error: err.message });
    }
  }
});
app.put('/admin/users/:id', requireAdmin, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const fields = [];
    const params = [];
    if (email) {
      fields.push('email = ?');
      params.push(email);
    }
    if (password) {
      const salt = generateSalt();
      const passwordHash = hashPassword(password, salt);
      fields.push('password_hash = ?');
      fields.push('salt = ?');
      params.push(passwordHash, salt);
    }
    if (fields.length === 0) {
      res.status(400).json({ error: 'Nothing to update' });
      return;
    }
    params.push(req.params.id);
    await dbRun(`UPDATE admin_users SET ${fields.join(', ')} WHERE id = ?`, params);
    res.json({ success: true });
  } catch (err) {
    if (/unique/i.test(err.message)) {
      res.status(409).json({ error: 'Admin already exists' });
    } else {
      res.status(500).json({ error: err.message });
    }
  }
});
app.delete('/admin/users/:id', requireAdmin, async (req, res) => {
  try {
    await dbRun('DELETE FROM admin_users WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Fallback route
app.get('*', (req, res) => {
  if (req.method === 'GET' && !req.path.startsWith('/api') && !req.path.startsWith('/admin')) {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  } else {
    res.status(404).send('Not Found');
  }
});

initDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server listening on port ${PORT}`);
    });
  })
  .catch(err => {
    console.error('Failed to initialize database', err);
    process.exit(1);
  });