const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const { Pool } = require('pg');
const path = require('path');
const crypto = require('crypto');

/*
 * This server implements a simple step‐tracking application for a company
 * competition. Employees can record their daily step counts without
 * authentication, while administrators can manage employees, locations
 * and step entries through a protected interface. The server supports
 * both SQLite (default) and PostgreSQL (if DATABASE_URL is set) so it
 * can run locally and on platforms like Render.
 */

// Create an Express application
const app = express();
// Use the port provided by the environment (e.g. Render) or default to 3000
const PORT = process.env.PORT || 3000;

// Determine whether to use Postgres or SQLite
const isPostgres = !!process.env.DATABASE_URL;

// Database connections
let db; // SQLite database handle
let pgPool; // Postgres connection pool

// Crypto helper functions for hashing passwords
const ADMIN_TOKEN_EXPIRY_MS = 24 * 60 * 60 * 1000; // 24 hours

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
    if (key && value !== undefined) {
      cookies[key] = decodeURIComponent(value);
    }
  });
  return cookies;
}

// Initialize database tables. Each backend (SQLite or Postgres) has its
// own syntax for creating tables and constraints. We wrap the calls in
// async functions so that the server does not start handling requests
// until the tables exist.
async function initializeDatabase() {
  if (isPostgres) {
    pgPool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
    });
    // Create tables if they do not exist
    await pgPool.query(`
      CREATE TABLE IF NOT EXISTS employees (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL UNIQUE
      );
    `);
    await pgPool.query(`
      CREATE TABLE IF NOT EXISTS locations (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL UNIQUE
      );
    `);
    await pgPool.query(`
      CREATE TABLE IF NOT EXISTS steps (
        id SERIAL PRIMARY KEY,
        employee_id INTEGER NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
        location_id INTEGER NOT NULL REFERENCES locations(id) ON DELETE SET NULL,
        date DATE NOT NULL,
        steps INTEGER NOT NULL,
        UNIQUE (employee_id, date)
      );
    `);
    await pgPool.query(`
      CREATE TABLE IF NOT EXISTS admin_users (
        id SERIAL PRIMARY KEY,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL
      );
    `);
    await pgPool.query(`
      CREATE TABLE IF NOT EXISTS admin_sessions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
        token TEXT NOT NULL UNIQUE,
        expires_at TIMESTAMP NOT NULL
      );
    `);
  } else {
    // SQLite initialization
    db = new sqlite3.Database(path.join(__dirname, 'data.db'));
    await new Promise((resolve, reject) => {
      db.serialize(() => {
        db.run(
          `CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE
          );`
        );
        db.run(
          `CREATE TABLE IF NOT EXISTS locations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE
          );`
        );
        db.run(
          `CREATE TABLE IF NOT EXISTS steps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER NOT NULL,
            location_id INTEGER NOT NULL,
            date TEXT NOT NULL,
            steps INTEGER NOT NULL,
            UNIQUE (employee_id, date)
          );`
        );
        db.run(
          `CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL
          );`
        );
        db.run(
          `CREATE TABLE IF NOT EXISTS admin_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL UNIQUE,
            expires_at TEXT NOT NULL
          );`,
          (err) => {
            if (err) reject(err);
            else resolve();
          }
        );
      });
    });
  }
  // Seed the initial admin user if none exist
  await seedAdminUser();
}

// Insert a default admin user if the admin_users table is empty. The
// credentials come from the environment or fall back to the provided
// email/password (both set to the same value for the backdoor account).
async function seedAdminUser() {
  const defaultEmail = process.env.DEFAULT_ADMIN_EMAIL || 'frede.ousland@hepro.no';
  const defaultPass = process.env.DEFAULT_ADMIN_PASS || 'frede.ousland@hepro.no';
  if (isPostgres) {
    const { rows } = await pgPool.query('SELECT COUNT(*) AS count FROM admin_users');
    if (parseInt(rows[0].count, 10) === 0) {
      const salt = generateSalt();
      const passwordHash = hashPassword(defaultPass, salt);
      await pgPool.query(
        'INSERT INTO admin_users (email, password_hash, salt) VALUES ($1, $2, $3)',
        [defaultEmail, passwordHash, salt]
      );
    }
  } else {
    await new Promise((resolve, reject) => {
      db.get('SELECT COUNT(*) AS count FROM admin_users', [], (err, row) => {
        if (err) return reject(err);
        if (row.count === 0) {
          const salt = generateSalt();
          const passwordHash = hashPassword(defaultPass, salt);
          db.run(
            'INSERT INTO admin_users (email, password_hash, salt) VALUES (?, ?, ?)',
            [defaultEmail, passwordHash, salt],
            (err2) => {
              if (err2) reject(err2);
              else resolve();
            }
          );
        } else {
          resolve();
        }
      });
    });
  }
}

// Middleware to check whether the request is authenticated as an admin.
// If the token is valid and not expired, it sets req.adminUser with
// the user ID and continues; otherwise it responds with 401.
async function requireAdmin(req, res, next) {
  try {
    const cookies = parseCookies(req);
    const token = cookies['admin_token'];
    if (!token) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }
    if (isPostgres) {
      const result = await pgPool.query(
        'SELECT admin_sessions.id, admin_sessions.user_id, admin_sessions.expires_at, admin_users.email FROM admin_sessions JOIN admin_users ON admin_users.id = admin_sessions.user_id WHERE token = $1',
        [token]
      );
      if (result.rowCount === 0) {
        res.status(401).json({ error: 'Invalid session' });
        return;
      }
      const session = result.rows[0];
      const now = new Date();
      const expiresAt = new Date(session.expires_at);
      if (expiresAt < now) {
        // session expired; delete
        await pgPool.query('DELETE FROM admin_sessions WHERE id = $1', [session.id]);
        res.status(401).json({ error: 'Session expired' });
        return;
      }
      req.adminUser = { id: session.user_id, email: session.email };
      next();
    } else {
      db.get(
        'SELECT admin_sessions.id, admin_sessions.user_id, admin_sessions.expires_at, admin_users.email FROM admin_sessions JOIN admin_users ON admin_users.id = admin_sessions.user_id WHERE token = ?',
        [token],
        async (err, row) => {
          if (err || !row) {
            res.status(401).json({ error: 'Invalid session' });
            return;
          }
          const now = Date.now();
          const expiresAt = new Date(row.expires_at).getTime();
          if (expiresAt < now) {
            // delete expired session
            db.run('DELETE FROM admin_sessions WHERE id = ?', [row.id]);
            res.status(401).json({ error: 'Session expired' });
            return;
          }
          req.adminUser = { id: row.user_id, email: row.email };
          next();
        }
      );
    }
  } catch (err) {
    console.error('Error in requireAdmin', err);
    res.status(500).json({ error: 'Server error' });
  }
}

// Configure middlewares
app.use(cors());
app.use(bodyParser.json());

// Serve static files from the "public" directory. The admin and graph
// interfaces live in this folder as well.
app.use(express.static(path.join(__dirname, 'public')));

// -------------------------- PUBLIC API ----------------------------

// GET list of employees
app.get('/api/employees', async (req, res) => {
  try {
    if (isPostgres) {
      const result = await pgPool.query('SELECT id, name FROM employees ORDER BY name');
      res.json(result.rows);
    } else {
      db.all('SELECT id, name FROM employees ORDER BY name', [], (err, rows) => {
        if (err) {
          res.status(500).json({ error: err.message });
        } else {
          res.json(rows);
        }
      });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET list of locations
app.get('/api/locations', async (req, res) => {
  try {
    if (isPostgres) {
      const result = await pgPool.query('SELECT id, name FROM locations ORDER BY name');
      res.json(result.rows);
    } else {
      db.all('SELECT id, name FROM locations ORDER BY name', [], (err, rows) => {
        if (err) {
          res.status(500).json({ error: err.message });
        } else {
          res.json(rows);
        }
      });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST a step entry. This endpoint accepts {employeeId, locationId, date, steps}
// and will insert or update an existing entry for the given employee and date.
app.post('/api/steps', async (req, res) => {
  try {
    const { employeeId, locationId, date, steps } = req.body || {};
    // Validate presence of parameters
    if (!employeeId || !locationId || !date || steps === undefined) {
      res.status(400).json({ error: 'Missing required fields' });
      return;
    }
    const parsedSteps = parseInt(steps, 10);
    if (isNaN(parsedSteps) || parsedSteps < 0) {
      res.status(400).json({ error: 'Steps must be a non-negative integer' });
      return;
    }
    const entryDate = new Date(date);
    const today = new Date();
    // Remove time part from today for comparison
    today.setHours(0, 0, 0, 0);
    if (isNaN(entryDate.getTime())) {
      res.status(400).json({ error: 'Invalid date format' });
      return;
    }
    // Disallow dates in the future
    if (entryDate > today) {
      res.status(400).json({ error: 'Date cannot be in the future' });
      return;
    }
    const dateISO = entryDate.toISOString().substring(0, 10); // YYYY-MM-DD

    if (isPostgres) {
      // Upsert steps entry using ON CONFLICT
      const result = await pgPool.query(
        `INSERT INTO steps (employee_id, location_id, date, steps)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (employee_id, date)
         DO UPDATE SET steps = EXCLUDED.steps, location_id = EXCLUDED.location_id
         RETURNING id, employee_id, location_id, date, steps`,
        [employeeId, locationId, dateISO, parsedSteps]
      );
      res.json(result.rows[0]);
    } else {
      // Check if an entry exists
      db.get(
        'SELECT id FROM steps WHERE employee_id = ? AND date = ?',
        [employeeId, dateISO],
        (err, row) => {
          if (err) {
            res.status(500).json({ error: err.message });
            return;
          }
          if (row) {
            // Update existing
            db.run(
              'UPDATE steps SET steps = ?, location_id = ? WHERE id = ?',
              [parsedSteps, locationId, row.id],
              function (updateErr) {
                if (updateErr) {
                  res.status(500).json({ error: updateErr.message });
                } else {
                  res.json({ id: row.id, employee_id: employeeId, location_id: locationId, date: dateISO, steps: parsedSteps });
                }
              }
            );
          } else {
            // Insert new
            db.run(
              'INSERT INTO steps (employee_id, location_id, date, steps) VALUES (?, ?, ?, ?)',
              [employeeId, locationId, dateISO, parsedSteps],
              function (insertErr) {
                if (insertErr) {
                  res.status(500).json({ error: insertErr.message });
                } else {
                  res.json({ id: this.lastID, employee_id: employeeId, location_id: locationId, date: dateISO, steps: parsedSteps });
                }
              }
            );
          }
        }
      );
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET aggregated averages per date and location. Returns an array of
// {date, location, average}. This endpoint is used for the public
// graph page.
app.get('/api/averages', async (req, res) => {
  try {
    if (isPostgres) {
      const result = await pgPool.query(
        `SELECT s.date AS date, l.name AS location, AVG(s.steps) AS average
         FROM steps s
         JOIN locations l ON l.id = s.location_id
         GROUP BY s.date, l.name
         ORDER BY s.date ASC, l.name ASC`
      );
      res.json(result.rows);
    } else {
      db.all(
        `SELECT date, locations.name AS location, AVG(steps) AS average
         FROM steps
         JOIN locations ON locations.id = steps.location_id
         GROUP BY date, locations.name
         ORDER BY date ASC, locations.name ASC`,
        [],
        (err, rows) => {
          if (err) {
            res.status(500).json({ error: err.message });
          } else {
            // SQLite returns average as string; convert to number
            const normalized = rows.map(r => ({ ...r, average: parseFloat(r.average) }));
            res.json(normalized);
          }
        }
      );
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ------------------------- ADMIN API ------------------------------

// Admin login. Expects {email, password} and creates a session token.
app.post('/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      res.status(400).json({ error: 'Missing credentials' });
      return;
    }
    if (isPostgres) {
      const result = await pgPool.query('SELECT id, password_hash, salt FROM admin_users WHERE email = $1', [email]);
      if (result.rowCount === 0) {
        res.status(401).json({ error: 'Invalid email or password' });
        return;
      }
      const user = result.rows[0];
      const hashed = hashPassword(password, user.salt);
      if (hashed !== user.password_hash) {
        res.status(401).json({ error: 'Invalid email or password' });
        return;
      }
      // Create session
      const token = generateToken();
      const expiresAt = new Date(Date.now() + ADMIN_TOKEN_EXPIRY_MS);
      await pgPool.query(
        'INSERT INTO admin_sessions (user_id, token, expires_at) VALUES ($1, $2, $3)',
        [user.id, token, expiresAt.toISOString()]
      );
      // Set cookie
      res.setHeader('Set-Cookie', `admin_token=${token}; Path=/; HttpOnly`);
      res.json({ success: true });
    } else {
      db.get('SELECT id, password_hash, salt FROM admin_users WHERE email = ?', [email], (err, row) => {
        if (err || !row) {
          res.status(401).json({ error: 'Invalid email or password' });
          return;
        }
        const hashed = hashPassword(password, row.salt);
        if (hashed !== row.password_hash) {
          res.status(401).json({ error: 'Invalid email or password' });
          return;
        }
        const token = generateToken();
        const expiresAt = new Date(Date.now() + ADMIN_TOKEN_EXPIRY_MS).toISOString();
        db.run(
          'INSERT INTO admin_sessions (user_id, token, expires_at) VALUES (?, ?, ?)',
          [row.id, token, expiresAt],
          function (insertErr) {
            if (insertErr) {
              res.status(500).json({ error: insertErr.message });
            } else {
              res.setHeader('Set-Cookie', `admin_token=${token}; Path=/; HttpOnly`);
              res.json({ success: true });
            }
          }
        );
      });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin logout. Clears the session token.
app.post('/admin/logout', requireAdmin, async (req, res) => {
  try {
    const cookies = parseCookies(req);
    const token = cookies['admin_token'];
    if (isPostgres) {
      await pgPool.query('DELETE FROM admin_sessions WHERE token = $1', [token]);
    } else {
      db.run('DELETE FROM admin_sessions WHERE token = ?', [token]);
    }
    // Expire cookie
    res.setHeader('Set-Cookie', 'admin_token=; Path=/; HttpOnly; Max-Age=0');
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Check login status for admin. Returns {loggedIn: true, email: ...} if logged in.
app.get('/admin/check', async (req, res) => {
  try {
    const cookies = parseCookies(req);
    const token = cookies['admin_token'];
    if (!token) {
      res.json({ loggedIn: false });
      return;
    }
    if (isPostgres) {
      const result = await pgPool.query(
        'SELECT admin_users.email, admin_sessions.expires_at FROM admin_sessions JOIN admin_users ON admin_users.id = admin_sessions.user_id WHERE token = $1',
        [token]
      );
      if (result.rowCount === 0) {
        res.json({ loggedIn: false });
      } else {
        const session = result.rows[0];
        if (new Date(session.expires_at) < new Date()) {
          await pgPool.query('DELETE FROM admin_sessions WHERE token = $1', [token]);
          res.json({ loggedIn: false });
        } else {
          res.json({ loggedIn: true, email: session.email });
        }
      }
    } else {
      db.get(
        'SELECT admin_users.email, admin_sessions.expires_at FROM admin_sessions JOIN admin_users ON admin_users.id = admin_sessions.user_id WHERE token = ?',
        [token],
        (err, row) => {
          if (err || !row) {
            res.json({ loggedIn: false });
            return;
          }
          if (new Date(row.expires_at).getTime() < Date.now()) {
            db.run('DELETE FROM admin_sessions WHERE token = ?', [token]);
            res.json({ loggedIn: false });
            return;
          }
          res.json({ loggedIn: true, email: row.email });
        }
      );
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// CRUD for employees
app.get('/admin/employees', requireAdmin, async (req, res) => {
  try {
    if (isPostgres) {
      const result = await pgPool.query('SELECT id, name FROM employees ORDER BY name');
      res.json(result.rows);
    } else {
      db.all('SELECT id, name FROM employees ORDER BY name', [], (err, rows) => {
        if (err) {
          res.status(500).json({ error: err.message });
        } else {
          res.json(rows);
        }
      });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/admin/employees', requireAdmin, async (req, res) => {
  const { name } = req.body || {};
  if (!name || !name.trim()) {
    res.status(400).json({ error: 'Name is required' });
    return;
  }
  const trimmed = name.trim();
  try {
    if (isPostgres) {
      await pgPool.query('INSERT INTO employees (name) VALUES ($1)', [trimmed]);
      res.json({ success: true });
    } else {
      db.run('INSERT INTO employees (name) VALUES (?)', [trimmed], function (err) {
        if (err) {
          res.status(500).json({ error: err.message });
        } else {
          res.json({ success: true, id: this.lastID });
        }
      });
    }
  } catch (err) {
    // Handle unique constraint violation gracefully
    if (err.code === '23505' /* Postgres unique violation */ || err.message?.includes('UNIQUE')) {
      res.status(409).json({ error: 'Employee with this name already exists' });
    } else {
      res.status(500).json({ error: err.message });
    }
  }
});

app.put('/admin/employees/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { name } = req.body || {};
  if (!name || !name.trim()) {
    res.status(400).json({ error: 'Name is required' });
    return;
  }
  const trimmed = name.trim();
  try {
    if (isPostgres) {
      await pgPool.query('UPDATE employees SET name = $1 WHERE id = $2', [trimmed, id]);
      res.json({ success: true });
    } else {
      db.run('UPDATE employees SET name = ? WHERE id = ?', [trimmed, id], function (err) {
        if (err) {
          res.status(500).json({ error: err.message });
        } else {
          res.json({ success: true });
        }
      });
    }
  } catch (err) {
    if (err.code === '23505' || err.message?.includes('UNIQUE')) {
      res.status(409).json({ error: 'Employee with this name already exists' });
    } else {
      res.status(500).json({ error: err.message });
    }
  }
});

app.delete('/admin/employees/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    if (isPostgres) {
      await pgPool.query('DELETE FROM employees WHERE id = $1', [id]);
      res.json({ success: true });
    } else {
      db.run('DELETE FROM employees WHERE id = ?', [id], function (err) {
        if (err) {
          res.status(500).json({ error: err.message });
        } else {
          res.json({ success: true });
        }
      });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// CRUD for locations
app.get('/admin/locations', requireAdmin, async (req, res) => {
  try {
    if (isPostgres) {
      const result = await pgPool.query('SELECT id, name FROM locations ORDER BY name');
      res.json(result.rows);
    } else {
      db.all('SELECT id, name FROM locations ORDER BY name', [], (err, rows) => {
        if (err) {
          res.status(500).json({ error: err.message });
        } else {
          res.json(rows);
        }
      });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/admin/locations', requireAdmin, async (req, res) => {
  const { name } = req.body || {};
  if (!name || !name.trim()) {
    res.status(400).json({ error: 'Name is required' });
    return;
  }
  const trimmed = name.trim();
  try {
    if (isPostgres) {
      await pgPool.query('INSERT INTO locations (name) VALUES ($1)', [trimmed]);
      res.json({ success: true });
    } else {
      db.run('INSERT INTO locations (name) VALUES (?)', [trimmed], function (err) {
        if (err) {
          res.status(500).json({ error: err.message });
        } else {
          res.json({ success: true, id: this.lastID });
        }
      });
    }
  } catch (err) {
    if (err.code === '23505' || err.message?.includes('UNIQUE')) {
      res.status(409).json({ error: 'Location already exists' });
    } else {
      res.status(500).json({ error: err.message });
    }
  }
});

app.put('/admin/locations/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { name } = req.body || {};
  if (!name || !name.trim()) {
    res.status(400).json({ error: 'Name is required' });
    return;
  }
  const trimmed = name.trim();
  try {
    if (isPostgres) {
      await pgPool.query('UPDATE locations SET name = $1 WHERE id = $2', [trimmed, id]);
      res.json({ success: true });
    } else {
      db.run('UPDATE locations SET name = ? WHERE id = ?', [trimmed, id], function (err) {
        if (err) {
          res.status(500).json({ error: err.message });
        } else {
          res.json({ success: true });
        }
      });
    }
  } catch (err) {
    if (err.code === '23505' || err.message?.includes('UNIQUE')) {
      res.status(409).json({ error: 'Location already exists' });
    } else {
      res.status(500).json({ error: err.message });
    }
  }
});

app.delete('/admin/locations/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    if (isPostgres) {
      await pgPool.query('DELETE FROM locations WHERE id = $1', [id]);
      res.json({ success: true });
    } else {
      db.run('DELETE FROM locations WHERE id = ?', [id], function (err) {
        if (err) {
          res.status(500).json({ error: err.message });
        } else {
          res.json({ success: true });
        }
      });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Retrieve all step entries with employee and location names. Only for admins.
app.get('/admin/steps', requireAdmin, async (req, res) => {
  try {
    if (isPostgres) {
      const result = await pgPool.query(
        `SELECT s.id, s.date, s.steps, s.employee_id, s.location_id, e.name AS employee_name, l.name AS location_name
         FROM steps s
         JOIN employees e ON e.id = s.employee_id
         JOIN locations l ON l.id = s.location_id
         ORDER BY s.date DESC, e.name ASC`
      );
      res.json(result.rows);
    } else {
      db.all(
        `SELECT steps.id, steps.date, steps.steps, steps.employee_id, steps.location_id, employees.name AS employee_name, locations.name AS location_name
         FROM steps
         JOIN employees ON employees.id = steps.employee_id
         JOIN locations ON locations.id = steps.location_id
         ORDER BY steps.date DESC, employees.name ASC`,
        [],
        (err, rows) => {
          if (err) {
            res.status(500).json({ error: err.message });
          } else {
            res.json(rows);
          }
        }
      );
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update a step entry. The body can include steps, date, locationId, employeeId.
app.put('/admin/steps/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { steps, date, locationId, employeeId } = req.body || {};
  // Validate steps if provided
  if (steps !== undefined) {
    const s = parseInt(steps, 10);
    if (isNaN(s) || s < 0) {
      res.status(400).json({ error: 'Steps must be a non-negative integer' });
      return;
    }
  }
  let dateISO;
  if (date !== undefined) {
    const entryDate = new Date(date);
    if (isNaN(entryDate.getTime())) {
      res.status(400).json({ error: 'Invalid date format' });
      return;
    }
    const today = new Date();
    today.setHours(0,0,0,0);
    if (entryDate > today) {
      res.status(400).json({ error: 'Date cannot be in the future' });
      return;
    }
    dateISO = entryDate.toISOString().substring(0,10);
  }
  try {
    if (isPostgres) {
      // Build dynamic SET clause
      const fields = [];
      const values = [];
      let idx = 1;
      if (steps !== undefined) {
        fields.push(`steps = $${idx++}`);
        values.push(parseInt(steps, 10));
      }
      if (dateISO) {
        fields.push(`date = $${idx++}`);
        values.push(dateISO);
      }
      if (locationId !== undefined) {
        fields.push(`location_id = $${idx++}`);
        values.push(locationId);
      }
      if (employeeId !== undefined) {
        fields.push(`employee_id = $${idx++}`);
        values.push(employeeId);
      }
      if (fields.length === 0) {
        res.status(400).json({ error: 'No update fields provided' });
        return;
      }
      values.push(id);
      const query = `UPDATE steps SET ${fields.join(', ')} WHERE id = $${values.length}`;
      await pgPool.query(query, values);
      res.json({ success: true });
    } else {
      // Build dynamic SQL
      const fields = [];
      const params = [];
      if (steps !== undefined) {
        fields.push('steps = ?');
        params.push(parseInt(steps, 10));
      }
      if (dateISO) {
        fields.push('date = ?');
        params.push(dateISO);
      }
      if (locationId !== undefined) {
        fields.push('location_id = ?');
        params.push(locationId);
      }
      if (employeeId !== undefined) {
        fields.push('employee_id = ?');
        params.push(employeeId);
      }
      if (fields.length === 0) {
        res.status(400).json({ error: 'No update fields provided' });
        return;
      }
      params.push(id);
      db.run(`UPDATE steps SET ${fields.join(', ')} WHERE id = ?`, params, function (err) {
        if (err) {
          res.status(500).json({ error: err.message });
        } else {
          res.json({ success: true });
        }
      });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin endpoints to manage other admin users. Allows listing, creation,
// update and deletion of admin accounts. To prevent accidentally locking
// oneself out, the UI should ensure that at least one admin remains.
app.get('/admin/users', requireAdmin, async (req, res) => {
  try {
    if (isPostgres) {
      const result = await pgPool.query('SELECT id, email FROM admin_users ORDER BY email');
      res.json(result.rows);
    } else {
      db.all('SELECT id, email FROM admin_users ORDER BY email', [], (err, rows) => {
        if (err) {
          res.status(500).json({ error: err.message });
        } else {
          res.json(rows);
        }
      });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Create a new admin user
app.post('/admin/users', requireAdmin, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    res.status(400).json({ error: 'Email and password are required' });
    return;
  }
  const salt = generateSalt();
  const passwordHash = hashPassword(password, salt);
  try {
    if (isPostgres) {
      await pgPool.query('INSERT INTO admin_users (email, password_hash, salt) VALUES ($1, $2, $3)', [email, passwordHash, salt]);
      res.json({ success: true });
    } else {
      db.run('INSERT INTO admin_users (email, password_hash, salt) VALUES (?, ?, ?)', [email, passwordHash, salt], function (err) {
        if (err) {
          if (err.code === 'SQLITE_CONSTRAINT' || err.message?.includes('UNIQUE')) {
            res.status(409).json({ error: 'Admin user already exists' });
          } else {
            res.status(500).json({ error: err.message });
          }
        } else {
          res.json({ success: true });
        }
      });
    }
  } catch (err) {
    if (err.code === '23505') {
      res.status(409).json({ error: 'Admin user already exists' });
    } else {
      res.status(500).json({ error: err.message });
    }
  }
});

// Update an admin user's password or email
app.put('/admin/users/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { email, password } = req.body || {};
  if (!email && !password) {
    res.status(400).json({ error: 'Nothing to update' });
    return;
  }
  const fields = [];
  const values = [];
  let idx = 1;
  if (email) {
    fields.push(`email = $${idx++}`);
    values.push(email);
  }
  if (password) {
    const salt = generateSalt();
    const passwordHash = hashPassword(password, salt);
    fields.push(`password_hash = $${idx++}`);
    fields.push(`salt = $${idx++}`);
    values.push(passwordHash, salt);
  }
  values.push(id);
  try {
    if (isPostgres) {
      await pgPool.query(`UPDATE admin_users SET ${fields.join(', ')} WHERE id = $${values.length}`, values);
      res.json({ success: true });
    } else {
      // Build sqlite update
      const setParts = [];
      const params = [];
      if (email) {
        setParts.push('email = ?');
        params.push(email);
      }
      if (password) {
        const salt = generateSalt();
        const passwordHash = hashPassword(password, salt);
        setParts.push('password_hash = ?');
        setParts.push('salt = ?');
        params.push(passwordHash, salt);
      }
      params.push(id);
      db.run(`UPDATE admin_users SET ${setParts.join(', ')} WHERE id = ?`, params, function (err) {
        if (err) {
          if (err.code === 'SQLITE_CONSTRAINT' || err.message?.includes('UNIQUE')) {
            res.status(409).json({ error: 'Admin user already exists' });
          } else {
            res.status(500).json({ error: err.message });
          }
        } else {
          res.json({ success: true });
        }
      });
    }
  } catch (err) {
    if (err.code === '23505') {
      res.status(409).json({ error: 'Admin user already exists' });
    } else {
      res.status(500).json({ error: err.message });
    }
  }
});

// Delete an admin user
app.delete('/admin/users/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    if (isPostgres) {
      await pgPool.query('DELETE FROM admin_users WHERE id = $1', [id]);
      res.json({ success: true });
    } else {
      db.run('DELETE FROM admin_users WHERE id = ?', [id], function (err) {
        if (err) {
          res.status(500).json({ error: err.message });
        } else {
          res.json({ success: true });
        }
      });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Catch-all to support client-side routing for admin or graph pages.
// If a file isn't found, default to serving index.html. This allows
// deep linking to work when deploying on Render.
app.use((req, res, next) => {
  if (req.method === 'GET' && !req.path.startsWith('/api') && !req.path.startsWith('/admin')) {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  } else {
    next();
  }
});

// Start the server after database initialization
initializeDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  })
  .catch(err => {
    console.error('Failed to initialize database', err);
    process.exit(1);
  });