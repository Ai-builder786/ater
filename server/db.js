import Database from 'better-sqlite3'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const dataDir = path.resolve(process.env.ATERS_DATA_DIR || path.join(here, '..', 'data'))
fs.mkdirSync(dataDir, { recursive: true })
const db = new Database(path.join(dataDir, 'aters.sqlite'))
db.pragma('journal_mode = WAL')
db.pragma('foreign_keys = ON')
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','dispatcher','driver','hospital')),
 active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 expires_at TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS incidents (
 id INTEGER PRIMARY KEY AUTOINCREMENT, public_ref TEXT NOT NULL UNIQUE, caller_name TEXT NOT NULL,
 caller_phone TEXT NOT NULL, category TEXT NOT NULL, severity TEXT NOT NULL DEFAULT 'high',
 description TEXT NOT NULL DEFAULT '', address TEXT NOT NULL, latitude REAL, longitude REAL,
 status TEXT NOT NULL DEFAULT 'submitted', assigned_ambulance_id INTEGER,
 assigned_hospital_id INTEGER, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, closed_at TEXT,
 FOREIGN KEY(assigned_ambulance_id) REFERENCES ambulances(id),
 FOREIGN KEY(assigned_hospital_id) REFERENCES hospitals(id)
);
CREATE TABLE IF NOT EXISTS ambulances (
 id INTEGER PRIMARY KEY AUTOINCREMENT, unit_code TEXT NOT NULL UNIQUE, driver_name TEXT NOT NULL,
 driver_phone TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'available',
 latitude REAL, longitude REAL, last_seen_at TEXT, notes TEXT NOT NULL DEFAULT '',
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS hospitals (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, address TEXT NOT NULL,
 phone TEXT NOT NULL DEFAULT '', capacity_total INTEGER NOT NULL DEFAULT 0,
 capacity_available INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'available',
 latitude REAL, longitude REAL, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_logs (
 id INTEGER PRIMARY KEY AUTOINCREMENT, actor_user_id INTEGER REFERENCES users(id),
 action TEXT NOT NULL, entity_type TEXT NOT NULL, entity_id TEXT NOT NULL,
 details TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_incidents_status_created ON incidents(status, created_at);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
`)
const count = db.prepare('SELECT COUNT(*) n FROM ambulances').get().n
if (!count) {
  const ambulance = db.prepare('INSERT INTO ambulances(unit_code,driver_name,driver_phone,status,latitude,longitude,last_seen_at,notes) VALUES(?,?,?,?,?,?,CURRENT_TIMESTAMP,?)')
  ambulance.run('AMB-101','Driver A','', 'available',22.5726,88.3639,'Demo seed unit — replace with verified fleet details')
  ambulance.run('AMB-102','Driver B','', 'available',22.5650,88.3700,'Demo seed unit — replace with verified fleet details')
  ambulance.run('AMB-103','Driver C','', 'offline',22.5850,88.3500,'Demo seed unit — replace with verified fleet details')
}
if (!db.prepare('SELECT COUNT(*) n FROM hospitals').get().n) {
  const hospital = db.prepare('INSERT INTO hospitals(name,address,phone,capacity_total,capacity_available,status,latitude,longitude) VALUES(?,?,?,?,?,?,?,?)')
  hospital.run('Demo General Hospital','Replace with verified address','',40,18,'available',22.5726,88.3639)
  hospital.run('Demo City Medical Centre','Replace with verified address','',25,7,'available',22.5650,88.3700)
}
export default db
