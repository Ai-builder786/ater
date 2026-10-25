import bcrypt from 'bcryptjs'
import readline from 'node:readline/promises'
import { stdin as input, stdout as output } from 'node:process'
import db from '../server/db.js'

const rl = readline.createInterface({ input, output })
try {
  const name = (await rl.question('Admin full name: ')).trim()
  const email = (await rl.question('Admin email: ')).trim().toLowerCase()
  const password = await rl.question('Admin password (minimum 12 characters): ')
  if (name.length < 2 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 12) {
    console.error('Invalid input. Name must be 2+ characters, email valid, password at least 12 characters.')
    process.exitCode = 1
  } else {
    const exists = db.prepare('SELECT id FROM users WHERE email=?').get(email)
    if (exists) { console.error('A user with this email already exists.'); process.exitCode = 1 }
    else {
      db.prepare('INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)').run(name,email,bcrypt.hashSync(password,12),'admin')
      console.log('Admin account created. Sign in from the ATERS dashboard.')
    }
  }
} finally { rl.close(); db.close() }
