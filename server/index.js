import express from 'express'
import helmet from 'helmet'
import rateLimit from 'express-rate-limit'
import bcrypt from 'bcryptjs'
import crypto from 'node:crypto'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { z } from 'zod'
import db from './db.js'

const app = express()
app.set('trust proxy',1);
// Create the initial admin only when the database has no users.
const adminName = process.env.ATERS_ADMIN_NAME?.trim();
const adminEmail = process.env.ATERS_ADMIN_EMAIL?.trim().toLowerCase();
const adminPassword = process.env.ATERS_ADMIN_PASSWORD;

if (adminName && adminEmail && adminPassword) {
  const userCount = db.prepare('SELECT COUNT(*) AS count FROM users').get().count;

  if (userCount === 0) {
    if (
      adminName.length >= 2 &&
      /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(adminEmail) &&
      adminPassword.length >= 12
    ) {
      db.prepare(
        'INSERT INTO users(name, email, password_hash, role) VALUES(?,?,?,?)'
      ).run(adminName, adminEmail, bcrypt.hashSync(adminPassword, 12), 'admin');

      console.log('Initial admin account created.');
    } else {
      console.error('Initial admin settings are invalid.');
    }
  }
}
const PORT = Number(process.env.PORT || 3000)
const isProd = process.env.NODE_ENV === 'production'
const here = path.dirname(fileURLToPath(import.meta.url))
const publicDir = path.resolve(here, '..', 'dist')
app.disable('x-powered-by')
app.use(helmet({ contentSecurityPolicy: isProd ? undefined : false, crossOriginEmbedderPolicy: false }))
app.use(express.json({ limit: '30kb' }))
app.use('/api/auth/login', rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false }))
app.use('/api/public/incidents', rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: 'draft-7', legacyHeaders: false }))

const sha = s => crypto.createHash('sha256').update(s).digest('hex')
const tokenCookie = isProd ? '__Host-aters_session' : 'aters_session'
function setSession(res, token) {
  res.cookie(tokenCookie, token, { httpOnly: true, secure: isProd, sameSite: 'strict', path: '/', maxAge: 8 * 60 * 60 * 1000 })
}
function clearSession(res) { res.clearCookie(tokenCookie, { httpOnly: true, secure: isProd, sameSite: 'strict', path: '/' }) }
function audit(userId, action, type, id, details = {}) {
  db.prepare('INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,details) VALUES(?,?,?,?,?)')
    .run(userId ?? null, action, type, String(id), JSON.stringify(details))
}
function auth(req, res, next) {
  const token = req.cookies?.[tokenCookie] || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : null)
  if (!token) return res.status(401).json({ error: 'Sign in required' })
  const row = db.prepare(`SELECT u.id,u.name,u.email,u.role,u.active,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?`).get(sha(token))
  if (!row || !row.active || new Date(row.expires_at) < new Date()) {
    if (row) db.prepare('DELETE FROM sessions WHERE token_hash=?').run(sha(token))
    clearSession(res); return res.status(401).json({ error: 'Session expired. Please sign in again.' })
  }
  req.user = { id: row.id, name: row.name, email: row.email, role: row.role }
  next()
}
function roles(...allowed) {
  return (req,res,next) => allowed.includes(req.user.role) ? next() : res.status(403).json({ error: 'You do not have permission to perform this action' })
}
function parse(schema, body, res) {
  const result = schema.safeParse(body)
  if (!result.success) { res.status(400).json({ error: 'Please check the submitted fields', details: result.error.issues.map(i => ({ field: i.path.join('.'), message: i.message })) }); return null }
  return result.data
}
const clean = s => String(s ?? '').trim()
const incidentInput = z.object({
  callerName: z.string().trim().min(2).max(100), callerPhone: z.string().trim().min(7).max(24),
  category: z.enum(['Medical emergency','Road accident','Cardiac emergency','Breathing difficulty','Injury','Other']),
  severity: z.enum(['critical','high','medium']).default('high'),
  description: z.string().trim().max(1000).default(''),
  address: z.string().trim().min(5).max(300),
  latitude: z.number().min(-90).max(90).nullable().optional(),
  longitude: z.number().min(-180).max(180).nullable().optional()
})
const statusSet = new Set(['validated','awaiting_dispatch','assigned','accepted','en_route','arrived','handover','closed','cancelled'])
const incidentStatuses = { submitted: 'Submitted', validated: 'Validated', awaiting_dispatch: 'Awaiting dispatch', assigned: 'Assigned', accepted: 'Accepted', en_route: 'En route', arrived: 'Arrived', handover: 'Handover', closed: 'Closed', cancelled: 'Cancelled' }

app.get('/api/health', (_req,res) => res.json({ ok: true, service: 'ATERS', timestamp: new Date().toISOString() }))
app.use((req,res,next) => {
  const cookie = req.headers.cookie || ''
  if (req.method !== 'GET' && req.method !== 'HEAD' && req.path.startsWith('/api/') && cookie && req.headers.origin) {
    const expected = `${req.protocol}://${req.get('host')}`
    if (req.headers.origin !== expected) return res.status(403).json({ error: 'Request origin not allowed' })
  }
  next()
})
app.use((req,res,next) => {
  const cookies = {}
  for (const part of (req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=')
    if (i > -1) cookies[part.slice(0,i).trim()] = decodeURIComponent(part.slice(i+1).trim())
  }
  req.cookies = cookies
  next()
})

app.post('/api/auth/login', (req,res) => {
  const data = parse(z.object({ email:z.string().email().max(254), password:z.string().min(1).max(200) }), req.body, res)
  if (!data) return
  const user = db.prepare('SELECT * FROM users WHERE email=? AND active=1').get(data.email.toLowerCase())
  if (!user || !bcrypt.compareSync(data.password, user.password_hash)) return res.status(401).json({ error: 'Invalid email or password' })
  const token = crypto.randomBytes(32).toString('base64url')
  const expires = new Date(Date.now()+8*60*60*1000).toISOString()
  db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').run(sha(token), user.id, expires)
  setSession(res,token)
  audit(user.id,'login','user',user.id)
  res.json({ user: { id:user.id,name:user.name,email:user.email,role:user.role }, expiresAt:expires })
})
app.get('/api/auth/me', auth, (req,res) => res.json({ user:req.user }))
app.post('/api/auth/logout', auth, (req,res) => {
  const token = req.cookies[tokenCookie] || req.headers.authorization?.slice(7)
  db.prepare('DELETE FROM sessions WHERE token_hash=?').run(sha(token))
  audit(req.user.id,'logout','user',req.user.id); clearSession(res); res.json({ ok:true })
})

app.post('/api/public/incidents', (req,res) => {
  const data = parse(incidentInput, req.body, res); if (!data) return
  const ref = 'AT-' + new Date().toISOString().slice(2,10).replaceAll('-','') + '-' + crypto.randomBytes(3).toString('hex').toUpperCase()
  const result = db.prepare(`INSERT INTO incidents(public_ref,caller_name,caller_phone,category,severity,description,address,latitude,longitude)
    VALUES(@public_ref,@caller_name,@caller_phone,@category,@severity,@description,@address,@latitude,@longitude)`).run({
    public_ref:ref,caller_name:data.callerName,caller_phone:data.callerPhone,category:data.category,severity:data.severity,
    description:data.description,address:data.address,latitude:data.latitude ?? null,longitude:data.longitude ?? null
  })
  audit(null,'incident_created','incident',result.lastInsertRowid,{publicRef:ref,source:'public-form'})
  res.status(201).json({ id:result.lastInsertRowid, reference:ref, status:'submitted', message:'Request recorded. In a real deployment, call your local emergency number if help is urgently needed; this demo does not dispatch an ambulance.' })
})
app.get('/api/public/incidents/:reference', (req,res) => {
  const item = db.prepare('SELECT public_ref AS reference,status,created_at AS createdAt,updated_at AS updatedAt FROM incidents WHERE public_ref=?').get(req.params.reference.toUpperCase())
  if (!item) return res.status(404).json({ error:'Reference not found' })
  res.json(item)
})

app.get('/api/dashboard', auth, roles('admin','dispatcher','driver','hospital'), (req,res) => {
  const stats = {
    activeIncidents: db.prepare("SELECT COUNT(*) n FROM incidents WHERE status NOT IN ('closed','cancelled')").get().n,
    pendingIncidents: db.prepare("SELECT COUNT(*) n FROM incidents WHERE status IN ('submitted','validated','awaiting_dispatch')").get().n,
    availableAmbulances: db.prepare("SELECT COUNT(*) n FROM ambulances WHERE status='available'").get().n,
    hospitalsAvailable: db.prepare("SELECT COUNT(*) n FROM hospitals WHERE status='available'").get().n
  }
  const incidents = db.prepare(`SELECT i.*, a.unit_code AS ambulance_code, h.name AS hospital_name
    FROM incidents i LEFT JOIN ambulances a ON a.id=i.assigned_ambulance_id LEFT JOIN hospitals h ON h.id=i.assigned_hospital_id
    ORDER BY CASE i.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END, i.created_at DESC LIMIT 100`).all()
  const ambulances = db.prepare('SELECT * FROM ambulances ORDER BY unit_code').all()
  const hospitals = db.prepare('SELECT * FROM hospitals ORDER BY name').all()
  const logs = db.prepare(`SELECT l.*,u.name AS actor_name FROM audit_logs l LEFT JOIN users u ON u.id=l.actor_user_id ORDER BY l.id DESC LIMIT 30`).all()
  res.json({ stats, incidents, ambulances, hospitals, logs, statuses:incidentStatuses, user:req.user })
})
app.get('/api/incidents', auth, roles('admin','dispatcher','driver','hospital'), (req,res) => {
  const rows = db.prepare(`SELECT i.*,a.unit_code AS ambulance_code,h.name AS hospital_name FROM incidents i
    LEFT JOIN ambulances a ON a.id=i.assigned_ambulance_id LEFT JOIN hospitals h ON h.id=i.assigned_hospital_id
    ORDER BY i.created_at DESC LIMIT 300`).all()
  res.json({ incidents:rows })
})
app.patch('/api/incidents/:id/status', auth, roles('admin','dispatcher'), (req,res) => {
  const data = parse(z.object({status:z.string(), note:z.string().max(500).optional()}),req.body,res); if(!data)return
  if (!statusSet.has(data.status)) return res.status(400).json({error:'Unsupported status'})
  const item = db.prepare('SELECT * FROM incidents WHERE id=?').get(Number(req.params.id))
  if (!item) return res.status(404).json({error:'Incident not found'})
  const allowed = {
    submitted:['validated','cancelled'], validated:['awaiting_dispatch','cancelled'], awaiting_dispatch:['assigned','cancelled'],
    assigned:['accepted','awaiting_dispatch','cancelled'], accepted:['en_route','cancelled'], en_route:['arrived','cancelled'],
    arrived:['handover'], handover:['closed'], closed:[], cancelled:[]
  }
  if (!allowed[item.status]?.includes(data.status)) return res.status(409).json({error:`Cannot move incident from ${item.status} to ${data.status}`})
  if(req.user.role==='driver' && item.assigned_ambulance_id==null) return res.status(403).json({error:'Drivers can only update incidents assigned to an ambulance'})
  const tx = db.transaction(() => {
    db.prepare(`UPDATE incidents SET status=?,updated_at=CURRENT_TIMESTAMP,closed_at=CASE WHEN ?='closed' THEN CURRENT_TIMESTAMP ELSE closed_at END WHERE id=?`).run(data.status,data.status,item.id)
    if (item.assigned_ambulance_id) {
      if (data.status === 'en_route') db.prepare("UPDATE ambulances SET status='en_route',updated_at=CURRENT_TIMESTAMP WHERE id=?").run(item.assigned_ambulance_id)
      if (data.status === 'closed' || data.status === 'cancelled' || data.status === 'awaiting_dispatch') db.prepare("UPDATE ambulances SET status='available',updated_at=CURRENT_TIMESTAMP WHERE id=?").run(item.assigned_ambulance_id)
    }
    audit(req.user.id,'incident_status_changed','incident',item.id,{from:item.status,to:data.status,note:data.note||''})
  })
  tx()
  res.json({ok:true,status:data.status})
})
app.post('/api/incidents/:id/assign', auth, roles('admin','dispatcher'), (req,res) => {
  const data = parse(z.object({ambulanceId:z.number().int().positive(),hospitalId:z.number().int().positive().optional()}),req.body,res); if(!data)return
  const incident = db.prepare('SELECT * FROM incidents WHERE id=?').get(Number(req.params.id))
  if(!incident)return res.status(404).json({error:'Incident not found'})
  if(['closed','cancelled'].includes(incident.status))return res.status(409).json({error:'Closed incidents cannot be assigned'})
  const amb = db.prepare('SELECT * FROM ambulances WHERE id=?').get(data.ambulanceId)
  if(!amb)return res.status(404).json({error:'Ambulance not found'})
  if(amb.status!=='available' && amb.id!==incident.assigned_ambulance_id)return res.status(409).json({error:'Ambulance is not available'})
  const hosp = data.hospitalId ? db.prepare('SELECT * FROM hospitals WHERE id=?').get(data.hospitalId) : null
  if(data.hospitalId && !hosp)return res.status(404).json({error:'Hospital not found'})
  const tx = db.transaction(() => {
    if(incident.assigned_ambulance_id && incident.assigned_ambulance_id!==amb.id) db.prepare("UPDATE ambulances SET status='available',updated_at=CURRENT_TIMESTAMP WHERE id=?").run(incident.assigned_ambulance_id)
    db.prepare("UPDATE ambulances SET status='assigned',updated_at=CURRENT_TIMESTAMP WHERE id=?").run(amb.id)
    db.prepare("UPDATE incidents SET assigned_ambulance_id=?,assigned_hospital_id=?,status='assigned',updated_at=CURRENT_TIMESTAMP WHERE id=?").run(amb.id,hosp?.id ?? incident.assigned_hospital_id,incident.id)
    audit(req.user.id,'ambulance_assigned','incident',incident.id,{ambulanceId:amb.id,unitCode:amb.unit_code,hospitalId:hosp?.id??null})
  })
  tx(); res.json({ok:true})
})
app.post('/api/ambulances', auth, roles('admin'), (req,res) => {
  const data=parse(z.object({unitCode:z.string().trim().min(2).max(30),driverName:z.string().trim().min(2).max(100),driverPhone:z.string().trim().max(24).default(''),status:z.enum(['available','assigned','en_route','offline']).default('available'),notes:z.string().max(300).default('')}),req.body,res);if(!data)return
  try {
    const r=db.prepare('INSERT INTO ambulances(unit_code,driver_name,driver_phone,status,notes) VALUES(?,?,?,?,?)').run(data.unitCode,data.driverName,data.driverPhone,data.status,data.notes)
    audit(req.user.id,'ambulance_created','ambulance',r.lastInsertRowid,{unitCode:data.unitCode});res.status(201).json({id:r.lastInsertRowid})
  } catch { res.status(409).json({error:'That unit code already exists'}) }
})
app.patch('/api/ambulances/:id/location', auth, roles('admin','dispatcher','driver'), (req,res) => {
  const data=parse(z.object({latitude:z.number().min(-90).max(90),longitude:z.number().min(-180).max(180)}),req.body,res);if(!data)return
  const amb=db.prepare('SELECT * FROM ambulances WHERE id=?').get(Number(req.params.id));if(!amb)return res.status(404).json({error:'Ambulance not found'})
  db.prepare('UPDATE ambulances SET latitude=?,longitude=?,last_seen_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(data.latitude,data.longitude,amb.id)
  audit(req.user.id,'ambulance_location_updated','ambulance',amb.id,{latitude:data.latitude,longitude:data.longitude})
  res.json({ok:true,lastSeenAt:new Date().toISOString()})
})
app.patch('/api/ambulances/:id/status', auth, roles('admin','dispatcher'), (req,res) => {
  const data=parse(z.object({status:z.enum(['available','assigned','en_route','offline'])}),req.body,res);if(!data)return
  const amb=db.prepare('SELECT * FROM ambulances WHERE id=?').get(Number(req.params.id));if(!amb)return res.status(404).json({error:'Ambulance not found'})
  db.prepare('UPDATE ambulances SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(data.status,amb.id)
  audit(req.user.id,'ambulance_status_changed','ambulance',amb.id,{from:amb.status,to:data.status});res.json({ok:true})
})
app.patch('/api/hospitals/:id/capacity', auth, roles('admin','dispatcher','hospital'), (req,res) => {
  if(req.user.role==='hospital') return res.status(403).json({error:'Hospital users need an assigned hospital account before editing capacity'})
  const data=parse(z.object({capacityTotal:z.number().int().min(0).max(100000),capacityAvailable:z.number().int().min(0).max(100000),status:z.enum(['available','busy','full','offline'])}),req.body,res);if(!data)return
  if(data.capacityAvailable>data.capacityTotal)return res.status(400).json({error:'Available capacity cannot exceed total capacity'})
  const hosp=db.prepare('SELECT * FROM hospitals WHERE id=?').get(Number(req.params.id));if(!hosp)return res.status(404).json({error:'Hospital not found'})
  db.prepare('UPDATE hospitals SET capacity_total=?,capacity_available=?,status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(data.capacityTotal,data.capacityAvailable,data.status,hosp.id)
  audit(req.user.id,'hospital_capacity_updated','hospital',hosp.id,{capacityTotal:data.capacityTotal,capacityAvailable:data.capacityAvailable,status:data.status});res.json({ok:true})
})
app.post('/api/hospitals', auth, roles('admin'), (req,res) => {
  const data=parse(z.object({name:z.string().trim().min(2).max(120),address:z.string().trim().min(5).max(300),phone:z.string().trim().max(24).default(''),capacityTotal:z.number().int().min(0).max(100000),capacityAvailable:z.number().int().min(0).max(100000),status:z.enum(['available','busy','full','offline']).default('available')}),req.body,res);if(!data)return
  if(data.capacityAvailable>data.capacityTotal)return res.status(400).json({error:'Available capacity cannot exceed total capacity'})
  try{const r=db.prepare('INSERT INTO hospitals(name,address,phone,capacity_total,capacity_available,status) VALUES(?,?,?,?,?,?)').run(data.name,data.address,data.phone,data.capacityTotal,data.capacityAvailable,data.status);audit(req.user.id,'hospital_created','hospital',r.lastInsertRowid,{name:data.name});res.status(201).json({id:r.lastInsertRowid})}catch{res.status(409).json({error:'Hospital name already exists'})}
})
app.get('/api/admin/users', auth, roles('admin'), (_req,res) => res.json({users:db.prepare('SELECT id,name,email,role,active,created_at AS createdAt FROM users ORDER BY id DESC').all()}))
app.post('/api/admin/users', auth, roles('admin'), (req,res) => {
  const data=parse(z.object({name:z.string().trim().min(2).max(100),email:z.string().email().max(254),password:z.string().min(12).max(200),role:z.enum(['admin','dispatcher','driver','hospital'])}),req.body,res);if(!data)return
  try{const r=db.prepare('INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)').run(data.name,data.email.toLowerCase(),bcrypt.hashSync(data.password,12),data.role);audit(req.user.id,'user_created','user',r.lastInsertRowid,{email:data.email,role:data.role});res.status(201).json({id:r.lastInsertRowid})}catch{res.status(409).json({error:'Email already exists'})}
})
app.get('/api/audit', auth, roles('admin','dispatcher'), (_req,res) => res.json({logs:db.prepare('SELECT l.*,u.name AS actor_name FROM audit_logs l LEFT JOIN users u ON u.id=l.actor_user_id ORDER BY l.id DESC LIMIT 500').all()}))

app.use('/api', (_req,res) => res.status(404).json({error:'API route not found'}))
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(publicDir, { index:false, maxAge:'1d', immutable:false }))
  app.get('*', (_req,res) => res.sendFile(path.join(publicDir,'index.html')))
}
app.use((err, _req, res, _next) => {
  console.error('Unhandled server error:', err?.message || err)
  res.status(500).json({ error: 'Unexpected server error' })
})
app.listen(PORT, () => console.log(`ATERS API listening on http://localhost:${PORT}`))
