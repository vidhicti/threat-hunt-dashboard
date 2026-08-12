import express from 'express'
import { createServer } from 'http'

// Import all API handlers
import threatactors from './api/threatactors.js'
import feeds1 from './api/feeds1.js'
import feeds2 from './api/feeds2.js'
import feeds3 from './api/feeds3.js'
import virustotal from './api/virustotal.js'
import abuseipdb from './api/abuseipdb.js'
import shodan from './api/shodan.js'
import lookup from './api/lookup.js'
import misp from './api/misp.js'
import opencti from './api/opencti.js'
import indexHandler from './api/index.js'

const app = express()
app.use(express.json())

// Allow CORS for local Vite dev server
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-apikey')
  if (req.method === 'OPTIONS') {
    res.status(200).end()
    return
  }
  next()
})

// Route each API handler
app.all('/api/threatactors', (req, res) => threatactors(req, res))
app.all('/api/feeds1', (req, res) => feeds1(req, res))
app.all('/api/feeds2', (req, res) => feeds2(req, res))
app.all('/api/feeds3', (req, res) => feeds3(req, res))
app.all('/api/virustotal', (req, res) => virustotal(req, res))
app.all('/api/abuseipdb', (req, res) => abuseipdb(req, res))
app.all('/api/shodan', (req, res) => shodan(req, res))
app.all('/api/lookup', (req, res) => lookup(req, res))
app.all('/api/misp', (req, res) => misp(req, res))
app.all('/api/opencti', (req, res) => opencti(req, res))
app.all('/api', (req, res) => indexHandler(req, res))

const PORT = 3000
createServer(app).listen(PORT, () => {
  console.log(`[API Server] Running at http://localhost:${PORT}`)
})
