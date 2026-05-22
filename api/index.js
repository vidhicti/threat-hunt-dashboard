export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.status(200).json({ 
    status: 'ok', 
    message: 'Threat Intel API running',
    endpoints: ['/api/threatfox','/api/urlhaus','/api/feodotracker','/api/malwarebazaar','/api/emergingthreats','/api/cinsarmy','/api/sslblacklist','/api/alienvault','/api/certpoland']
  })
}
