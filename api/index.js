export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-apikey')
  if (req.method === 'OPTIONS') {
    res.status(200).end()
    return
  }

  res.status(200).json({
    status: 'ok',
    message: 'Threat Intel API running',
    version: '2.0',
    endpoints: {
      feeds: [
        '/api/feeds1?feed=threatfox',
        '/api/feeds1?feed=urlhaus',
        '/api/feeds1?feed=feodotracker',
        '/api/feeds1?feed=malwarebazaar',
        '/api/feeds2?feed=emergingthreats',
        '/api/feeds2?feed=cinsarmy',
        '/api/feeds2?feed=sslblacklist',
        '/api/feeds3?feed=alienvault',
        '/api/feeds3?feed=certpoland',
      ],
      enrichment: [
        '/api/virustotal',
        '/api/abuseipdb',
        '/api/shodan',
      ],
    },
  })
}
