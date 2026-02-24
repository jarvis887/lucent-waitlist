export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { email, token, website, timestamp } = req.body || {};

  // Honeypot check — bots fill hidden fields
  if (website) {
    // Silently accept to not tip off bots
    return res.status(200).json({ success: true });
  }

  // Timing check — reject if submitted < 3s after page load
  if (timestamp && Date.now() - timestamp < 3000) {
    return res.status(200).json({ success: true });
  }

  // Email required
  if (!email || typeof email !== 'string' || !email.includes('@')) {
    return res.status(400).json({ error: 'Valid email required' });
  }

  // Turnstile verification
  if (!token) {
    return res.status(403).json({ error: 'Bot verification failed' });
  }

  const secret = process.env.TURNSTILE_SECRET_KEY;
  if (!secret) {
    console.error('TURNSTILE_SECRET_KEY not configured');
    return res.status(500).json({ error: 'Server configuration error' });
  }

  try {
    const verifyRes = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ secret, response: token }),
    });
    const result = await verifyRes.json();

    if (!result.success) {
      return res.status(403).json({ error: 'Bot verification failed' });
    }
  } catch (err) {
    console.error('Turnstile verification error:', err);
    return res.status(500).json({ error: 'Verification service unavailable' });
  }

  // Forward to Google Apps Script
  try {
    await fetch(
      'https://script.google.com/macros/s/AKfycbzoX0IYn4SX_sGGAsHi5l48HNvwLZReFsoqVW2itEfB4ulRRoD5SL5qRYycWJb9Y5G7/exec',
      {
        method: 'POST',
        headers: { 'Content-Type': 'text/plain' },
        body: JSON.stringify({ email, source: 'mylucentai.com' }),
      }
    );
    return res.status(200).json({ success: true });
  } catch (err) {
    console.error('Google Sheets forwarding error:', err);
    return res.status(500).json({ error: 'Failed to save signup' });
  }
}
