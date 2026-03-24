import crypto from 'crypto';

export default function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { email, password } = req.body;

  if (
    email === process.env.AUTH_EMAIL &&
    password === process.env.AUTH_PASSWORD
  ) {
    const token = crypto
      .createHmac('sha256', process.env.AUTH_SECRET)
      .update(email)
      .digest('hex');

    res.setHeader('Set-Cookie', [
      `auth_session=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400`,
    ]);
    return res.status(200).json({ success: true });
  }

  return res.status(401).json({ error: 'Invalid credentials' });
}
