import { createSessionToken, isAllowedLogin } from '../lib/auth.js';

export default function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { email, password } = req.body;

  if (isAllowedLogin(email, password)) {
    const token = createSessionToken(email);

    res.setHeader('Set-Cookie', [
      `auth_session=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400`,
    ]);
    return res.status(200).json({ success: true });
  }

  return res.status(401).json({ error: 'Invalid credentials' });
}
