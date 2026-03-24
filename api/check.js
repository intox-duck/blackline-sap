import crypto from 'crypto';

export default function handler(req, res) {
  const cookies = req.headers.cookie || '';
  const match = cookies.match(/auth_session=([^;]+)/);
  const token = match ? match[1] : null;

  const expected = crypto
    .createHmac('sha256', process.env.AUTH_SECRET)
    .update(process.env.AUTH_EMAIL)
    .digest('hex');

  if (token === expected) {
    return res.status(200).json({ authenticated: true });
  }

  return res.status(401).json({ authenticated: false });
}
