import { isValidSessionToken } from '../lib/auth.js';

export default function handler(req, res) {
  const cookies = req.headers.cookie || '';
  const match = cookies.match(/auth_session=([^;]+)/);
  const token = match ? match[1] : null;

  if (isValidSessionToken(token)) {
    return res.status(200).json({ authenticated: true });
  }

  return res.status(401).json({ authenticated: false });
}
