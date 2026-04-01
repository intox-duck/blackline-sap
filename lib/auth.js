import crypto from 'crypto';

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

export function getAllowedEmails() {
  const emails = new Set();
  const csv = String(process.env.AUTH_EMAILS || '');

  csv
    .split(',')
    .map(normalizeEmail)
    .filter(Boolean)
    .forEach((email) => emails.add(email));

  const fallbackEmail = normalizeEmail(process.env.AUTH_EMAIL);
  if (fallbackEmail) {
    emails.add(fallbackEmail);
  }

  return [...emails];
}

export function isAllowedLogin(email, password) {
  const normalizedEmail = normalizeEmail(email);
  if (!normalizedEmail || !password) {
    return false;
  }

  if (!getAllowedEmails().includes(normalizedEmail)) {
    return false;
  }

  const userPasswords = parseUserPasswords();
  const expected = userPasswords[normalizedEmail] || process.env.AUTH_PASSWORD;
  return password === expected;
}

function parseUserPasswords() {
  const map = {};
  const raw = String(process.env.AUTH_USER_PASSWORDS || '');
  for (const entry of raw.split(',')) {
    const idx = entry.indexOf(':');
    if (idx > 0) {
      const em = normalizeEmail(entry.slice(0, idx));
      const pw = entry.slice(idx + 1);
      if (em && pw) map[em] = pw;
    }
  }
  return map;
}

export function createSessionToken(email) {
  return crypto
    .createHmac('sha256', process.env.AUTH_SECRET)
    .update(normalizeEmail(email))
    .digest('hex');
}

export function isValidSessionToken(token) {
  if (!token) {
    return false;
  }

  return getAllowedEmails().some((email) => createSessionToken(email) === token);
}
