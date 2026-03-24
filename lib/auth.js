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
  if (!normalizedEmail || password !== process.env.AUTH_PASSWORD) {
    return false;
  }

  return getAllowedEmails().includes(normalizedEmail);
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
