import crypto from 'crypto';

export type QrLoginStatus = 'pending' | 'scanned' | 'confirmed' | 'expired' | 'cancelled' | 'used';

export interface QrLoginSession {
  token: string;
  status: QrLoginStatus;
  createdAt: number;
  expiresAt: number;
  authToken?: string;
  userAgent?: string;
}

type GlobalWithQr = typeof globalThis & { __moonTvQrLoginStore?: Map<string, QrLoginSession> };

const g = globalThis as GlobalWithQr;
export const qrLoginStore = g.__moonTvQrLoginStore || new Map<string, QrLoginSession>();
g.__moonTvQrLoginStore = qrLoginStore;

const QR_LOGIN_HASH_KEY = 'qr_login_sessions';

let getStorage: (() => any) | null = null;

async function loadStorage() {
  try {
    if (!getStorage) {
      const db = await import('@/lib/db');
      getStorage = db.getStorage;
    }
    const storage = getStorage();
    return storage && typeof (storage as any).adapter?.hGet === 'function' ? storage : null;
  } catch {
    return null;
  }
}

async function persistQrLoginSession(session: QrLoginSession) {
  qrLoginStore.set(session.token, session);

  const storage = await loadStorage();
  if (!storage || typeof (storage as any).adapter?.hSet !== 'function') return;

  await (storage as any).adapter.hSet(QR_LOGIN_HASH_KEY, session.token, JSON.stringify(session));
}

async function deletePersistedQrLoginSession(token: string) {
  qrLoginStore.delete(token);

  const storage = await loadStorage();
  if (!storage || typeof (storage as any).adapter?.hDel !== 'function') return;

  await (storage as any).adapter.hDel(QR_LOGIN_HASH_KEY, token);
}

export async function createQrLoginSession(ttlMs = 120_000) {
  await cleanupQrLoginSessions();
  const token = crypto.randomBytes(24).toString('base64url');
  const now = Date.now();
  const session: QrLoginSession = {
    token,
    status: 'pending',
    createdAt: now,
    expiresAt: now + ttlMs,
  };
  await persistQrLoginSession(session);
  return session;
}

export async function getQrLoginSession(token?: string | null) {
  if (!token) return null;
  let session = qrLoginStore.get(token) || null;

  if (!session) {
    const storage = await loadStorage();
    if (storage && typeof (storage as any).adapter?.hGet === 'function') {
      const raw = await (storage as any).adapter.hGet(QR_LOGIN_HASH_KEY, token);
      if (raw) {
        try {
          session = JSON.parse(raw) as QrLoginSession;
          qrLoginStore.set(token, session);
        } catch {
          await deletePersistedQrLoginSession(token);
          return null;
        }
      }
    }
  }

  if (session && session.expiresAt <= Date.now() && session.status !== 'confirmed' && session.status !== 'used') {
    session.status = 'expired';
    await persistQrLoginSession(session);
  }
  return session;
}

export async function saveQrLoginSession(session: QrLoginSession) {
  await persistQrLoginSession(session);
}

export async function cleanupQrLoginSessions() {
  const now = Date.now();
  for (const [token, session] of Array.from(qrLoginStore.entries())) {
    if (session.expiresAt + 300_000 < now || session.status === 'used') {
      await deletePersistedQrLoginSession(token);
    }
  }

  const storage = await loadStorage();
  if (!storage || typeof (storage as any).adapter?.hGetAll !== 'function') return;

  const sessions = await (storage as any).adapter.hGetAll(QR_LOGIN_HASH_KEY);
  for (const [token, raw] of Object.entries(sessions)) {
    try {
      const session = JSON.parse(raw as string) as QrLoginSession;
      if (session.expiresAt + 300_000 < now || session.status === 'used') {
        await deletePersistedQrLoginSession(token);
      }
    } catch {
      await deletePersistedQrLoginSession(token);
    }
  }
}
