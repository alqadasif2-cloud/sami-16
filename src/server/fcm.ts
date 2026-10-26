import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import {
  firestoreClient,
  projectId,
  databaseId,
  getChannelById,
  isChannelOpenPublic,
  getAllUsersList,
} from './db.ts';

/**
 * Firebase Cloud Messaging (FCM) Push Notification Service for Sami
 * Uses shared Firestore collection `community_notifications` (type = 'fcm_device_token' for tokens
 * and fcmStatus = 'pending' for push jobs) which is authorized across Web, Android, and Server.
 */

export interface DeviceTokenRecord {
  id: string;
  token: string;
  userId: number;
  username: string;
  deviceId: string;
  platform: string;
  deviceModel?: string;
  updatedAt: number;
  createdAt: number;
}

const DATA_DIR = path.resolve('data');
const TOKENS_FILE = path.join(DATA_DIR, 'fcm_tokens.json');
const SHARED_NOTIF_COLLECTION = 'community_notifications';

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

function loadLocalTokens(): Record<string, DeviceTokenRecord> {
  try {
    if (fs.existsSync(TOKENS_FILE)) {
      return JSON.parse(fs.readFileSync(TOKENS_FILE, 'utf8'));
    }
  } catch {}
  return {};
}

function saveLocalTokens(store: Record<string, DeviceTokenRecord>): void {
  try {
    fs.writeFileSync(TOKENS_FILE, JSON.stringify(store, null, 2), 'utf8');
  } catch (e) {
    console.warn('[FCM] Error saving local token store:', e);
  }
}

const localTokens = loadLocalTokens();

function getFirestoreBaseUrl(): string {
  const dbSeg = encodeURIComponent(databaseId || '(default)');
  return `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/databases/${dbSeg}/documents`;
}

function sanitizeDocIdPart(val: string): string {
  return String(val || 'android').replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 64) || 'android';
}

function buildTokenDocId(userId: number, deviceId: string): string {
  return `fcm_tok_${userId}_${sanitizeDocIdPart(deviceId)}`;
}

// ==========================================
// 1. TOKEN REGISTRATION, REFRESH & CLEANUP
// ==========================================

export async function registerDeviceToken(params: {
  token: string;
  userId: number;
  username: string;
  deviceId?: string;
  platform?: string;
  deviceModel?: string;
}): Promise<DeviceTokenRecord> {
  const cleanToken = String(params.token || '').trim();
  const userId = Number(params.userId);
  if (!cleanToken || !userId || userId <= 0) {
    throw new Error('بيانات تسجيل رمز الإشعارات غير صالحة');
  }

  const deviceId = sanitizeDocIdPart(
    params.deviceId?.trim() || crypto.createHash('sha1').update(cleanToken).digest('hex').slice(0, 16)
  );
  const now = Date.now();
  const docId = buildTokenDocId(userId, deviceId);

  // Clean up any stale bindings on the same physical device or same FCM token (account switch protection)
  for (const [k, existing] of Object.entries(localTokens)) {
    if (k !== docId && (existing.token === cleanToken || existing.deviceId === deviceId)) {
      delete localTokens[k];
    }
  }

  const record: DeviceTokenRecord = {
    id: docId,
    token: cleanToken,
    userId,
    username: params.username || `user_${userId}`,
    deviceId,
    platform: params.platform || 'android',
    deviceModel: params.deviceModel || 'Android',
    updatedAt: now,
    createdAt: localTokens[docId]?.createdAt || now,
  };

  localTokens[docId] = record;
  saveLocalTokens(localTokens);

  // Clean stale bindings in shared Firestore community_notifications (type == 'fcm_device_token')
  try {
    const res = await fetch(`${getFirestoreBaseUrl()}:runQuery`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        structuredQuery: {
          from: [{ collectionId: SHARED_NOTIF_COLLECTION }],
          where: {
            compositeFilter: {
              op: 'AND',
              filters: [
                {
                  fieldFilter: {
                    field: { fieldPath: 'type' },
                    op: 'EQUAL',
                    value: { stringValue: 'fcm_device_token' },
                  },
                },
                {
                  fieldFilter: {
                    field: { fieldPath: 'deviceId' },
                    op: 'EQUAL',
                    value: { stringValue: deviceId },
                  },
                },
              ],
            },
          },
          limit: 15,
        },
      }),
    });
    if (res.ok) {
      const rows: any[] = await res.json();
      for (const row of rows) {
        const docName = row?.document?.name;
        if (docName && !String(docName).endsWith(`/${docId}`)) {
          await fetch(`https://firestore.googleapis.com/v1/${docName}`, { method: 'DELETE' }).catch(() => {});
        }
      }
    }
  } catch {}

  if (firestoreClient) {
    try {
      await firestoreClient.collection(SHARED_NOTIF_COLLECTION).doc(docId).set(
        {
          ...record,
          type: 'fcm_device_token',
          title: 'fcm_token',
          body: '',
          senderId: userId,
          senderName: record.username,
          targetUserIds: [],
          timestamp: now,
        },
        { merge: true }
      );
      return record;
    } catch {}
  }

  try {
    const url = `${getFirestoreBaseUrl()}/${SHARED_NOTIF_COLLECTION}/${encodeURIComponent(docId)}`;
    await fetch(url, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        fields: {
          id: { stringValue: record.id },
          type: { stringValue: 'fcm_device_token' },
          title: { stringValue: 'fcm_token' },
          body: { stringValue: '' },
          token: { stringValue: record.token },
          userId: { integerValue: String(record.userId) },
          senderId: { integerValue: String(record.userId) },
          username: { stringValue: record.username },
          senderName: { stringValue: record.username },
          deviceId: { stringValue: record.deviceId },
          platform: { stringValue: record.platform },
          deviceModel: { stringValue: record.deviceModel || 'Android' },
          targetUserIds: { arrayValue: { values: [] } },
          timestamp: { integerValue: String(record.updatedAt) },
          updatedAt: { integerValue: String(record.updatedAt) },
          createdAt: { integerValue: String(record.createdAt) },
        },
      }),
    });
  } catch (err: any) {
    console.warn('[FCM] Firestore REST token save notice:', err?.message);
  }

  return record;
}

export async function unregisterDeviceToken(userId: number, token?: string, deviceId?: string): Promise<void> {
  const cleanTok = token?.trim();
  const cleanDev = deviceId ? sanitizeDocIdPart(deviceId.trim()) : undefined;

  for (const [k, rec] of Object.entries(localTokens)) {
    const matchesUser = rec.userId === userId;
    const matchesTok = cleanTok && rec.token === cleanTok;
    const matchesDev = cleanDev && rec.deviceId === cleanDev;
    if (matchesTok || (matchesUser && matchesDev) || (matchesUser && !cleanTok && !cleanDev)) {
      delete localTokens[k];
    }
  }
  saveLocalTokens(localTokens);

  if (cleanDev && userId > 0) {
    const docId = buildTokenDocId(userId, cleanDev);
    await fetch(`${getFirestoreBaseUrl()}/${SHARED_NOTIF_COLLECTION}/${encodeURIComponent(docId)}`, {
      method: 'DELETE',
    }).catch(() => {});
  }

  try {
    const res = await fetch(`${getFirestoreBaseUrl()}:runQuery`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        structuredQuery: {
          from: [{ collectionId: SHARED_NOTIF_COLLECTION }],
          where: {
            compositeFilter: {
              op: 'AND',
              filters: [
                {
                  fieldFilter: {
                    field: { fieldPath: 'type' },
                    op: 'EQUAL',
                    value: { stringValue: 'fcm_device_token' },
                  },
                },
                {
                  fieldFilter: {
                    field: { fieldPath: 'userId' },
                    op: 'EQUAL',
                    value: { integerValue: String(userId) },
                  },
                },
              ],
            },
          },
          limit: 25,
        },
      }),
    });
    if (res.ok) {
      const rows: any[] = await res.json();
      for (const row of rows) {
        const doc = row?.document;
        if (!doc?.name || !doc?.fields) continue;
        const docTok = doc.fields.token?.stringValue || '';
        const docDev = doc.fields.deviceId?.stringValue || '';
        if (
          (cleanTok && docTok === cleanTok) ||
          (cleanDev && docDev === cleanDev) ||
          (!cleanTok && !cleanDev)
        ) {
          await fetch(`https://firestore.googleapis.com/v1/${doc.name}`, { method: 'DELETE' }).catch(() => {});
        }
      }
    }
  } catch {}
}

async function pruneInvalidToken(badToken: string): Promise<void> {
  let modified = false;
  for (const [k, rec] of Object.entries(localTokens)) {
    if (rec.token === badToken) {
      delete localTokens[k];
      modified = true;
    }
  }
  if (modified) saveLocalTokens(localTokens);

  try {
    const res = await fetch(`${getFirestoreBaseUrl()}:runQuery`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        structuredQuery: {
          from: [{ collectionId: SHARED_NOTIF_COLLECTION }],
          where: {
            compositeFilter: {
              op: 'AND',
              filters: [
                {
                  fieldFilter: {
                    field: { fieldPath: 'type' },
                    op: 'EQUAL',
                    value: { stringValue: 'fcm_device_token' },
                  },
                },
                {
                  fieldFilter: {
                    field: { fieldPath: 'token' },
                    op: 'EQUAL',
                    value: { stringValue: badToken },
                  },
                },
              ],
            },
          },
          limit: 20,
        },
      }),
    });
    if (res.ok) {
      const rows: any[] = await res.json();
      for (const row of rows) {
        if (row?.document?.name) {
          await fetch(`https://firestore.googleapis.com/v1/${row.document.name}`, { method: 'DELETE' }).catch(() => {});
        }
      }
    }
  } catch {}
}

export async function getTokensForUsers(
  userIds: number[],
  excludeSenderId?: number
): Promise<Array<{ token: string; userId: number }>> {
  const allowedIds = Array.from(
    new Set(userIds.filter((id) => id > 0 && id !== excludeSenderId))
  );
  if (allowedIds.length === 0) return [];

  const tokenToUser = new Map<string, number>();

  for (const rec of Object.values(localTokens)) {
    if (allowedIds.includes(rec.userId) && rec.token) {
      tokenToUser.set(rec.token, rec.userId);
    }
  }

  try {
    const res = await fetch(`${getFirestoreBaseUrl()}:runQuery`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        structuredQuery: {
          from: [{ collectionId: SHARED_NOTIF_COLLECTION }],
          where: {
            fieldFilter: {
              field: { fieldPath: 'type' },
              op: 'EQUAL',
              value: { stringValue: 'fcm_device_token' },
            },
          },
          limit: 400,
        },
      }),
    });
    if (res.ok) {
      const rows: any[] = await res.json();
      for (const row of rows) {
        const f = row?.document?.fields;
        if (!f) continue;
        const uid = Number(f.userId?.integerValue || 0);
        const tok = String(f.token?.stringValue || '').trim();
        if (tok && allowedIds.includes(uid) && uid !== excludeSenderId) {
          tokenToUser.set(tok, uid);
        }
      }
    }
  } catch {}

  return Array.from(tokenToUser.entries()).map(([token, userId]) => ({ token, userId }));
}

// ==========================================
// 2. OAUTH2 / CREDENTIAL VALIDATION FOR FCM HTTP v1 API
// ==========================================

let cachedAccessToken: string | null = null;
let cachedTokenExpiry = 0;
let cachedMetadataProjectId: string | null | undefined = undefined;
let loggedMissingCredsWarning = false;

function parseValidServiceAccountJson(): { client_email: string; private_key: string; project_id: string } | null {
  const saRaw = (process.env.FIREBASE_SERVICE_ACCOUNT_KEY || process.env.GCP_SERVICE_ACCOUNT_KEY || '').trim();
  if (!saRaw || saRaw.length < 120) return null;
  try {
    const jsonStr = saRaw.startsWith('{') ? saRaw : Buffer.from(saRaw, 'base64').toString('utf8');
    if (!jsonStr.trim().startsWith('{')) return null;
    const creds = JSON.parse(jsonStr);
    if (
      creds?.type === 'service_account' &&
      typeof creds.client_email === 'string' &&
      typeof creds.private_key === 'string' &&
      creds.private_key.includes('BEGIN PRIVATE KEY')
    ) {
      return {
        client_email: creds.client_email,
        private_key: creds.private_key,
        project_id: String(creds.project_id || projectId),
      };
    }
  } catch {}
  return null;
}

function getValidLegacyServerKey(): string | null {
  const raw = (process.env.FCM_SERVER_KEY || process.env.FIREBASE_SERVER_KEY || '').trim();
  if (!raw || raw.length < 80) return null;
  if (raw.startsWith('ai-studio-') || raw.endsWith('-media') || raw.includes(' ')) return null;
  return raw;
}

export function hasServerFcmCredentials(): { configured: boolean; mode: string; reason?: string } {
  const sa = parseValidServiceAccountJson();
  if (sa) {
    if (sa.project_id && sa.project_id !== projectId) {
      return {
        configured: false,
        mode: 'project_mismatch',
        reason: `Service account belongs to "${sa.project_id}" instead of "${projectId}"`,
      };
    }
    return { configured: true, mode: 'service_account_v1' };
  }
  if (cachedMetadataProjectId === projectId) {
    return { configured: true, mode: 'gce_metadata_adc_v1' };
  }
  const legacy = getValidLegacyServerKey();
  if (legacy) {
    return { configured: true, mode: 'legacy_server_key' };
  }
  return {
    configured: false,
    mode: 'missing_credentials',
    reason: `FIREBASE_SERVICE_ACCOUNT_KEY (JSON for project "${projectId}") is not configured on the server`,
  };
}

function base64UrlEncode(input: Buffer | string): string {
  const buf = typeof input === 'string' ? Buffer.from(input, 'utf8') : input;
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function getGoogleOAuth2AccessToken(): Promise<string | null> {
  const now = Date.now();
  if (cachedAccessToken && now < cachedTokenExpiry - 60_000) {
    return cachedAccessToken;
  }

  // 1. Service Account JSON (FIREBASE_SERVICE_ACCOUNT_KEY or GCP_SERVICE_ACCOUNT_KEY)
  const creds = parseValidServiceAccountJson();
  if (creds && (!creds.project_id || creds.project_id === projectId)) {
    try {
      const iat = Math.floor(now / 1000);
      const exp = iat + 3600;
      const header = base64UrlEncode(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
      const claimSet = base64UrlEncode(
        JSON.stringify({
          iss: creds.client_email,
          scope: 'https://www.googleapis.com/auth/firebase.messaging',
          aud: 'https://oauth2.googleapis.com/token',
          iat,
          exp,
        })
      );
      const signer = crypto.createSign('RSA-SHA256');
      signer.update(`${header}.${claimSet}`);
      signer.end();
      const signature = base64UrlEncode(signer.sign(creds.private_key));
      const assertion = `${header}.${claimSet}.${signature}`;

      const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
          assertion,
        }).toString(),
      });

      if (tokenRes.ok) {
        const tokenData: any = await tokenRes.json();
        if (tokenData.access_token) {
          cachedAccessToken = tokenData.access_token;
          cachedTokenExpiry = now + (Number(tokenData.expires_in) || 3500) * 1000;
          return cachedAccessToken;
        }
      } else {
        const errBody = await tokenRes.text().catch(() => '');
        console.warn('[FCM] Service Account OAuth2 token exchange failed:', tokenRes.status, errBody.slice(0, 180));
      }
    } catch (e: any) {
      console.warn('[FCM] Service Account JWT signing failed:', e?.message);
    }
  }

  // 2. GCE / Cloud Run Metadata Server ADC — ONLY if running inside the matching Firebase GCP project!
  try {
    if (cachedMetadataProjectId === undefined) {
      const ctrlProj = new AbortController();
      const tProj = setTimeout(() => ctrlProj.abort(), 1500);
      const projRes = await fetch('http://metadata.google.internal/computeMetadata/v1/project/project-id', {
        headers: { 'Metadata-Flavor': 'Google' },
        signal: ctrlProj.signal,
      });
      clearTimeout(tProj);
      cachedMetadataProjectId = projRes.ok ? (await projRes.text()).trim() : null;
    }

    if (cachedMetadataProjectId === projectId) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 1800);
      const metaRes = await fetch(
        'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
        {
          headers: { 'Metadata-Flavor': 'Google' },
          signal: controller.signal,
        }
      );
      clearTimeout(timeout);
      if (metaRes.ok) {
        const metaData: any = await metaRes.json();
        if (metaData.access_token) {
          cachedAccessToken = metaData.access_token;
          cachedTokenExpiry = now + (Number(metaData.expires_in) || 1800) * 1000;
          return cachedAccessToken;
        }
      }
    }
  } catch {
    cachedMetadataProjectId = null;
  }

  if (!loggedMissingCredsWarning) {
    loggedMissingCredsWarning = true;
    console.warn(
      `[FCM] Server FCM HTTP v1 credentials are not configured for Firebase project "${projectId}". ` +
        `Set FIREBASE_SERVICE_ACCOUNT_KEY to a valid Service Account JSON from "${projectId}" to enable killed-app FCM pushes.`
    );
  }

  return null;
}

// ==========================================
// 3. DEDUPLICATION & ACTUAL PUSH SENDING
// ==========================================

const recentSentPushKeys = new Map<string, number>();

function isAlreadySentRecently(dedupKey: string): boolean {
  const now = Date.now();
  if (recentSentPushKeys.size > 500) {
    for (const [k, ts] of recentSentPushKeys.entries()) {
      if (now - ts > 120_000) recentSentPushKeys.delete(k);
    }
  }
  const prev = recentSentPushKeys.get(dedupKey);
  if (prev && now - prev < 60_000) return true;
  recentSentPushKeys.set(dedupKey, now);
  return false;
}

export interface ChatPushPayload {
  title: string;
  body: string;
  chatType: 'channel' | 'private';
  channelId?: string;
  partnerId?: number;
  messageId?: string;
  senderName?: string;
  senderId?: number;
}

async function sendSingleFcmV1(
  accessToken: string,
  targetToken: string,
  recipientUserId: number,
  payload: ChatPushPayload
): Promise<{ ok: boolean; invalidToken?: boolean; error?: string }> {
  const url = `https://fcm.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/messages:send`;
  const channelIdAndroid = payload.chatType === 'private' ? 'sami_private_messages_v2' : 'sami_channel_messages_v2';
  const tagKey = payload.messageId || `${payload.chatType}_${payload.channelId || payload.partnerId || 'msg'}`;

  const dataMap: Record<string, string> = {
    title: payload.title,
    body: payload.body,
    chatType: payload.chatType,
    channelId: payload.channelId || '',
    partnerId: payload.partnerId ? String(payload.partnerId) : '',
    recipientUserId: String(recipientUserId),
    messageId: payload.messageId || '',
    senderName: payload.senderName || 'Sami',
    senderId: payload.senderId ? String(payload.senderId) : '',
  };

  // Send BOTH notification + data with high priority so Android OS wakes app when killed/swiped
  // AND delivers to SamiFirebaseMessagingService in foreground.
  // For private messages, redact lockscreen notification body if sensitive while keeping full data payload for authorized unlocked session.
  const osNotificationBody =
    payload.chatType === 'private' ? 'لديك رسالة خاصة جديدة — افتح التطبيق لعرضها' : payload.body;

  const messageBody = {
    message: {
      token: targetToken,
      notification: {
        title: payload.title,
        body: osNotificationBody,
      },
      data: dataMap,
      android: {
        priority: 'HIGH',
        ttl: '86400s',
        collapse_key: tagKey.slice(0, 64),
        notification: {
          channel_id: channelIdAndroid,
          sound: 'default',
          default_vibrate_timings: true,
          notification_priority: 'PRIORITY_HIGH',
          visibility: payload.chatType === 'private' ? 'PRIVATE' : 'PUBLIC',
          tag: tagKey.slice(0, 64),
          click_action: 'OPEN_SAMI_CHAT',
        },
      },
    },
  };

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(messageBody),
  });

  if (res.ok) {
    return { ok: true };
  }

  const errText = await res.text().catch(() => '');
  const isInvalid =
    res.status === 404 ||
    errText.includes('UNREGISTERED') ||
    errText.includes('INVALID_ARGUMENT') ||
    errText.includes('registration-token-not-registered');

  return { ok: false, invalidToken: isInvalid, error: `${res.status}: ${errText.slice(0, 180)}` };
}

export async function sendNotificationToUsers(
  targetUserIds: number[],
  payload: ChatPushPayload
): Promise<{ sentCount: number; failedCount: number; credentialsConfigured: boolean }> {
  const recipients = await getTokensForUsers(targetUserIds, payload.senderId);
  if (recipients.length === 0) {
    return { sentCount: 0, failedCount: 0, credentialsConfigured: hasServerFcmCredentials().configured };
  }

  const accessToken = await getGoogleOAuth2AccessToken();
  if (!accessToken) {
    return { sentCount: 0, failedCount: recipients.length, credentialsConfigured: false };
  }

  let sentCount = 0;
  let failedCount = 0;

  await Promise.allSettled(
    recipients.map(async ({ token, userId }) => {
      const dedupKey = `${payload.messageId || `${payload.title}_${payload.body}`}::${token}`;
      if (payload.messageId && isAlreadySentRecently(dedupKey)) {
        return;
      }

      const result = await sendSingleFcmV1(accessToken, token, userId, payload);
      if (result.ok) {
        sentCount++;
      } else {
        failedCount++;
        if (result.invalidToken) {
          await pruneInvalidToken(token);
        } else if (result.error) {
          console.warn('[FCM] Push delivery error:', result.error);
        }
      }
    })
  );

  return { sentCount, failedCount, credentialsConfigured: true };
}

// ==========================================
// 4. AUTHORIZED MESSAGE PUSH DISPATCHER
// ==========================================

export async function dispatchAuthorizedChatPush(params: {
  senderId: number;
  senderName: string;
  senderRole: string;
  chatType: 'channel' | 'private';
  channelId?: string;
  receiverId?: number;
  messageId: string;
  snippet: string;
}): Promise<{ sentCount: number; failedCount: number; credentialsConfigured: boolean }> {
  const { senderId, senderName, senderRole, chatType, channelId, receiverId, messageId, snippet } = params;

  if (chatType === 'private') {
    if (!receiverId || receiverId <= 0 || receiverId === senderId) {
      return { sentCount: 0, failedCount: 0, credentialsConfigured: hasServerFcmCredentials().configured };
    }
    const title = senderId === 1 ? '👑 رسالة خاصة من القائد Sami' : `💬 رسالة خاصة من ${senderName}`;
    const body = snippet && snippet.trim() ? snippet.trim().slice(0, 100) : 'لديك رسالة خاصة جديدة';
    return sendNotificationToUsers([receiverId], {
      title,
      body,
      chatType: 'private',
      partnerId: senderId,
      messageId,
      senderName,
      senderId,
    });
  }

  if (!channelId) {
    return { sentCount: 0, failedCount: 0, credentialsConfigured: hasServerFcmCredentials().configured };
  }

  const channel = await getChannelById(channelId);
  if (!channel) {
    return { sentCount: 0, failedCount: 0, credentialsConfigured: hasServerFcmCredentials().configured };
  }

  const openPublic = isChannelOpenPublic(channel);
  const authorizedMembers = Array.from(
    new Set([...(channel.allowedMemberIds || []), ...(channel.memberIds || []), 1])
  ).filter((id) => id > 0);

  if (!openPublic && senderRole !== 'owner' && senderId !== 1 && !authorizedMembers.includes(senderId)) {
    return { sentCount: 0, failedCount: 0, credentialsConfigured: hasServerFcmCredentials().configured };
  }

  let recipientIds: number[] = [];
  if (channel.visibility === 'hidden' || !openPublic) {
    // Strictly send ONLY to authorized members of hidden / password-protected / private channels
    recipientIds = authorizedMembers;
  } else {
    // Open public channel: send to registered users + joined members
    const allUsers = await getAllUsersList();
    recipientIds = Array.from(new Set([...allUsers.map((u) => u.id), ...authorizedMembers]));
  }

  const senderPrefix =
    senderRole === 'owner' || senderId === 1
      ? '👑 القائد Sami'
      : senderRole === 'moderator'
        ? `🛡️ المشرف ${senderName}`
        : senderName;

  return sendNotificationToUsers(recipientIds, {
    title: `${senderPrefix} • ${channel.name}`,
    body: snippet && snippet.trim() ? snippet.trim().slice(0, 100) : 'رسالة جديدة في القناة',
    chatType: 'channel',
    channelId: channel.id,
    messageId,
    senderName,
    senderId,
  });
}

// ==========================================
// 5. BACKGROUND OUTBOX WORKER (POLLS community_notifications WHERE fcmStatus == 'pending')
// ==========================================

let outboxPollingActive = false;

async function updateOutboxDocStatus(docName: string, status: string): Promise<void> {
  await fetch(
    `https://firestore.googleapis.com/v1/${docName}?updateMask.fieldPaths=fcmStatus&updateMask.fieldPaths=fcmProcessedAt`,
    {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        fields: {
          fcmStatus: { stringValue: status },
          fcmProcessedAt: { integerValue: String(Date.now()) },
        },
      }),
    }
  ).catch(() => {});
}

async function pollPendingFcmOutbox(): Promise<void> {
  if (outboxPollingActive) return;
  outboxPollingActive = true;
  try {
    // Trigger ADC check once on first poll so hasServerFcmCredentials() knows if GCE ADC matches projectId
    const accessToken = await getGoogleOAuth2AccessToken();
    if (!accessToken) {
      return;
    }

    const res = await fetch(`${getFirestoreBaseUrl()}:runQuery`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        structuredQuery: {
          from: [{ collectionId: SHARED_NOTIF_COLLECTION }],
          where: {
            fieldFilter: {
              field: { fieldPath: 'fcmStatus' },
              op: 'EQUAL',
              value: { stringValue: 'pending' },
            },
          },
          limit: 15,
        },
      }),
    });
    if (!res.ok) return;
    const rows: any[] = await res.json();
    if (!Array.isArray(rows)) return;

    const now = Date.now();
    for (const row of rows) {
      const doc = row?.document;
      const f = doc?.fields;
      if (!doc?.name || !f) continue;

      const notifType = f.type?.stringValue || '';
      if (notifType === 'fcm_device_token') continue;

      const jobId = f.id?.stringValue || String(doc.name).split('/').pop() || '';
      const createdAt = Number(f.timestamp?.integerValue || f.createdAt?.integerValue || 0);
      if (createdAt > 0 && now - createdAt > 15 * 60 * 1000) {
        await updateOutboxDocStatus(doc.name, 'expired');
        continue;
      }

      const senderId = Number(f.senderId?.integerValue || 0);
      const senderName = String(f.senderName?.stringValue || 'Sami');
      const senderRole = String(f.senderRole?.stringValue || (senderId === 1 ? 'owner' : 'user'));
      const chatType =
        f.chatType?.stringValue === 'private' || notifType === 'private_message' ? 'private' : 'channel';
      const channelId = f.channelId?.stringValue || undefined;
      const partnerId = Number(f.partnerId?.integerValue || f.privateChatWithUserId?.integerValue || 0);
      const messageId = f.messageId?.stringValue || jobId;
      const bodyText = String(f.body?.stringValue || 'رسالة جديدة');
      const targetUserIds: number[] = Array.isArray(f.targetUserIds?.arrayValue?.values)
        ? f.targetUserIds.arrayValue.values
            .map((v: any) => Number(v.integerValue || 0))
            .filter((n: number) => n > 0)
        : [];

      const receiverId = chatType === 'private' ? targetUserIds[0] : undefined;

      await updateOutboxDocStatus(doc.name, 'processing');

      const dispatchRes = await dispatchAuthorizedChatPush({
        senderId,
        senderName,
        senderRole,
        chatType,
        channelId,
        receiverId: receiverId || (partnerId && partnerId !== senderId ? partnerId : undefined),
        messageId,
        snippet: bodyText,
      });

      const finalStatus =
        dispatchRes.sentCount > 0
          ? 'sent'
          : dispatchRes.failedCount > 0
            ? 'failed'
            : 'no_registered_devices';
      await updateOutboxDocStatus(doc.name, finalStatus);
    }
  } catch {
    // Ignore transient network errors
  } finally {
    outboxPollingActive = false;
  }
}

setInterval(() => {
  pollPendingFcmOutbox().catch(() => {});
}, 5000);
