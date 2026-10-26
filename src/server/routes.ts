import { Router } from 'express';
import {
  getUserByUsername,
  getUserById,
  createUserRecord,
  getAllUsersList,
  getUsersCount,
  getChannelsForUser,
  getChannelById,
  getChannelMessages,
  saveChannelMessage,
  getUserChallenge,
  saveUserChallenge,
  getUserTrades,
  addTradeRecord,
  testFirestoreConnection,
  verifyUserPassword,
  projectId,
  databaseId,
  saveChannelRecord,
  updateChannelMembers,
  isChannelOpenPublic,
  joinChannelWithAccessCheck,
  getUserConversationsList,
  getPrivateMessagesList,
  savePrivateMessageRecord,
  saveFullChallengeAndTrades,
  getLatestAppUpdate,
  saveAppUpdateRecord,
  getAppUpdatesHistory,
  toggleAppUpdateVisibility,
} from './db.ts';
import { authenticateToken, requireAuth, requireRole, generateToken, verifyToken } from './auth.ts';
import { saveFile, getFile } from './storage.ts';
import {
  registerDeviceToken,
  unregisterDeviceToken,
  sendNotificationToUsers,
  dispatchAuthorizedChatPush,
  hasServerFcmCredentials,
} from './fcm.ts';

export const apiRouter = Router();

// Apply auth token parser to all API routes
apiRouter.use(authenticateToken);

// ==========================================
// 1. HEALTH & DATABASE STATUS (REAL DIAGNOSTICS)
// ==========================================

apiRouter.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'sami-fullstack-server',
    uptime: process.uptime(),
    timestamp: Date.now(),
  });
});

apiRouter.get('/database/status', async (req, res) => {
  const dbStatus = await testFirestoreConnection();
  res.json({
    appName: 'Sami',
    version: '1.3.0',
    platform: 'Google Cloud Node.js Runtime',
    firestore: {
      projectId: dbStatus.projectId,
      databaseId: dbStatus.databaseId,
      isConnected: dbStatus.connected,
      error: dbStatus.error || null,
      errorType: dbStatus.errorType || null,
    },
    storage: {
      targetBucket: `${projectId}-media`,
      freeTierEligible: true,
      freeTierQuota: '5GB standard storage / month',
    },
    auth: {
      jwtMode: process.env.JWT_SECRET ? 'Environment Configured' : 'Ephemeral Secure Generated',
    },
    fcm: hasServerFcmCredentials(),
    serverUptimeSeconds: Math.floor(process.uptime()),
  });
});

apiRouter.get('/config', (req, res) => {
  res.json({
    appName: 'Sami',
    version: '1.3.0',
    platform: 'google-cloud-run',
    database: `Cloud Firestore (${databaseId})`,
    storage: 'Google Cloud Storage',
    costTier: 'Free Tier Optimized',
    features: {
      audioMessaging: true,
      fileAttachments: true,
      privateChannels: true,
      tradingChallenge: true,
    },
  });
});

// ==========================================
// 2. AUTHENTICATION & USERS
// ==========================================

apiRouter.post('/auth/register', async (req, res) => {
  try {
    const { username, displayName, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'اسم المستخدم وكلمة المرور مطلوبان' });
    }

    if (String(password).length < 6) {
      return res.status(400).json({ error: 'كلمة المرور يجب أن لا تقل عن 6 أحرف أو أرقام' });
    }

    const cleanUser = String(username).trim();
    const existing = await getUserByUsername(cleanUser);

    if (existing) {
      return res.status(400).json({ error: 'اسم المستخدم مسجل مسبقاً، يرجى اختيار اسم آخر' });
    }

    const userCount = await getUsersCount();
    // Zero-Trust Bootstrap: First registered user becomes Owner
    const role = userCount === 0 ? 'owner' : 'user';

    const newUser = await createUserRecord({
      username: cleanUser,
      displayName: String(displayName || cleanUser).trim(),
      password: String(password),
      role,
    });

    const token = generateToken({
      id: newUser.id,
      username: newUser.username,
      displayName: newUser.displayName,
      role: newUser.role,
      avatarUrl: newUser.avatarUrl,
      isGuest: false,
    });

    res.json({
      success: true,
      token,
      user: {
        id: newUser.id,
        username: newUser.username,
        displayName: newUser.displayName,
        role: newUser.role,
        avatarUrl: newUser.avatarUrl,
      },
    });
  } catch (err: any) {
    res.status(500).json({ error: 'حدث خطأ أثناء التسجيل: ' + (err?.message || err) });
  }
});

apiRouter.post('/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'يرجى إدخال اسم المستخدم وكلمة المرور' });
    }

    const user = await getUserByUsername(String(username).trim());
    if (!user) {
      return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
    }

    const valid = verifyUserPassword(String(password), user.passwordHash, user.salt);
    if (!valid) {
      return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
    }

    const token = generateToken({
      id: user.id,
      username: user.username,
      displayName: user.displayName,
      role: user.role,
      avatarUrl: user.avatarUrl,
      isGuest: false,
    });

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        username: user.username,
        displayName: user.displayName,
        role: user.role,
        avatarUrl: user.avatarUrl,
      },
    });
  } catch (err: any) {
    res.status(500).json({ error: 'حدث خطأ أثناء تسجيل الدخول: ' + (err?.message || err) });
  }
});

apiRouter.post('/auth/guest', (req, res) => {
  const guestName = req.body.guestName?.trim() || `ضيف_${Math.floor(Math.random() * 9000 + 1000)}`;
  const guestId = Math.floor(Date.now() / 1000);

  const token = generateToken({
    id: guestId,
    username: `guest_${guestId}`,
    displayName: guestName,
    role: 'guest',
    avatarUrl: null,
    isGuest: true,
  });

  res.json({
    success: true,
    token,
    user: {
      id: guestId,
      username: `guest_${guestId}`,
      displayName: guestName,
      role: 'guest',
      isGuest: true,
    },
  });
});

apiRouter.post('/auth/session-token', async (req, res) => {
  try {
    const { userId, username } = req.body;
    if (!userId) {
      return res.status(400).json({ error: 'Missing userId' });
    }
    const dbUser = await getUserById(Number(userId));
    if (!dbUser || (username && dbUser.username.toLowerCase() !== String(username).toLowerCase())) {
      return res.status(401).json({ error: 'جلسة المستخدم غير صالحة' });
    }
    const token = generateToken({
      id: dbUser.id,
      username: dbUser.username,
      displayName: dbUser.displayName,
      role: dbUser.role,
      avatarUrl: dbUser.avatarUrl,
      isGuest: false,
    });
    res.json({
      success: true,
      token,
      user: {
        id: dbUser.id,
        username: dbUser.username,
        displayName: dbUser.displayName,
        role: dbUser.role,
        avatarUrl: dbUser.avatarUrl,
      },
    });
  } catch (err: any) {
    res.status(500).json({ error: err?.message || 'فشل توليد رمز الدخول' });
  }
});

apiRouter.get('/auth/me', requireAuth, async (req, res) => {
  const user = await getUserById(req.user!.id);
  if (!user && !req.user!.isGuest) {
    return res.status(404).json({ error: 'المستخدم غير موجود' });
  }

  res.json({
    success: true,
    user: user
      ? {
          id: user.id,
          username: user.username,
          displayName: user.displayName,
          role: user.role,
          avatarUrl: user.avatarUrl,
          warningsCount: user.warningsCount,
        }
      : req.user,
  });
});

apiRouter.get('/users', requireAuth, async (req, res) => {
  const users = await getAllUsersList();
  res.json({ success: true, users });
});

// ==========================================
// 3. CHANNELS & PERMISSIONS (RBAC)
// ==========================================

apiRouter.get('/channels', requireAuth, async (req, res) => {
  const user = req.user!;
  const channels = await getChannelsForUser(user.id, user.role);
  res.json({ success: true, channels });
});

apiRouter.get('/channels/:id', requireAuth, async (req, res) => {
  const channelId = req.params.id;
  const user = req.user!;
  const channel = await getChannelById(channelId);

  if (!channel) {
    return res.status(404).json({ error: 'القناة غير موجودة' });
  }

  // Enforce zero-trust access:
  if (channel.visibility === 'hidden' && user.role !== 'owner') {
    const isAllowed = channel.allowedMemberIds?.includes(user.id) || channel.memberIds?.includes(user.id);
    if (!isAllowed) {
      return res.status(403).json({ error: 'ليس لديك صلاحية للوصول إلى هذه القناة الخاصة' });
    }
  }

  res.json({ success: true, channel });
});

apiRouter.post('/channels', requireAuth, requireRole('owner'), async (req, res) => {
  try {
    const { id, name, description, visibility, isPrivate, isOpenPublic, password, allowedMemberIds, memberIds, displayMemberCount } = req.body;
    if (!name) {
      return res.status(400).json({ error: 'اسم القناة مطلوب' });
    }
    const channelId = id ? String(id).trim() : `chan_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    let parsedCount: number | null = null;
    if (displayMemberCount !== undefined && displayMemberCount !== null && displayMemberCount !== '') {
      const parsed = parseInt(String(displayMemberCount).trim(), 10);
      if (!isNaN(parsed) && parsed >= 0) parsedCount = parsed;
    }

    const isHidden = visibility === 'hidden';
    const cleanPassword = !isHidden && isOpenPublic ? '' : String(password || '').trim();
    const openPublicFlag = !isHidden && (isOpenPublic === true || (!isPrivate && !cleanPassword && isOpenPublic !== false));
    const seedMembers = Array.isArray(memberIds)
      ? memberIds
      : Array.isArray(allowedMemberIds)
        ? allowedMemberIds
        : [];
    const normalizedMembers = Array.from(new Set([1, req.user!.id, ...seedMembers.map(Number).filter((n) => n > 0)]));

    const newChan = {
      id: channelId,
      name: String(name).trim(),
      description: String(description || '').trim(),
      password: cleanPassword,
      isOpenPublic: openPublicFlag,
      isPrivate: isHidden || (!openPublicFlag && (Boolean(isPrivate) || cleanPassword.length > 0)),
      visibility: isHidden ? ('hidden' as const) : ('public' as const),
      allowedMemberIds: normalizedMembers,
      memberIds: normalizedMembers,
      createdAt: Date.now(),
      updatedAt: Date.now(),
      displayMemberCount: parsedCount,
    };
    await saveChannelRecord(newChan);
    res.json({ success: true, channel: newChan });
  } catch (err: any) {
    res.status(500).json({ error: 'فشل إنشاء القناة: ' + (err?.message || err) });
  }
});

apiRouter.put('/channels/:id', requireAuth, requireRole('owner'), async (req, res) => {
  try {
    let channel = await getChannelById(req.params.id);
    if (!channel) {
      // Create mirror record if channel existed only in client Firestore previously
      channel = {
        id: req.params.id,
        name: String(req.body.name || 'قناة تداول').trim(),
        description: String(req.body.description || '').trim(),
        isPrivate: false,
        visibility: 'public',
        allowedMemberIds: [1],
        memberIds: [1],
        createdAt: Date.now(),
      };
    }
    const { name, description, visibility, isPrivate, isOpenPublic, password, allowedMemberIds, memberIds, displayMemberCount } = req.body;
    if (name) channel.name = String(name).trim();
    if (description !== undefined) channel.description = String(description).trim();
    if (visibility) channel.visibility = visibility === 'hidden' ? 'hidden' : 'public';

    if (channel.visibility === 'hidden') {
      channel.isOpenPublic = false;
      channel.isPrivate = true;
      if (password !== undefined) channel.password = String(password).trim();
    } else if (isOpenPublic !== undefined) {
      channel.isOpenPublic = Boolean(isOpenPublic);
      if (channel.isOpenPublic) {
        channel.password = '';
        channel.isPrivate = false;
      } else {
        if (password !== undefined) channel.password = String(password).trim();
        channel.isPrivate = isPrivate !== undefined ? Boolean(isPrivate) : Boolean(channel.password);
      }
    } else {
      if (password !== undefined) channel.password = String(password).trim();
      if (isPrivate !== undefined) channel.isPrivate = !!isPrivate;
    }

    if (displayMemberCount !== undefined) {
      if (displayMemberCount === null || displayMemberCount === '') {
        channel.displayMemberCount = null;
      } else {
        const parsed = parseInt(String(displayMemberCount).trim(), 10);
        channel.displayMemberCount = !isNaN(parsed) && parsed >= 0 ? parsed : null;
      }
    }
    const incomingMembers = Array.isArray(memberIds) ? memberIds : Array.isArray(allowedMemberIds) ? allowedMemberIds : null;
    if (incomingMembers) {
      channel.allowedMemberIds = Array.from(new Set([1, ...incomingMembers.map(Number).filter((n) => n > 0)]));
      channel.memberIds = channel.allowedMemberIds;
    }
    channel.updatedAt = Date.now();
    await saveChannelRecord(channel);
    res.json({ success: true, channel });
  } catch (err: any) {
    res.status(500).json({ error: 'فشل تحديث القناة: ' + (err?.message || err) });
  }
});

apiRouter.post('/channels/:id/join', requireAuth, async (req, res) => {
  try {
    const user = req.user!;
    const password = typeof req.body?.password === 'string' ? req.body.password : undefined;
    const { channel } = await joinChannelWithAccessCheck({
      channelId: req.params.id,
      userId: user.id,
      userRole: user.role,
      isGuest: user.isGuest,
      password,
    });
    res.json({ success: true, channel });
  } catch (err: any) {
    res.status(403).json({ error: err?.message || 'تعذر الانضمام إلى القناة' });
  }
});

apiRouter.post('/channels/:id/members', requireAuth, requireRole('owner'), async (req, res) => {
  try {
    const { memberIds } = req.body;
    if (!Array.isArray(memberIds)) {
      return res.status(400).json({ error: 'قائمة الأعضاء غير صحيحة' });
    }
    const updated = await updateChannelMembers(req.params.id, memberIds);
    if (!updated) {
      return res.status(404).json({ error: 'القناة غير موجودة' });
    }
    res.json({ success: true, channel: updated });
  } catch (err: any) {
    res.status(500).json({ error: 'فشل تحديث أعضاء القناة: ' + (err?.message || err) });
  }
});

// ==========================================
// 4. MESSAGES (PERSISTENT IN FIRESTORE/DISK)
// ==========================================

apiRouter.get('/channels/:id/messages', requireAuth, async (req, res) => {
  const channelId = req.params.id;
  const user = req.user!;
  const channel = await getChannelById(channelId);

  if (!channel) {
    return res.status(404).json({ error: 'القناة غير موجودة' });
  }

  const openPublic = isChannelOpenPublic(channel);
  if (!openPublic && user.role !== 'owner') {
    if (user.isGuest || user.role === 'guest') {
      return res.status(403).json({ error: 'هذه القناة متاحة للأعضاء المصرح لهم فقط' });
    }
    const isAllowed = channel.allowedMemberIds?.includes(user.id) || channel.memberIds?.includes(user.id);
    if (!isAllowed) {
      return res.status(403).json({ error: 'غير مصرح لك بعرض رسائل هذه القناة' });
    }
  }

  const limitCount = parseInt(req.query.limit as string, 10) || 80;
  const messages = await getChannelMessages(channelId, limitCount);
  res.json({ success: true, messages });
});

apiRouter.post('/channels/:id/messages', requireAuth, async (req, res) => {
  try {
    const channelId = req.params.id;
    const user = req.user!;
    const channel = await getChannelById(channelId);

    if (!channel) {
      return res.status(404).json({ error: 'القناة غير موجودة' });
    }

    const openPublic = isChannelOpenPublic(channel);
    if (!openPublic && user.role !== 'owner') {
      if (user.isGuest || user.role === 'guest') {
        return res.status(403).json({ error: 'غير مصرح للضيوف بالإرسال في القنوات المحمية أو الخاصة' });
      }
      const isAllowed = channel.allowedMemberIds?.includes(user.id) || channel.memberIds?.includes(user.id);
      if (!isAllowed) {
        return res.status(403).json({ error: 'غير مصرح لك بالإرسال في هذه القناة' });
      }
    }

    const { text, fileUrl, fileName, fileSize, fileType, audioUrl, audioDuration, storagePath, replyToId } = req.body;

    if (!text && !fileUrl && !audioUrl) {
      return res.status(400).json({ error: 'محتوى الرسالة مطلوب' });
    }

    const isLocalPath = (u: unknown) =>
      typeof u === 'string' && /^(blob:|file:|content:|filesystem:)/i.test(u.trim());
    if (isLocalPath(audioUrl) || isLocalPath(fileUrl)) {
      return res.status(400).json({ error: 'لا يمكن حفظ مسار صوتي محلي غير مرفوع إلى السحابة' });
    }

    const now = Date.now();
    const messageId = `msg_${now}_${user.id}_${Math.random().toString(36).substring(2, 7)}`;
    // Ensure guests never acquire elevated roles
    const safeRole = user.isGuest || user.role === 'guest' ? 'guest' : user.role;

    const newMsg = {
      id: messageId,
      channelId,
      senderId: user.id,
      senderName: user.displayName,
      senderRole: safeRole,
      senderAvatarUrl: user.avatarUrl || null,
      text: text ? String(text).trim() : undefined,
      fileUrl: fileUrl || undefined,
      fileName: fileName || undefined,
      fileSize: fileSize || undefined,
      fileType: fileType || undefined,
      storagePath: storagePath || undefined,
      audioUrl: audioUrl || undefined,
      audioDuration: audioDuration ? Number(audioDuration) : undefined,
      replyToId: replyToId || null,
      isDeleted: false,
      timestamp: now,
    };

    await saveChannelMessage(newMsg);

    const snippet = text
      ? String(text).trim().slice(0, 100)
      : audioUrl
        ? '🎤 رسالة صوتية'
        : fileName
          ? `📎 مرفق ملف: ${fileName}`
          : 'رسالة جديدة';

    dispatchAuthorizedChatPush({
      senderId: user.id,
      senderName: user.displayName,
      senderRole: safeRole,
      chatType: 'channel',
      channelId: channel.id,
      messageId: newMsg.id,
      snippet,
    }).catch((e) => console.warn('[FCM] Notification dispatch notice:', e));

    res.json({ success: true, message: newMsg });
  } catch (err: any) {
    res.status(500).json({ error: 'فشل إرسال الرسالة: ' + (err?.message || err) });
  }
});

// ==========================================
// 5. TRADING CHALLENGE & 150 MILESTONES
// ==========================================

apiRouter.get('/challenge', requireAuth, async (req, res) => {
  const user = req.user!;
  const challenge = await getUserChallenge(user.id, user.displayName);
  res.json({ success: true, challenge });
});

apiRouter.post('/challenge/reset', requireAuth, async (req, res) => {
  const user = req.user!;
  const initialCapitalCents = parseInt(req.body.initialCapitalCents, 10) || 10000;

  const challenge = await getUserChallenge(user.id, user.displayName);
  challenge.initialCapitalCents = initialCapitalCents;
  challenge.currentBalanceCents = initialCapitalCents;
  challenge.tradeCount = 0;
  challenge.challengeStarted = false;
  challenge.updatedAt = Date.now();

  await saveUserChallenge(challenge);
  res.json({ success: true, challenge });
});

apiRouter.get('/challenge/trades', requireAuth, async (req, res) => {
  const user = req.user!;
  const trades = await getUserTrades(user.id);
  res.json({ success: true, trades });
});

apiRouter.post('/challenge/trades', requireAuth, async (req, res) => {
  try {
    const user = req.user!;
    const { resultCents, type, attachmentPath } = req.body;

    const parsedResult = parseInt(resultCents, 10);
    if (isNaN(parsedResult)) {
      return res.status(400).json({ error: 'قيمة الصفقة غير صحيحة' });
    }

    const challenge = await getUserChallenge(user.id, user.displayName);
    const oldBalance = challenge.currentBalanceCents;
    const newBalance = oldBalance + parsedResult;
    const newTradeCount = challenge.tradeCount + 1;

    challenge.currentBalanceCents = newBalance;
    challenge.tradeCount = newTradeCount;
    challenge.challengeStarted = true;
    challenge.updatedAt = Date.now();

    const now = Date.now();
    const newTrade = {
      id: `trade_${now}_${user.id}_${newTradeCount}`,
      challengeId: challenge.id,
      userId: user.id,
      tradeNumber: newTradeCount,
      resultCents: parsedResult,
      oldBalanceCents: oldBalance,
      newBalanceCents: newBalance,
      type: type === 'LOSS' || parsedResult < 0 ? ('LOSS' as const) : ('WIN' as const),
      attachmentPath: attachmentPath || null,
      timestamp: now,
    };

    await addTradeRecord(user.id, newTrade, challenge);

    res.json({
      success: true,
      trade: newTrade,
      challenge,
    });
  } catch (err: any) {
    res.status(500).json({ error: 'فشل تسجيل الصفقة: ' + (err?.message || err) });
  }
});

// ==========================================
// 6. FILE ATTACHMENTS & UPLOADS
// ==========================================

apiRouter.post('/files/upload', requireAuth, async (req, res) => {
  try {
    const rawFileName = req.body.fileName || req.body.filename;
    const rawFileData = req.body.fileData || req.body.data;
    const mimeType = req.body.mimeType || 'application/octet-stream';
    const folder = req.body.folder || 'chat_files';
    const channelId = req.body.channelId ? String(req.body.channelId) : undefined;
    const receiverId = req.body.receiverId ? parseInt(req.body.receiverId, 10) : undefined;

    if (!rawFileName || !rawFileData) {
      return res.status(400).json({ error: 'الملف وبياناته مطلوبة' });
    }

    const fileName = String(rawFileName);
    const fileData = String(rawFileData);

    const base64Content = fileData.includes('base64,') ? fileData.split('base64,')[1] : fileData;
    const buffer = Buffer.from(base64Content, 'base64');

    if (buffer.length > 26214400) {
      return res.status(400).json({ error: 'حجم الملف يتجاوز الحد الأقصى المسموح (25 ميغابايت)' });
    }

    const targetFolder = ['chat_images', 'chat_files', 'chat_audio', 'avatars'].includes(folder)
      ? (folder as any)
      : 'chat_files';

    const saved = await saveFile(
      String(fileName),
      buffer,
      String(mimeType || 'application/octet-stream'),
      req.user!.id,
      targetFolder,
      {
        channelId,
        receiverId,
        participantIds: receiverId ? [req.user!.id, receiverId] : undefined,
      }
    );

    res.json({
      success: true,
      fileUrl: saved.fileUrl,
      fileName: saved.fileName,
      fileSize: saved.fileSize,
      fileType: saved.fileType,
      storagePath: saved.storagePath,
      isCloudStorage: saved.isCloudStorage,
    });
  } catch (err: any) {
    res.status(500).json({ error: 'فشل رفع الملف: ' + (err?.message || err) });
  }
});

apiRouter.get('/files/:id', async (req, res) => {
  const fileId = req.params.id;
  const result = await getFile(fileId);

  if (!result) {
    return res.status(404).send('File not found');
  }

  // Security check: Public avatars/branding are globally accessible
  const isPublic = result.file.id.startsWith('avatars_') || result.file.storagePath?.startsWith('avatars/');

  if (!isPublic) {
    let authUser = req.user;
    const authHeader = req.headers.authorization;
    if (!authUser && authHeader?.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      authUser = verifyToken(token) || undefined;
    }
    if (!authUser && req.query.token) {
      authUser = verifyToken(String(req.query.token)) || undefined;
    }

    if (!authUser && req.query.session) {
      try {
        const raw = decodeURIComponent(String(req.query.session));
        const parsed = JSON.parse(raw);
        if (parsed?.id) {
          if (parsed.isGuest || parsed.role === 'guest' || Number(parsed.id) > 9000000) {
            authUser = {
              id: Number(parsed.id),
              username: String(parsed.username || `guest_${parsed.id}`),
              displayName: String(parsed.displayName || 'ضيف'),
              role: 'guest',
              isGuest: true,
            };
          } else {
            const dbU = await getUserById(Number(parsed.id));
            if (dbU && dbU.username.toLowerCase() === String(parsed.username || '').toLowerCase()) {
              authUser = {
                id: dbU.id,
                username: dbU.username,
                displayName: dbU.displayName,
                role: dbU.role,
              };
            }
          }
        }
      } catch {}
    }

    if (!authUser) {
      return res.status(401).json({ error: 'يجب تسجيل الدخول للوصول إلى هذا المرفق الخاص' });
    }

    const isUploader = authUser.id === result.file.uploaderId;
    const isParticipant =
      (result.file.receiverId && authUser.id === result.file.receiverId) ||
      (result.file.participantIds && result.file.participantIds.includes(authUser.id));

    let hasChannelAccess = false;
    if (result.file.channelId) {
      const channel = await getChannelById(result.file.channelId);
      if (channel) {
        if (authUser.role === 'owner') hasChannelAccess = true;
        else if (isChannelOpenPublic(channel)) hasChannelAccess = true;
        else if (!authUser.isGuest && authUser.role !== 'guest') {
          hasChannelAccess = !!(channel.allowedMemberIds?.includes(authUser.id) || channel.memberIds?.includes(authUser.id));
        }
      }
    }

    const isAllowed = isUploader || isParticipant || hasChannelAccess || (authUser.role === 'owner' && !result.file.receiverId);
    if (!isAllowed) {
      return res.status(403).json({ error: 'غير مصرح لك بالوصول إلى هذا المرفق الخاص' });
    }
  }

  const totalLength = result.buffer.length;
  const contentType = result.file.fileType || 'application/octet-stream';
  res.setHeader('Content-Type', contentType);
  res.setHeader('Accept-Ranges', 'bytes');
  res.setHeader('Content-Disposition', `inline; filename="${encodeURIComponent(result.file.fileName)}"`);
  res.setHeader('Cache-Control', 'private, max-age=3600');

  const range = req.headers.range;
  if (range) {
    const parts = range.replace(/bytes=/, '').split('-');
    const start = parseInt(parts[0], 10);
    const end = parts[1] ? parseInt(parts[1], 10) : totalLength - 1;
    if (!isNaN(start) && !isNaN(end) && start >= 0 && end < totalLength && start <= end) {
      const chunkSize = end - start + 1;
      res.status(206);
      res.setHeader('Content-Range', `bytes ${start}-${end}/${totalLength}`);
      res.setHeader('Content-Length', chunkSize);
      return res.send(result.buffer.subarray(start, end + 1));
    }
  }

  res.setHeader('Content-Length', totalLength);
  res.send(result.buffer);
});

// ==========================================
// 7. PRIVATE MESSAGES & CONVERSATIONS (RBAC ENFORCED)
// ==========================================

apiRouter.get('/private-conversations', requireAuth, async (req, res) => {
  const currentUserId = req.user!.id;
  const userRole = req.user!.role;
  const conversations = await getUserConversationsList(currentUserId, userRole);
  res.json({ success: true, conversations });
});

apiRouter.get('/conversations/:id/messages', requireAuth, async (req, res) => {
  const convId = req.params.id;
  const currentUserId = req.user!.id;

  let p1: number | null = null;
  let p2: number | null = null;

  if (convId.includes('_')) {
    const parts = convId.split('_').map((p) => parseInt(p, 10)).filter((n) => !isNaN(n));
    if (parts.length >= 2) {
      p1 = parts[0];
      p2 = parts[1];
    }
  } else {
    const parsed = parseInt(convId, 10);
    if (!isNaN(parsed)) {
      p1 = currentUserId;
      p2 = parsed;
    }
  }

  if (p1 === null || p2 === null) {
    return res.status(400).json({ error: 'معرّف المحادثة غير صحيح' });
  }

  // Strict enforcement: A user can only access a conversation they participate in
  if (currentUserId !== p1 && currentUserId !== p2) {
    return res.status(403).json({ error: 'غير مصرح لك بالوصول إلى هذه المحادثة الخاصة، المحادثة مقتصرة على المشاركين فقط' });
  }

  const limitCount = parseInt(req.query.limit as string, 10) || 80;
  const messages = await getPrivateMessagesList(p1, p2, limitCount);
  res.json({ success: true, messages });
});

apiRouter.get('/private-messages', requireAuth, async (req, res) => {
  const otherUserId = parseInt(req.query.otherUserId as string, 10);
  if (!otherUserId) {
    return res.status(400).json({ error: 'معرّف الطرف الآخر مطلوب' });
  }

  const currentUserId = req.user!.id;
  if (currentUserId === otherUserId) {
    return res.status(400).json({ error: 'لا يمكن جلب محادثة مع نفسك' });
  }

  const limitCount = parseInt(req.query.limit as string, 10) || 80;
  const messages = await getPrivateMessagesList(currentUserId, otherUserId, limitCount);
  res.json({ success: true, messages });
});

apiRouter.post('/private-messages', requireAuth, async (req, res) => {
  const receiverId = parseInt(req.body.receiverId, 10);
  if (!receiverId) {
    return res.status(400).json({ error: 'معرّف المستلم مطلوب' });
  }

  const senderId = req.user!.id;
  if (senderId === receiverId) {
    return res.status(400).json({ error: 'لا يمكن إرسال رسالة خاصة إلى نفسك' });
  }

  if (req.body.conversationId) {
    const parts = String(req.body.conversationId).split('_').map((p) => parseInt(p, 10));
    if (parts.length === 2 && !parts.includes(senderId)) {
      return res.status(403).json({ error: 'غير مصرح لك بالإرسال في هذه المحادثة الخاصة' });
    }
  }

  const { text, imageUrl, storagePath, audioUrl, audioDuration, fileUrl, fileName, fileSize, fileType } = req.body;
  if (!text && !imageUrl && !audioUrl && !fileUrl) {
    return res.status(400).json({ error: 'محتوى الرسالة مطلوب' });
  }

  const isLocalPrivatePath = (u: unknown) =>
    typeof u === 'string' && /^(blob:|file:|content:|filesystem:)/i.test(u.trim());
  if (isLocalPrivatePath(audioUrl) || isLocalPrivatePath(fileUrl) || isLocalPrivatePath(imageUrl)) {
    return res.status(400).json({ error: 'لا يمكن حفظ مسار ملف أو تسجيل صوتي محلي غير مرفوع إلى السحابة' });
  }

  const now = Date.now();
  const newMsg = {
    id: `pm_${now}_${senderId}_${Math.random().toString(36).substring(2, 7)}`,
    senderId,
    receiverId,
    senderName: req.user!.displayName,
    senderRole: req.user!.role,
    senderAvatarUrl: req.user!.avatarUrl || null,
    text: text ? String(text).trim() : undefined,
    imageUrl: imageUrl || undefined,
    storagePath: storagePath || undefined,
    audioUrl: audioUrl || undefined,
    audioDuration: audioDuration ? Number(audioDuration) : undefined,
    fileUrl: fileUrl || undefined,
    fileName: fileName || undefined,
    fileSize: fileSize ? Number(fileSize) : undefined,
    fileType: fileType || undefined,
    timestamp: now,
  };

  await savePrivateMessageRecord(newMsg);

  const snippet = text
    ? String(text).trim().slice(0, 100)
    : audioUrl
      ? '🎤 رسالة صوتية'
      : fileName
        ? `📎 مرفق ملف: ${fileName}`
        : imageUrl
          ? '📷 صورة مرفقة'
          : 'رسالة خاصة جديدة';

  dispatchAuthorizedChatPush({
    senderId,
    senderName: req.user!.displayName,
    senderRole: req.user!.role,
    chatType: 'private',
    receiverId,
    messageId: newMsg.id,
    snippet,
  }).catch((e) => console.warn('[FCM] Private message push notice:', e));

  res.json({ success: true, message: newMsg });
});

// ==========================================
// 8. CHALLENGE FULL SYNC (ANDROID API CLIENT)
// ==========================================

apiRouter.post('/challenge', requireAuth, async (req, res) => {
  try {
    const user = req.user!;
    const challengeObj = req.body.challenge;
    const tradesArr = Array.isArray(req.body.trades) ? req.body.trades : [];

    if (!challengeObj) {
      return res.status(400).json({ error: 'بيانات الرحلة مطلوبة' });
    }

    const challenge = {
      id: challengeObj.id || `challenge_${user.id}`,
      userId: user.id,
      userName: challengeObj.userName || user.displayName,
      initialCapitalCents: parseInt(challengeObj.initialCapitalCents, 10) || 10000,
      currentBalanceCents: parseInt(challengeObj.currentBalanceCents, 10) || 10000,
      targetBalanceCents: parseInt(challengeObj.targetBalanceCents, 10) || 300000,
      tradeCount: tradesArr.length,
      challengeStarted: tradesArr.length > 0,
      createdAt: challengeObj.createdAt || Date.now(),
      updatedAt: Date.now(),
    };

    await saveFullChallengeAndTrades(user.id, challenge, tradesArr);

    res.json({ success: true, challenge, tradesCount: tradesArr.length });
  } catch (err: any) {
    res.status(500).json({ error: 'فشل حفظ بيانات الرحلة: ' + (err?.message || err) });
  }
});

// ==========================================
// 9. PACKAGES
// ==========================================

apiRouter.get('/packages', (req, res) => {
  res.json([
    {
      id: 'pkg_silver',
      name: 'الباقة الفضية',
      description: 'دخول القنوات العامة ومتابعة رحلة التداول لـ 150 محطة بدقة.',
      priceDollars: 30,
      period: 'شهري',
      features: ['تتبع 150 محطة تداول', 'القناة العامة للنقاشات', 'تقارير الأداء PDF'],
    },
    {
      id: 'pkg_gold',
      name: 'الباقة الذهبية',
      description: 'دخول قناة Sami VIP الخاصة بالتوصيات والصفقات المتقدمة.',
      priceDollars: 60,
      period: 'شهري',
      features: ['جميع ميزات الباقة الفضية', 'قناة Sami VIP الخاصة', 'إشارات وتوصيات يومية مباشر'],
    },
    {
      id: 'pkg_vip_lifetime',
      name: 'باقة VIP الدائمة',
      description: 'عضوية دائمة مع كافة قنوات وتوصيات القائد Sami.',
      priceDollars: 150,
      period: 'دائم',
      features: ['عضوية VIP دائمة مدى الحياة', 'دعم خاص مباشر من Sami', 'أولوية في جميع الدورات والصفقات'],
    },
  ]);
});

// ==========================================
// 10. FCM DEVICE TOKENS MANAGEMENT
// ==========================================

apiRouter.post('/fcm/register', requireAuth, async (req, res) => {
  try {
    const { token, deviceId, platform, deviceModel } = req.body;
    if (!token) {
      return res.status(400).json({ error: 'رمز الجهاز (FCM Token) مطلوب' });
    }
    const record = await registerDeviceToken({
      token: String(token).trim(),
      userId: req.user!.id,
      username: req.user!.username,
      deviceId: deviceId ? String(deviceId) : undefined,
      platform: platform ? String(platform) : 'android',
      deviceModel: deviceModel ? String(deviceModel) : undefined,
    });
    res.json({ success: true, record });
  } catch (err: any) {
    res.status(500).json({ error: 'فشل تسجيل رمز الجهاز: ' + (err?.message || err) });
  }
});

apiRouter.post('/fcm/unregister', requireAuth, async (req, res) => {
  try {
    const { token, deviceId } = req.body;
    await unregisterDeviceToken(
      req.user!.id,
      token ? String(token) : undefined,
      deviceId ? String(deviceId) : undefined
    );
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: 'فشل إلغاء تسجيل رمز الجهاز: ' + (err?.message || err) });
  }
});

apiRouter.post('/fcm/dispatch', requireAuth, async (req, res) => {
  try {
    const user = req.user!;
    const chatType = req.body.chatType === 'private' ? 'private' : 'channel';
    const channelId = req.body.channelId ? String(req.body.channelId) : undefined;
    const receiverId = req.body.receiverId ? Number(req.body.receiverId) : undefined;
    const messageId = req.body.messageId ? String(req.body.messageId) : `msg_${Date.now()}`;
    const snippet = req.body.body
      ? String(req.body.body)
      : req.body.snippet
        ? String(req.body.snippet)
        : 'رسالة جديدة';

    const result = await dispatchAuthorizedChatPush({
      senderId: user.id,
      senderName: user.displayName,
      senderRole: user.isGuest || user.role === 'guest' ? 'guest' : user.role,
      chatType,
      channelId,
      receiverId,
      messageId,
      snippet,
    });
    res.json({ success: true, ...result });
  } catch (err: any) {
    res.status(500).json({ error: 'فشل إرسال الإشعار الخارجي: ' + (err?.message || err) });
  }
});

// ==========================================
// 11. APP UPDATES (SHARED DATABASE & RBAC)
// ==========================================

const setNoCacheHeaders = (res: any) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
};

// GET /api/app-updates - Get the latest update from the shared database
apiRouter.get('/app-updates', async (req, res) => {
  setNoCacheHeaders(res);
  try {
    const update = await getLatestAppUpdate();
    res.json({ success: true, update });
  } catch (err: any) {
    res.status(500).json({ error: 'فشل استرجاع إعدادات التحديث: ' + (err?.message || err) });
  }
});

apiRouter.get('/app-updates/latest', async (req, res) => {
  setNoCacheHeaders(res);
  try {
    const update = await getLatestAppUpdate();
    res.json({ success: true, update });
  } catch (err: any) {
    res.status(500).json({ error: 'فشل استرجاع إعدادات التحديث: ' + (err?.message || err) });
  }
});

// POST /api/app-updates - Publish update (STRICT: OWNER ONLY)
apiRouter.post('/app-updates', requireAuth, requireRole('owner'), async (req, res) => {
  setNoCacheHeaders(res);
  try {
    const { versionName, versionCode, downloadUrl, description, isMandatory, minSupportedVersionCode } = req.body;

    if (!versionName || typeof versionName !== 'string' || !versionName.trim()) {
      return res.status(400).json({ error: 'يرجى إدخال رقم الإصدار (versionName)' });
    }

    const codeNum = parseInt(versionCode, 10);
    if (isNaN(codeNum) || codeNum <= 0) {
      return res.status(400).json({ error: 'يرجى إدخال كود إصدار رقمي صحيح (versionCode)' });
    }

    if (!downloadUrl || typeof downloadUrl !== 'string' || !downloadUrl.trim()) {
      return res.status(400).json({ error: 'يرجى إدخال رابط تحميل الـ APK الصحيح' });
    }

    const savedUpdate = await saveAppUpdateRecord({
      versionName: versionName.trim(),
      versionCode: codeNum,
      downloadUrl: downloadUrl.trim(),
      description: description ? String(description).trim() : '',
      isMandatory: !!isMandatory,
      minSupportedVersionCode: minSupportedVersionCode ? parseInt(minSupportedVersionCode, 10) : undefined,
      publishedBy: req.user!.displayName || 'Sami',
    });

    // Notify registered devices about the new update
    try {
      const allUsers = await getAllUsersList();
      const recipientIds = allUsers.map((u) => u.id);
      if (recipientIds.length > 0) {
        sendNotificationToUsers(recipientIds, {
          title: isMandatory ? '⚠️ تحديث إجباري متوفر للتطبيق' : '✨ تحديث جديد متوفر للتطبيق',
          body: `الإصدار ${savedUpdate.versionName}: ${savedUpdate.description.slice(0, 100) || 'تحسينات جديدة متاحة الآن'}`,
          chatType: 'channel',
        }).catch((e) => console.warn('[FCM] App update broadcast notice:', e));
      }
    } catch (_: any) {}

    res.json({
      success: true,
      message: 'تم نشر التحديث وحفظه في قاعدة البيانات المشتركة بنجاح 🚀',
      update: savedUpdate,
    });
  } catch (err: any) {
    res.status(500).json({ error: 'فشل حفظ ونشر التحديث في قاعدة البيانات: ' + (err?.message || err) });
  }
});

// GET /api/app-updates/history - Get all past updates and their active status (STRICT: OWNER ONLY)
apiRouter.get('/app-updates/history', requireAuth, requireRole('owner'), async (req, res) => {
  setNoCacheHeaders(res);
  try {
    const updates = await getAppUpdatesHistory();
    res.json({ success: true, updates });
  } catch (err: any) {
    res.status(500).json({ error: 'فشل جلب سجل التحديثات: ' + (err?.message || err) });
  }
});

// POST /api/app-updates/toggle - Pause / resume update visibility (STRICT: OWNER ONLY)
apiRouter.post('/app-updates/toggle', requireAuth, requireRole('owner'), async (req, res) => {
  setNoCacheHeaders(res);
  try {
    if (typeof req.body?.isActive !== 'boolean') {
      return res.status(400).json({ error: 'يرجى تحديد حالة النشر المطلوبة بشكل صحيح' });
    }
    const { isActive, updateId, versionCode } = req.body;
    const target = updateId || versionCode || 'latest';
    await toggleAppUpdateVisibility(target, isActive);

    // Re-read authoritative saved state from shared database before responding
    const verified = await getLatestAppUpdate();
    if (verified.isActive !== isActive || verified.isHidden !== !isActive) {
      return res.status(500).json({ error: 'تعذر التحقق من حفظ حالة إيقاف/تفعيل التحديث في قاعدة البيانات المشتركة' });
    }

    res.json({
      success: true,
      message: isActive
        ? 'تمت إعادة إظهار التحديث ومزامنته للمستخدمين بنجاح ✅'
        : 'تم إيقاف ظهور التحديث وإخفاؤه عن جميع المستخدمين بنجاح ⏸️',
      update: verified,
    });
  } catch (err: any) {
    res.status(500).json({ error: 'فشل تغيير حالة ظهور التحديث: ' + (err?.message || err) });
  }
});



