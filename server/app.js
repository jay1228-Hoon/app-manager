const express = require('express');
const multer = require('multer');
const unzipper = require('unzipper');
const path = require('path');
const fs = require('fs-extra');
const crypto = require('crypto');
const { exec } = require('child_process');
const util = require('util');
const httpProxy = require('http-proxy');
const axios = require('axios');
const execPromise = util.promisify(exec);

const app = express();
const PORT = 3001;

// 프록시 서버 생성
const proxy = httpProxy.createProxyServer({ proxyTimeout: 180000, timeout: 180000 }); // AI 응답 대기 180초

// 프록시 에러 처리
proxy.on('error', (err, req, res) => {
  console.error('프록시 에러:', err.message);
  if (!res.headersSent) {
    res.status(502).json({ error: '백엔드 서버 연결 실패' });
  }
});

// ===== 설정 =====
const DATA_ROOT = path.join(__dirname, '..', 'data');
const CONFIG = {
  APPS_DIR: path.join(DATA_ROOT, 'apps'),
  IMAGES_DIR: path.join(DATA_ROOT, 'images'),
  DOWNLOADS_DIR: path.join(DATA_ROOT, 'downloads'),
  BACKUPS_DIR: path.join(DATA_ROOT, 'backups'),
  APP_ZIPS_DIR: path.join(DATA_ROOT, 'app-zips'),
  AUTH_FILE: path.join(DATA_ROOT, 'config', 'auth.json'),
  IP_CONFIG_FILE: path.join(DATA_ROOT, 'config', 'ip-config.json'),
  SETTINGS_FILE: path.join(DATA_ROOT, 'config', 'settings.json'),
  AI_LOG_FILE: path.join(DATA_ROOT, 'config', 'ai-usage-log.json'),
  BATCH_LOG_FILE: path.join(DATA_ROOT, 'config', 'ai-batch-log.json'),
  IMAGE_CATS_FILE: path.join(DATA_ROOT, 'config', 'image-folder-cats.json'),
  DOWNLOAD_CATS_FILE: path.join(DATA_ROOT, 'config', 'download-file-cats.json'),
  DEFAULT_USERNAME: 'admin',
  DEFAULT_PASSWORD: 'doodle99!*',
  PORT_START: 4001,
  PORT_END: 4999,
  MAX_BACKUPS_PER_APP: 5  // 앱당 최대 백업 개수
};

// ===== 헬퍼 함수들 (프록시보다 먼저 정의) =====

// 비밀번호 해시
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

// 인증 정보 로드
async function getAuthConfig() {
  try {
    if (await fs.pathExists(CONFIG.AUTH_FILE)) {
      return await fs.readJson(CONFIG.AUTH_FILE);
    }
  } catch (e) {
    console.log('인증 파일 로드 실패, 기본값 사용');
  }
  return {
    username: CONFIG.DEFAULT_USERNAME,
    passwordHash: hashPassword(CONFIG.DEFAULT_PASSWORD)
  };
}

// 인증 정보 저장
async function saveAuthConfig(authConfig) {
  await fs.ensureDir(path.dirname(CONFIG.AUTH_FILE));
  await fs.writeJson(CONFIG.AUTH_FILE, authConfig, { spaces: 2 });
}

// IP 설정 로드
async function getIpConfig() {
  try {
    if (await fs.pathExists(CONFIG.IP_CONFIG_FILE)) {
      return await fs.readJson(CONFIG.IP_CONFIG_FILE);
    }
  } catch (e) {
    console.log('IP 설정 파일 로드 실패, 기본값 사용');
  }
  return { allowedIps: [] };  // 빈 배열 = 모든 IP 허용
}

// IP 설정 저장
async function saveIpConfig(ipConfig) {
  await fs.ensureDir(path.dirname(CONFIG.IP_CONFIG_FILE));
  await fs.writeJson(CONFIG.IP_CONFIG_FILE, ipConfig, { spaces: 2 });
}

// 클라이언트 IP 추출
function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    return forwarded.split(',')[0].trim();
  }
  return req.connection?.remoteAddress || req.socket?.remoteAddress || req.ip;
}

// 세션 토큰 생성
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// 세션 저장소
const sessions = new Map();

// IP 체크 미들웨어 (관리자 페이지만 적용)
const checkAdminIp = async (req, res, next) => {
  try {
    const ipConfig = await getIpConfig();
    
    // 허용 목록이 비어있으면 모든 IP 허용
    if (!ipConfig.allowedIps || ipConfig.allowedIps.length === 0) {
      return next();
    }
    
    const clientIp = getClientIp(req);
    
    // IPv6 localhost 처리
    const normalizedIp = clientIp === '::1' ? '127.0.0.1' : clientIp.replace('::ffff:', '');
    
    if (ipConfig.allowedIps.includes(normalizedIp)) {
      return next();
    }
    
    console.log(`IP 차단: ${normalizedIp} (허용 목록: ${ipConfig.allowedIps.join(', ')})`);
    return res.status(403).json({ error: '접근이 허용되지 않은 IP입니다' });
  } catch (error) {
    console.error('IP 체크 오류:', error.message);
    next();  // 오류 시 통과 (서비스 중단 방지)
  }
};

// 인증 미들웨어

// ===== 앱명 자동 추출 헬퍼 =====
function extractAppId(req, bodyAppId) {
  // 1. body에 명시된 app_id 최우선
  if (bodyAppId) return bodyAppId;

  // 2. Referer 헤더에서 /api/apps/{appUrl} 패턴 추출
  const referer = req.headers.referer || req.headers.referrer || '';
  if (referer) {
    // 패턴: /api/apps/spark/... 또는 /apps/spark/...
    const m = referer.match(/\/api\/apps\/([^/?#]+)/i) || referer.match(/\/apps\/([^/?#]+)/i);
    if (m && m[1]) return m[1];
  }

  // 3. x-app-id 커스텀 헤더
  if (req.headers['x-app-id']) return req.headers['x-app-id'];

  // 4. Origin에서 서브패스 추출 불가 → unknown
  return 'unknown';
}

const requireAuth = (req, res, next) => {
  const token = req.headers['x-auth-token'];
  
  if (!token || !sessions.has(token)) {
    return res.status(401).json({ error: '로그인이 필요합니다' });
  }
  
  const session = sessions.get(token);
  
  if (Date.now() - session.createdAt > 24 * 60 * 60 * 1000) {
    sessions.delete(token);
    return res.status(401).json({ error: '세션이 만료되었습니다' });
  }
  
  req.user = session;
  next();
};

// PM2 명령어 실행
async function pm2Command(command) {
  try {
    const { stdout, stderr } = await execPromise(command);
    console.log(`PM2 명령 실행: ${command}`);
    if (stdout) console.log('stdout:', stdout);
    if (stderr) console.log('stderr:', stderr);
    return { success: true, stdout, stderr };
  } catch (error) {
    console.error(`PM2 명령 실패: ${command}`, error.message);
    return { success: false, error: error.message };
  }
}

// 사용 가능한 포트 찾기
async function findAvailablePort() {
  const appsConfigPath = path.join(CONFIG.APPS_DIR, 'apps.json');
  let usedPorts = [];
  
  if (await fs.pathExists(appsConfigPath)) {
    const config = await fs.readJson(appsConfigPath);
    usedPorts = config.apps
      .filter(a => a.port)
      .map(a => a.port);
  }
  
  for (let port = CONFIG.PORT_START; port <= CONFIG.PORT_END; port++) {
    if (!usedPorts.includes(port)) {
      return port;
    }
  }
  
  throw new Error('사용 가능한 포트가 없습니다');
}

// 백엔드 서버 시작
async function startBackendServer(appUrl, port) {
  const backendPath = path.join(CONFIG.APPS_DIR, appUrl, 'backend');
  const apiFile = path.join(backendPath, 'api.js');
  const packageFile = path.join(backendPath, 'package.json');
  
  if (!await fs.pathExists(apiFile)) {
    console.log(`${appUrl}: api.js 없음, 백엔드 서버 시작 안 함`);
    return { success: true, message: '백엔드 없음' };
  }
  
  if (await fs.pathExists(packageFile)) {
    console.log(`${appUrl}: npm install 실행 중...`);
    await pm2Command(`cd ${backendPath} && npm install`);
  }
  
  const pm2Name = `app-${appUrl}`;
  await pm2Command(`pm2 delete ${pm2Name} 2>/dev/null || true`);
  
  // 글로벌 설정에서 API 키 로드
  let envVars = `PORT=${port}`;
  try {
    if (await fs.pathExists(CONFIG.SETTINGS_FILE)) {
      const settings = await fs.readJson(CONFIG.SETTINGS_FILE);
      if (settings.anthropicApiKey) envVars += ` ANTHROPIC_API_KEY=${settings.anthropicApiKey}`;
    }
  } catch (e) { /* 설정 없으면 무시 */ }

  const result = await pm2Command(`${envVars} pm2 start ${apiFile} --name ${pm2Name}`);
  
  if (result.success) {
    await pm2Command('pm2 save');
    console.log(`${appUrl}: 백엔드 서버 시작됨 (${pm2Name}, 포트: ${port})`);
  }
  
  return result;
}

// 백엔드 서버 중지
async function stopBackendServer(appUrl) {
  const pm2Name = `app-${appUrl}`;
  const result = await pm2Command(`pm2 delete ${pm2Name} 2>/dev/null || true`);
  await pm2Command('pm2 save');
  console.log(`${appUrl}: 백엔드 서버 중지됨`);
  return result;
}

// 앱 정보 조회
async function getAppInfo(appUrl) {
  const appsConfigPath = path.join(CONFIG.APPS_DIR, 'apps.json');
  if (!await fs.pathExists(appsConfigPath)) return null;
  
  const config = await fs.readJson(appsConfigPath);
  return config.apps.find(a => a.url === appUrl);
}

// ===== 백업 관련 함수들 =====

// 타임스탬프 생성 (백업 폴더명용)
function getBackupTimestamp() {
  const now = new Date();
  return now.toISOString().replace(/[:.]/g, '-').slice(0, 19);
}

// 앱 백업 생성
async function createAppBackup(appUrl, reason = 'manual') {
  const appPath = path.join(CONFIG.APPS_DIR, appUrl);
  
  if (!await fs.pathExists(appPath)) {
    return { success: false, error: '앱 폴더가 없습니다' };
  }
  
  const timestamp = getBackupTimestamp();
  const backupName = `${timestamp}_${reason}`;
  const backupPath = path.join(CONFIG.BACKUPS_DIR, appUrl, backupName);
  
  try {
    await fs.ensureDir(backupPath);
    await fs.copy(appPath, path.join(backupPath, 'app'));
    
    // 앱 정보도 백업
    const appInfo = await getAppInfo(appUrl);
    if (appInfo) {
      await fs.writeJson(path.join(backupPath, 'app-info.json'), appInfo, { spaces: 2 });
    }
    
    console.log(`백업 생성: ${appUrl} → ${backupName}`);
    
    // 오래된 백업 정리
    await cleanupOldBackups(appUrl);
    
    return { success: true, backupName, backupPath };
  } catch (error) {
    console.error(`백업 실패: ${appUrl}`, error.message);
    return { success: false, error: error.message };
  }
}

// 오래된 백업 정리 (앱당 최대 개수 유지)
async function cleanupOldBackups(appUrl) {
  const appBackupDir = path.join(CONFIG.BACKUPS_DIR, appUrl);
  
  if (!await fs.pathExists(appBackupDir)) return;
  
  const backups = await fs.readdir(appBackupDir);
  
  if (backups.length > CONFIG.MAX_BACKUPS_PER_APP) {
    // 날짜순 정렬 (오래된 것부터)
    backups.sort();
    
    const toDelete = backups.slice(0, backups.length - CONFIG.MAX_BACKUPS_PER_APP);
    
    for (const backup of toDelete) {
      await fs.remove(path.join(appBackupDir, backup));
      console.log(`오래된 백업 삭제: ${appUrl}/${backup}`);
    }
  }
}

// 백업에서 복원
async function restoreAppFromBackup(appUrl, backupName) {
  const backupPath = path.join(CONFIG.BACKUPS_DIR, appUrl, backupName, 'app');
  const appPath = path.join(CONFIG.APPS_DIR, appUrl);
  
  if (!await fs.pathExists(backupPath)) {
    return { success: false, error: '백업을 찾을 수 없습니다' };
  }
  
  try {
    // 복원 전 현재 상태 백업
    await createAppBackup(appUrl, 'before-restore');
    
    // 백엔드 서버 중지
    await stopBackendServer(appUrl);
    
    // 기존 앱 삭제 후 백업에서 복원
    await fs.remove(appPath);
    await fs.copy(backupPath, appPath);
    
    // 백엔드가 있으면 다시 시작
    const appInfo = await getAppInfo(appUrl);
    if (appInfo && appInfo.hasBackend && appInfo.port) {
      await startBackendServer(appUrl, appInfo.port);
    }
    
    console.log(`복원 완료: ${appUrl} ← ${backupName}`);
    return { success: true };
  } catch (error) {
    console.error(`복원 실패: ${appUrl}`, error.message);
    return { success: false, error: error.message };
  }
}

// 백업 목록 조회
async function getBackupList(appUrl = null) {
  const backups = [];
  
  try {
    if (appUrl) {
      // 특정 앱의 백업만
      const appBackupDir = path.join(CONFIG.BACKUPS_DIR, appUrl);
      if (await fs.pathExists(appBackupDir)) {
        const items = await fs.readdir(appBackupDir);
        for (const item of items) {
          const stat = await fs.stat(path.join(appBackupDir, item));
          backups.push({
            appUrl,
            name: item,
            date: stat.mtime,
            size: await getDirSize(path.join(appBackupDir, item))
          });
        }
      }
    } else {
      // 전체 백업 목록
      if (await fs.pathExists(CONFIG.BACKUPS_DIR)) {
        const apps = await fs.readdir(CONFIG.BACKUPS_DIR);
        for (const app of apps) {
          const appBackupDir = path.join(CONFIG.BACKUPS_DIR, app);
          const stat = await fs.stat(appBackupDir);
          if (stat.isDirectory()) {
            const items = await fs.readdir(appBackupDir);
            for (const item of items) {
              const itemStat = await fs.stat(path.join(appBackupDir, item));
              backups.push({
                appUrl: app,
                name: item,
                date: itemStat.mtime,
                size: await getDirSize(path.join(appBackupDir, item))
              });
            }
          }
        }
      }
    }
    
    // 최신순 정렬
    backups.sort((a, b) => new Date(b.date) - new Date(a.date));
    
  } catch (error) {
    console.error('백업 목록 조회 실패:', error.message);
  }
  
  return backups;
}

// 디렉토리 크기 계산 (대략적)
async function getDirSize(dirPath) {
  let size = 0;
  try {
    const items = await fs.readdir(dirPath, { withFileTypes: true });
    for (const item of items) {
      const itemPath = path.join(dirPath, item.name);
      if (item.isDirectory()) {
        size += await getDirSize(itemPath);
      } else {
        const stat = await fs.stat(itemPath);
        size += stat.size;
      }
    }
  } catch (e) {}
  return size;
}

// ========================================
// ★★★ 핵심 수정: 프록시 라우트를 body parser보다 먼저 정의 ★★★
// ========================================

// ===== 나라 맞춤법 검사기 프록시 API =====
// 새 엔드포인트: https://nara-speller.co.kr/api/check (2025년 React 리뉴얼)

// 맞춤법 검사 글자 제한
const SPELLER_CHAR_LIMIT = 500;

// 정규식 특수문자 이스케이프
function escapeRegExp(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// 텍스트 분할 (글자 제한)
function splitText(text, limit) {
  const chunks = [];
  let remaining = text;
  
  while (remaining.length > 0) {
    if (remaining.length <= limit) {
      chunks.push(remaining);
      break;
    }
    let cutPoint = remaining.lastIndexOf('.', limit);
    if (cutPoint === -1 || cutPoint < limit * 0.5) {
      cutPoint = remaining.lastIndexOf(' ', limit);
    }
    if (cutPoint === -1 || cutPoint < limit * 0.5) {
      cutPoint = limit;
    }
    chunks.push(remaining.substring(0, cutPoint + 1).trim());
    remaining = remaining.substring(cutPoint + 1).trim();
  }
  return chunks;
}

// 나라 맞춤법 검사기 응답 파싱 (다양한 형식 대응)
function parseSpellerResponse(data, originalText) {
  const corrections = [];
  
  // 형식 1: { str, errInfo: [{ orgStr, candWord, help, errorType }] }
  if (data.errInfo && Array.isArray(data.errInfo)) {
    for (const err of data.errInfo) {
      const from = err.orgStr || err.errataWord || err.errata_word || '';
      const to = err.candWord || err.correctWord || err.correct_word || from;
      if (from && from !== to) {
        corrections.push({
          from,
          to,
          type: parseErrorType(err.errorType || err.error_type || err.correctMethod || 0),
          description: err.help || err.description || ''
        });
      }
    }
  }
  
  // 형식 2: { suggestions: [{ text, candidates, description, start, end }] }
  else if (data.suggestions && Array.isArray(data.suggestions)) {
    for (const s of data.suggestions) {
      const from = s.text || s.token || '';
      const to = (s.candidates && s.candidates[0]) || s.replacement || from;
      if (from && from !== to) {
        corrections.push({
          from, to,
          type: s.type || '맞춤법',
          description: s.description || s.help || ''
        });
      }
    }
  }
  
  // 형식 3: { result: { errs: [...] } } 또는 배열 직접
  else if (data.result) {
    const errs = data.result.errs || data.result.errInfo || data.result.corrections || [];
    const arr = Array.isArray(errs) ? errs : [];
    for (const err of arr) {
      const from = err.orgStr || err.from || err.text || '';
      const to = err.candWord || err.to || (err.candidates && err.candidates[0]) || from;
      if (from && from !== to) {
        corrections.push({
          from, to,
          type: parseErrorType(err.errorType || err.correctMethod || 0),
          description: err.help || err.description || ''
        });
      }
    }
  }
  
  // 교정된 텍스트 생성
  let correctedText = originalText;
  for (const c of corrections) {
    correctedText = correctedText.replace(new RegExp(escapeRegExp(c.from), 'g'), c.to);
  }
  
  return { corrections, correctedText };
}

// errorType/correctMethod → 한글 타입
function parseErrorType(code) {
  const n = parseInt(code);
  switch (n) {
    case 1: return '맞춤법';
    case 2: return '띄어쓰기';
    case 3: return '표준어';
    case 4: return '통계적 교정';
    default:
      if (typeof code === 'string' && code.length > 1) return code;
      return '맞춤법';
  }
}

// 프록시: /api/apps/:appUrl/* → 해당 앱 백엔드로 전달
app.all('/api/apps/:appUrl/*', async (req, res) => {
  const { appUrl } = req.params;
  
  try {
    const appInfo = await getAppInfo(appUrl);
    
    if (!appInfo) {
      return res.status(404).json({ error: '앱을 찾을 수 없습니다' });
    }
    
    if (!appInfo.active) {
      return res.status(503).json({ error: '앱이 비활성화 상태입니다' });
    }
    
    if (!appInfo.hasBackend || !appInfo.port) {
      return res.status(404).json({ error: '백엔드가 없는 앱입니다' });
    }
    
    // 원래 경로에서 /api/apps/{appUrl} 부분 제거
    const targetPath = req.originalUrl.replace(`/api/apps/${appUrl}`, '') || '/';
    req.url = targetPath;
    
    // 해당 포트로 프록시
    const target = `http://127.0.0.1:${appInfo.port}`;
    console.log(`프록시: ${req.method} ${req.originalUrl} → ${target}${targetPath}`);
    
    proxy.web(req, res, { target, timeout: 180000, proxyTimeout: 180000 });
    
  } catch (error) {
    console.error('프록시 처리 실패:', error.message);
    if (!res.headersSent) {
      res.status(500).json({ error: '프록시 처리 실패: ' + error.message });
    }
  }
});

// appUrl만 있고 뒤에 경로가 없는 경우도 처리
app.all('/api/apps/:appUrl', async (req, res) => {
  const { appUrl } = req.params;
  
  try {
    const appInfo = await getAppInfo(appUrl);
    
    if (!appInfo) {
      return res.status(404).json({ error: '앱을 찾을 수 없습니다' });
    }
    
    if (!appInfo.active) {
      return res.status(503).json({ error: '앱이 비활성화 상태입니다' });
    }
    
    if (!appInfo.hasBackend || !appInfo.port) {
      return res.status(404).json({ error: '백엔드가 없는 앱입니다' });
    }
    
    req.url = '/';
    const target = `http://127.0.0.1:${appInfo.port}`;
    console.log(`프록시: ${req.method} /api/apps/${appUrl} → ${target}/`);
    
    proxy.web(req, res, { target, timeout: 180000, proxyTimeout: 180000 });
    
  } catch (error) {
    if (!res.headersSent) {
      res.status(500).json({ error: '프록시 처리 실패: ' + error.message });
    }
  }
});

// ========================================
// ★★★ Body Parser는 프록시 라우트 이후에 정의 ★★★
// ========================================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 프론트엔드 정적 파일 서빙 (index.html, admin/)
const FRONTEND_DIR = path.join(__dirname, '..');
app.use(express.static(FRONTEND_DIR));

const upload = multer({ dest: path.join(DATA_ROOT, 'tmp-uploads') });

// ========================================
// 관리자 API (body parser 필요)
// ========================================

// ===== ★ 세션 영속화 — 재시작 후 재로그인 불필요 =====
const SESSION_FILE = path.join(DATA_ROOT, 'config', 'sessions.json');

async function loadSessions() {
  try {
    if (await fs.pathExists(SESSION_FILE)) {
      const data = await fs.readJson(SESSION_FILE);
      const now = Date.now();
      // 만료 세션 제거 후 Map으로 복원
      Object.entries(data).forEach(([token, session]) => {
        if (now - session.createdAt < 24 * 60 * 60 * 1000) {
          sessions.set(token, session);
        }
      });
      console.log(`[Session] ${sessions.size}개 세션 복원됨`);
    }
  } catch (e) {
    console.warn('[Session] 세션 로드 실패 (무시):', e.message);
  }
}

async function persistSessions() {
  try {
    const data = {};
    const now = Date.now();
    sessions.forEach((session, token) => {
      // 만료 안된 세션만 저장
      if (now - session.createdAt < 24 * 60 * 60 * 1000) {
        data[token] = session;
      }
    });
    await fs.ensureDir(path.dirname(SESSION_FILE));
    await fs.writeJson(SESSION_FILE, data);
  } catch (e) {
    console.warn('[Session] 세션 저장 실패:', e.message);
  }
}

// 서버 시작 시 세션 복원 (즉시 실행)
loadSessions();

// ===== 맞춤법 검사 프록시 API (body parser 이후로 이동) =====
app.post('/api/apps/speller/check', async (req, res) => {
  const { text } = req.body;

  if (!text || typeof text !== 'string') {
    return res.status(400).json({ error: '검사할 텍스트를 입력하세요' });
  }

  const trimmedText = text.trim();
  if (trimmedText.length === 0) {
    return res.status(400).json({ error: '텍스트가 비어있습니다' });
  }

  try {
    const chunks = splitText(trimmedText, SPELLER_CHAR_LIMIT);
    const allCorrections = [];
    let fullCorrectedText = '';
    let debugInfo = null;

    for (let ci = 0; ci < chunks.length; ci++) {
      const chunk = chunks[ci];
      let data = null;
      let method = '';

      try {
        const response = await axios.post(
          'https://nara-speller.co.kr/api/check',
          { text: chunk },
          { headers: { 'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0', 'Origin': 'https://nara-speller.co.kr', 'Referer': 'https://nara-speller.co.kr/speller/' }, timeout: 30000 }
        );
        data = response.data; method = 'json-api';
      } catch (e1) {
        console.log('[speller] JSON API 실패:', e1.message);
        try {
          const response = await axios.post(
            'https://nara-speller.co.kr/api/check',
            `text=${encodeURIComponent(chunk)}`,
            { headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'Mozilla/5.0', 'Origin': 'https://nara-speller.co.kr', 'Referer': 'https://nara-speller.co.kr/speller/' }, timeout: 30000 }
          );
          data = response.data; method = 'form-urlencoded';
        } catch (e2) {
          console.log('[speller] form-urlencoded 실패:', e2.message);
          try {
            const response = await axios.post(
              'https://speller.cs.pusan.ac.kr/results',
              `text1=${encodeURIComponent(chunk)}`,
              { headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'Mozilla/5.0', 'Origin': 'https://speller.cs.pusan.ac.kr', 'Referer': 'https://speller.cs.pusan.ac.kr/' }, timeout: 30000 }
            );
            data = response.data; method = 'old-endpoint';
          } catch (e3) {
            throw new Error(`모든 엔드포인트 실패: ${e1.message}`);
          }
        }
      }

      if (ci === 0) {
        debugInfo = { method, responseType: typeof data, keys: typeof data === 'object' ? Object.keys(data || {}) : [], snippet: JSON.stringify(data).substring(0, 500) };
        console.log('[speller] 방식:', method, '| 키:', debugInfo.keys);
      }

      if (typeof data === 'string') {
        fullCorrectedText += (fullCorrectedText ? ' ' : '') + chunk;
        continue;
      }

      const { corrections, correctedText } = parseSpellerResponse(data, chunk);
      allCorrections.push(...corrections);
      fullCorrectedText += (fullCorrectedText ? ' ' : '') + correctedText;
    }

    const uniqueCorrections = [];
    const seen = new Set();
    for (const c of allCorrections) {
      const key = `${c.from}→${c.to}`;
      if (!seen.has(key)) { seen.add(key); uniqueCorrections.push(c); }
    }

    res.json({ success: true, original: trimmedText, corrections: uniqueCorrections, corrected_text: fullCorrectedText, chunks_processed: chunks.length, _debug: debugInfo });

  } catch (error) {
    console.error('맞춤법 검사 오류:', error.message);
    res.status(500).json({ error: '맞춤법 검사 실패: ' + error.message, hint: '나라 맞춤법 검사기 서버에 연결할 수 없습니다' });
  }
});

// ===== 로그인 API =====
// ★ IP 체크 임시 비활성화 - 설정에서 IP 등록 후 다시 활성화 필요
// app.post('/api/admin/login', checkAdminIp, async (req, res) => {
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: '아이디와 비밀번호를 입력하세요' });
  }
  
  try {
    const authConfig = await getAuthConfig();
    const passwordHash = hashPassword(password);
    
    if (username === authConfig.username && passwordHash === authConfig.passwordHash) {
      const token = generateToken();
      sessions.set(token, {
        username,
        createdAt: Date.now()
      });
      await persistSessions();  // ★ 파일에 저장 → 재시작 후 복원 가능
      
      res.json({ success: true, token, username });
    } else {
      res.status(401).json({ error: '아이디 또는 비밀번호가 잘못되었습니다' });
    }
  } catch (error) {
    res.status(500).json({ error: '로그인 실패: ' + error.message });
  }
});

// ===== 로그아웃 API =====
app.post('/api/admin/logout', async (req, res) => {
  const token = req.headers['x-auth-token'];
  if (token) {
    sessions.delete(token);
    await persistSessions();  // ★ 파일에서도 제거
  }
  res.json({ success: true });
});

// ===== 인증 상태 확인 API =====
app.get('/api/admin/auth/check', (req, res) => {
  const token = req.headers['x-auth-token'];
  
  if (!token || !sessions.has(token)) {
    return res.json({ isLoggedIn: false });
  }
  
  const session = sessions.get(token);
  
  if (Date.now() - session.createdAt > 24 * 60 * 60 * 1000) {
    sessions.delete(token);
    return res.json({ isLoggedIn: false });
  }
  
  res.json({ isLoggedIn: true, username: session.username });
});

// ===== 글로벌 설정 조회 API =====
app.get('/api/admin/settings', requireAuth, async (req, res) => {
  try {
    let s = {};
    if (await fs.pathExists(CONFIG.SETTINGS_FILE)) {
      s = await fs.readJson(CONFIG.SETTINGS_FILE);
      // API 키는 앞 일부만 노출 (보안)
      if (s.anthropicApiKey)     s.anthropicApiKeyMasked     = s.anthropicApiKey.substring(0, 10) + '...';
      if (s.anthropicAdminApiKey) s.anthropicAdminApiKeyMasked = s.anthropicAdminApiKey.substring(0, 15) + '...';
      if (s.openaiApiKey)        s.openaiApiKeyMasked        = s.openaiApiKey.substring(0, 7) + '...';
      if (s.googleApiKey)        s.googleApiKeyMasked        = s.googleApiKey.substring(0, 8) + '...';
      // 원본 키는 응답에서 제거 (보안)
      delete s.anthropicApiKey;
      delete s.anthropicAdminApiKey;
      delete s.openaiApiKey;
      delete s.googleApiKey;
    }
    res.json({ success: true, ...s });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ===== 글로벌 설정 저장 API =====
app.post('/api/admin/settings', requireAuth, async (req, res) => {
  try {
    const existing = await fs.pathExists(CONFIG.SETTINGS_FILE) ? await fs.readJson(CONFIG.SETTINGS_FILE) : {};
    const updated = { ...existing, ...req.body };
    await fs.ensureDir(path.dirname(CONFIG.SETTINGS_FILE));
    await fs.writeJson(CONFIG.SETTINGS_FILE, updated, { spaces: 2 });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ===== 비밀번호 변경 API =====
app.post('/api/admin/change-password', requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: '현재 비밀번호와 새 비밀번호를 입력하세요' });
  }
  
  if (newPassword.length < 6) {
    return res.status(400).json({ error: '새 비밀번호는 6자 이상이어야 합니다' });
  }
  
  try {
    const authConfig = await getAuthConfig();
    const currentHash = hashPassword(currentPassword);
    
    if (currentHash !== authConfig.passwordHash) {
      return res.status(401).json({ error: '현재 비밀번호가 잘못되었습니다' });
    }
    
    authConfig.passwordHash = hashPassword(newPassword);
    await saveAuthConfig(authConfig);
    
    res.json({ success: true, message: '비밀번호가 변경되었습니다' });
  } catch (error) {
    res.status(500).json({ error: '비밀번호 변경 실패: ' + error.message });
  }
});

// ===== 앱 목록 API =====
app.get('/api/admin/apps', requireAuth, async (req, res) => {
  try {
    const appsConfigPath = path.join(CONFIG.APPS_DIR, 'apps.json');
    
    if (!await fs.pathExists(appsConfigPath)) {
      await fs.writeJson(appsConfigPath, { apps: [], categories: [] });
    }
    
    const config = await fs.readJson(appsConfigPath);
    res.json(config.apps);
  } catch (error) {
    res.status(500).json({ error: '앱 목록 조회 실패: ' + error.message });
  }
});

// ===== 카테고리 목록 API =====
app.get('/api/admin/categories', requireAuth, async (req, res) => {
  try {
    const appsConfigPath = path.join(CONFIG.APPS_DIR, 'apps.json');
    
    if (!await fs.pathExists(appsConfigPath)) {
      await fs.writeJson(appsConfigPath, { apps: [], categories: [] });
    }
    
    const config = await fs.readJson(appsConfigPath);
    res.json(config.categories || []);
  } catch (error) {
    res.status(500).json({ error: '카테고리 목록 조회 실패: ' + error.message });
  }
});

// ===== 카테고리 추가 API =====
app.post('/api/admin/categories', requireAuth, async (req, res) => {
  const { name } = req.body;
  
  if (!name) {
    return res.status(400).json({ error: '카테고리 이름을 입력하세요' });
  }
  
  try {
    const appsConfigPath = path.join(CONFIG.APPS_DIR, 'apps.json');
    const config = await fs.pathExists(appsConfigPath) 
      ? await fs.readJson(appsConfigPath) 
      : { apps: [], categories: [] };
    
    if (!config.categories) config.categories = [];
    
    if (config.categories.find(c => c.name === name)) {
      return res.status(400).json({ error: '이미 존재하는 카테고리입니다' });
    }
    
    const category = {
      id: 'cat_' + Date.now(),
      name,
      createdAt: new Date().toISOString()
    };
    
    config.categories.push(category);
    await fs.writeJson(appsConfigPath, config, { spaces: 2 });
    
    res.json({ success: true, category });
  } catch (error) {
    res.status(500).json({ error: '카테고리 추가 실패: ' + error.message });
  }
});

// ===== 카테고리 삭제 API =====
app.delete('/api/admin/categories/:categoryId', requireAuth, async (req, res) => {
  const { categoryId } = req.params;
  
  try {
    const appsConfigPath = path.join(CONFIG.APPS_DIR, 'apps.json');
    const config = await fs.readJson(appsConfigPath);
    
    config.categories = (config.categories || []).filter(c => c.id !== categoryId);
    
    // 해당 카테고리를 사용하는 앱들의 카테고리 초기화
    config.apps = config.apps.map(app => {
      if (app.categoryId === categoryId) {
        app.categoryId = null;
      }
      return app;
    });
    
    await fs.writeJson(appsConfigPath, config, { spaces: 2 });
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: '카테고리 삭제 실패: ' + error.message });
  }
});

// ===== 앱 정보 수정 API =====
app.patch('/api/admin/apps/:appUrl', requireAuth, async (req, res) => {
  const { appUrl } = req.params;
  if (!/^[a-zA-Z0-9_-]+$/.test(appUrl)) return res.status(400).json({ error: '유효하지 않은 appUrl' });
  const { name, description, categoryId } = req.body;
  
  try {
    const appsConfigPath = path.join(CONFIG.APPS_DIR, 'apps.json');
    const config = await fs.readJson(appsConfigPath);
    const appItem = config.apps.find(a => a.url === appUrl);
    
    if (!appItem) {
      return res.status(404).json({ error: '앱을 찾을 수 없습니다' });
    }
    
    if (name !== undefined) appItem.name = name;
    if (description !== undefined) appItem.description = description;
    if (categoryId !== undefined) appItem.categoryId = categoryId;
    appItem.updatedAt = new Date().toISOString();
    
    await fs.writeJson(appsConfigPath, config, { spaces: 2 });
    
    res.json({ success: true, app: appItem });
  } catch (error) {
    res.status(500).json({ error: '앱 정보 수정 실패: ' + error.message });
  }
});

// ===== 앱 배포 API =====
app.post('/api/admin/deploy', requireAuth, upload.fields([
  { name: 'frontend', maxCount: 1 },
  { name: 'backend', maxCount: 1 }
]), async (req, res) => {
  const { appName, appUrl, description, categoryId } = req.body;
  
  if (!appName || !appUrl) {
    return res.status(400).json({ error: '앱 이름과 URL은 필수입니다' });
  }

  // ★ appUrl 경로 조작 방지 — 영문/숫자/하이픈만 허용
  if (!/^[a-zA-Z0-9_-]+$/.test(appUrl)) {
    return res.status(400).json({ error: 'appUrl은 영문, 숫자, 하이픈(-), 언더스코어(_)만 사용 가능합니다' });
  }

  // ★ multer 임시파일 — 예외 발생 시 finally에서 반드시 정리
  const tempFiles = [];
  if (req.files?.frontend) tempFiles.push(req.files.frontend[0].path);
  if (req.files?.backend)  tempFiles.push(req.files.backend[0].path);

  try {
    const appPath = path.join(CONFIG.APPS_DIR, appUrl);
    const appsConfigPath = path.join(CONFIG.APPS_DIR, 'apps.json');
    const appZipsPath = path.join(CONFIG.APP_ZIPS_DIR, appUrl);  // 원본 ZIP 저장 경로
    
    const config = await fs.pathExists(appsConfigPath) 
      ? await fs.readJson(appsConfigPath) 
      : { apps: [] };
    
    const existingApp = config.apps.find(a => a.url === appUrl);
    let port = existingApp?.port;
    
    // ★ 자동 백업: 기존 앱이 있으면 업데이트 전 백업
    if (existingApp && await fs.pathExists(appPath)) {
      console.log(`${appUrl}: 업데이트 전 자동 백업 생성...`);
      await createAppBackup(appUrl, 'auto-before-update');
    }
    
    await stopBackendServer(appUrl);
    
    // 프론트엔드 배포
    if (req.files?.frontend) {
      const frontendZip = req.files.frontend[0].path;
      await fs.ensureDir(appPath);

      // ★ 원본 ZIP 저장 폴더 생성 (파일이 있을 때만)
      await fs.ensureDir(appZipsPath);
      
      // ★ 원본 ZIP 저장
      await fs.copy(frontendZip, path.join(appZipsPath, 'frontend.zip'));
      
      // 배포 시 보존할 폴더 목록 (데이터/설정 폴더)
      const PRESERVE = new Set([
        // 앱 데이터 폴더 (배포 후에도 유지)
        'backend', 'data', 'private-data',
        'play-workshop-data', 'spark-data', 'export-center-data',
        'prompt-manager-data', 'groupware-data', 'cs-center-data',
        // 설정 파일 (배포 시 절대 덮어쓰지 않음)
        'settings.json', 'auth.json', 'ip-config.json',
        'apps.json', 'ai-usage-log.json',
        'cc-mapping.json', 'plans.json',
      ]);

      const items = await fs.readdir(appPath).catch(() => []);
      for (const item of items) {
        if (!PRESERVE.has(item)) {
          await fs.remove(path.join(appPath, item));
        }
      }
      
      await fs.createReadStream(frontendZip)
        .pipe(unzipper.Extract({ path: appPath }))
        .promise();
      
      await fs.remove(frontendZip);
    }

    // 백엔드 배포
    let hasBackend = existingApp?.hasBackend || false;
    if (req.files?.backend) {
      const backendZip = req.files.backend[0].path;
      const backendPath = path.join(appPath, 'backend');
      await fs.ensureDir(backendPath);
      // ★ 원본 ZIP 저장 폴더 (백엔드만 배포 시에도 생성)
      await fs.ensureDir(appZipsPath);
      // 데이터 폴더는 보존하면서 코드만 교체
      const PRESERVE_BACKEND = new Set(['data', 'private-data', 'logs']);
      const bItems = await fs.readdir(backendPath).catch(() => []);
      for (const item of bItems) {
        if (!PRESERVE_BACKEND.has(item)) {
          await fs.remove(path.join(backendPath, item));
        }
      }
      
      // ★ 원본 ZIP 저장
      await fs.copy(backendZip, path.join(appZipsPath, 'backend.zip'));
      
      await fs.createReadStream(backendZip)
        .pipe(unzipper.Extract({ path: backendPath }))
        .promise();
      
      await fs.remove(backendZip);
      hasBackend = true;
      
      if (!port) {
        port = await findAvailablePort();
        console.log(`${appUrl}: 새 포트 할당 - ${port}`);
      }
      
      await startBackendServer(appUrl, port);
    }

    // 앱 정보 저장
    const existingIndex = config.apps.findIndex(a => a.url === appUrl);
    const appInfo = {
      name: appName,
      url: appUrl,
      description: description || '',
      categoryId: categoryId || existingApp?.categoryId || null,
      active: existingApp ? existingApp.active : true,  // ★ 기존 비활성화 상태 보존
      hasFrontend: !!req.files?.frontend || existingApp?.hasFrontend || false,
      hasBackend: hasBackend,
      port: hasBackend ? port : null,
      ai_model: existingApp?.ai_model || null,  // ★ 배포 시 AI 모델 설정 보존
      ai_agent: existingApp?.ai_agent || null,  // ★ 배포 시 AI 에이전트 설정 보존
      deployedAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    if (existingIndex >= 0) {
      appInfo.deployedAt = config.apps[existingIndex].deployedAt;
      config.apps[existingIndex] = appInfo;
    } else {
      config.apps.push(appInfo);
    }

    await fs.writeJson(appsConfigPath, config, { spaces: 2 });
    res.json({ success: true, app: appInfo });

  } catch (error) {
    res.status(500).json({ error: '배포 실패: ' + error.message });
  } finally {
    // ★ 성공/실패 무관 multer 임시파일 정리
    for (const tmpPath of tempFiles) {
      try { await fs.remove(tmpPath); } catch(_) {}
    }
  }
});


// ─── 앱별 AI 설정 API ────────────────────────────────────────────
// GET /api/admin/apps/:appUrl/ai-settings
app.get('/api/admin/apps/:appUrl/ai-settings', requireAuth, async (req, res) => {
  try {
    const { appUrl } = req.params;
    const appsConfig = path.join(CONFIG.APPS_DIR, 'apps.json');
    const cfg = await fs.pathExists(appsConfig) ? await fs.readJson(appsConfig) : { apps: [] };
    const appInfo = cfg.apps?.find(a => a.url === appUrl);
    if (!appInfo) return res.status(404).json({ error: '앱 없음' });
    res.json({
      success: true,
      ai_model: appInfo.ai_model || '',
      ai_agent: appInfo.ai_agent || '',
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// PUT /api/admin/apps/:appUrl/ai-settings
app.put('/api/admin/apps/:appUrl/ai-settings', requireAuth, async (req, res) => {
  try {
    const { appUrl } = req.params;
    const { ai_model, ai_agent } = req.body;
    const appsConfig = path.join(CONFIG.APPS_DIR, 'apps.json');
    const cfg = await fs.pathExists(appsConfig) ? await fs.readJson(appsConfig) : { apps: [] };
    const idx = cfg.apps?.findIndex(a => a.url === appUrl);
    if (idx < 0) return res.status(404).json({ error: '앱 없음' });
    cfg.apps[idx].ai_model = ai_model || null;
    cfg.apps[idx].ai_agent = ai_agent || null;
    await fs.writeJson(appsConfig, cfg, { spaces: 2 });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ===== 앱 삭제 API =====
app.delete('/api/admin/apps/:appUrl', requireAuth, async (req, res) => {
  const { appUrl } = req.params;
  if (!/^[a-zA-Z0-9_-]+$/.test(appUrl)) return res.status(400).json({ error: '유효하지 않은 appUrl' });
  
  try {
    await stopBackendServer(appUrl);
    
    const appPath = path.join(CONFIG.APPS_DIR, appUrl);
    await fs.remove(appPath);

    const appsConfigPath = path.join(CONFIG.APPS_DIR, 'apps.json');
    const config = await fs.readJson(appsConfigPath);
    config.apps = config.apps.filter(a => a.url !== appUrl);
    await fs.writeJson(appsConfigPath, config, { spaces: 2 });

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: '삭제 실패: ' + error.message });
  }
});

// ===== 앱 활성화/비활성화 API =====
app.patch('/api/admin/apps/:appUrl/toggle', requireAuth, async (req, res) => {
  const { appUrl } = req.params;
  if (!/^[a-zA-Z0-9_-]+$/.test(appUrl)) return res.status(400).json({ error: '유효하지 않은 appUrl' });
  
  try {
    const appsConfigPath = path.join(CONFIG.APPS_DIR, 'apps.json');
    const config = await fs.readJson(appsConfigPath);
    const appItem = config.apps.find(a => a.url === appUrl);
    
    if (!appItem) {
      return res.status(404).json({ error: '앱을 찾을 수 없습니다' });
    }
    
    appItem.active = !appItem.active;
    appItem.updatedAt = new Date().toISOString();
    
    if (appItem.hasBackend && appItem.port) {
      if (appItem.active) {
        await startBackendServer(appUrl, appItem.port);
      } else {
        await stopBackendServer(appUrl);
      }
    }
    
    await fs.writeJson(appsConfigPath, config, { spaces: 2 });
    
    res.json({ success: true, active: appItem.active });
  } catch (error) {
    res.status(500).json({ error: '상태 변경 실패: ' + error.message });
  }
});

// ===== 이미지 업로드 API =====
app.post('/api/admin/images', requireAuth, upload.array('images', 20), async (req, res) => {
  const { folder } = req.body;
  
  try {
    const targetDir = folder 
      ? path.join(CONFIG.IMAGES_DIR, folder)
      : CONFIG.IMAGES_DIR;
    
    await fs.ensureDir(targetDir);
    
    const uploadedFiles = [];
    for (const file of req.files) {
      const targetPath = path.join(targetDir, file.originalname);
      await fs.move(file.path, targetPath, { overwrite: true });
      uploadedFiles.push({
        name: file.originalname,
        path: folder ? `${folder}/${file.originalname}` : file.originalname
      });
    }
    
    res.json({ success: true, files: uploadedFiles });
  } catch (error) {
    res.status(500).json({ error: '이미지 업로드 실패: ' + error.message });
  }
});

// ===== 이미지 목록 API =====
app.get('/api/admin/images', requireAuth, async (req, res) => {
  const { folder } = req.query;
  
  try {
    const targetDir = folder 
      ? path.join(CONFIG.IMAGES_DIR, folder)
      : CONFIG.IMAGES_DIR;
    
    if (!await fs.pathExists(targetDir)) {
      return res.json({ files: [], folders: [] });
    }
    
    const items = await fs.readdir(targetDir, { withFileTypes: true });
    const files = [];
    const folders = [];
    
    for (const item of items) {
      if (item.isDirectory()) {
        folders.push(item.name);
      } else {
        const stat = await fs.stat(path.join(targetDir, item.name));
        files.push({
          name: item.name,
          size: stat.size,
          modified: stat.mtime
        });
      }
    }
    
    res.json({ files, folders });
  } catch (error) {
    res.status(500).json({ error: '이미지 목록 조회 실패: ' + error.message });
  }
});

// ===== 이미지 폴더 생성 API =====
app.post('/api/admin/images/folder', requireAuth, async (req, res) => {
  const { folderName, parentFolder } = req.body;
  
  if (!folderName) {
    return res.status(400).json({ error: '폴더 이름을 입력하세요' });
  }
  
  // 폴더명 유효성 검사 (영문, 숫자, 하이픈, 언더스코어, 한글만 허용)
  if (!/^[a-zA-Z0-9가-힣_-]+$/.test(folderName)) {
    return res.status(400).json({ error: '폴더 이름은 영문, 숫자, 한글, 하이픈(-), 언더스코어(_)만 사용 가능합니다' });
  }
  
  try {
    const targetPath = parentFolder 
      ? path.join(CONFIG.IMAGES_DIR, parentFolder, folderName)
      : path.join(CONFIG.IMAGES_DIR, folderName);
    
    if (await fs.pathExists(targetPath)) {
      return res.status(400).json({ error: '이미 존재하는 폴더입니다' });
    }
    
    await fs.ensureDir(targetPath);
    
    res.json({ success: true, folder: folderName });
  } catch (error) {
    res.status(500).json({ error: '폴더 생성 실패: ' + error.message });
  }
});

// ===== 백업 목록 API =====
app.get('/api/admin/backups', requireAuth, async (req, res) => {
  const { appUrl } = req.query;
  
  try {
    const backups = await getBackupList(appUrl || null);
    res.json(backups);
  } catch (error) {
    res.status(500).json({ error: '백업 목록 조회 실패: ' + error.message });
  }
});

// ===== 개별 앱 백업 API =====
app.post('/api/admin/backups/:appUrl', requireAuth, async (req, res) => {
  const { appUrl } = req.params;
  
  try {
    const result = await createAppBackup(appUrl, 'manual');
    
    if (result.success) {
      res.json({ success: true, backupName: result.backupName });
    } else {
      res.status(400).json({ error: result.error });
    }
  } catch (error) {
    res.status(500).json({ error: '백업 생성 실패: ' + error.message });
  }
});

// ===== 전체 백업 API =====
app.post('/api/admin/backups-all', requireAuth, async (req, res) => {
  try {
    const appsConfigPath = path.join(CONFIG.APPS_DIR, 'apps.json');
    const config = await fs.pathExists(appsConfigPath) 
      ? await fs.readJson(appsConfigPath) 
      : { apps: [] };
    
    const results = [];
    
    // 모든 앱 백업
    for (const app of config.apps) {
      const result = await createAppBackup(app.url, 'manual-full');
      results.push({ appUrl: app.url, ...result });
    }
    
    // apps.json 백업
    const timestamp = getBackupTimestamp();
    const configBackupPath = path.join(CONFIG.BACKUPS_DIR, '_config', timestamp);
    await fs.ensureDir(configBackupPath);
    await fs.copy(appsConfigPath, path.join(configBackupPath, 'apps.json'));
    
    // 공통 이미지 백업
    if (await fs.pathExists(CONFIG.IMAGES_DIR)) {
      await fs.copy(CONFIG.IMAGES_DIR, path.join(configBackupPath, 'images'));
    }
    
    res.json({ 
      success: true, 
      message: `${results.length}개 앱 + 설정 + 이미지 백업 완료`,
      results 
    });
  } catch (error) {
    res.status(500).json({ error: '전체 백업 실패: ' + error.message });
  }
});

// ===== 백업 복원 API =====
app.post('/api/admin/backups/:appUrl/restore', requireAuth, async (req, res) => {
  const { appUrl } = req.params;
  const { backupName } = req.body;
  
  if (!backupName) {
    return res.status(400).json({ error: '복원할 백업을 선택하세요' });
  }
  
  try {
    const result = await restoreAppFromBackup(appUrl, backupName);
    
    if (result.success) {
      res.json({ success: true, message: '복원 완료' });
    } else {
      res.status(400).json({ error: result.error });
    }
  } catch (error) {
    res.status(500).json({ error: '복원 실패: ' + error.message });
  }
});

// ===== 백업 삭제 API =====
app.delete('/api/admin/backups/:appUrl/:backupName', requireAuth, async (req, res) => {
  const { appUrl, backupName } = req.params;
  
  try {
    const backupPath = path.join(CONFIG.BACKUPS_DIR, appUrl, backupName);
    
    if (!await fs.pathExists(backupPath)) {
      return res.status(404).json({ error: '백업을 찾을 수 없습니다' });
    }
    
    await fs.remove(backupPath);
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: '백업 삭제 실패: ' + error.message });
  }
});

// ===== 이미지 삭제 API =====
app.delete('/api/admin/images/:imagePath(*)', requireAuth, async (req, res) => {
  const { imagePath } = req.params;
  
  try {
    const fullPath = path.join(CONFIG.IMAGES_DIR, imagePath);
    await fs.remove(fullPath);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: '이미지 삭제 실패: ' + error.message });
  }
});

// ===== 공개 이미지 서빙 API =====
app.get('/api/images/:imagePath(*)', async (req, res) => {
  const { imagePath } = req.params;
  
  if (imagePath.includes('..')) {
    return res.status(400).json({ error: '잘못된 경로입니다' });
  }
  
  try {
    const commonPath = path.join(CONFIG.IMAGES_DIR, imagePath);
    if (await fs.pathExists(commonPath)) {
      return res.sendFile(commonPath);
    }
    
    const appsConfigPath = path.join(CONFIG.APPS_DIR, 'apps.json');
    if (await fs.pathExists(appsConfigPath)) {
      const config = await fs.readJson(appsConfigPath);
      
      for (const appItem of config.apps) {
        if (!appItem.active) continue;
        
        const appImagePath = path.join(CONFIG.APPS_DIR, appItem.url, 'backend', 'images', imagePath);
        if (await fs.pathExists(appImagePath)) {
          return res.sendFile(appImagePath);
        }
      }
    }
    
    return res.status(404).json({ error: '이미지를 찾을 수 없습니다' });
    
  } catch (error) {
    res.status(500).json({ error: '이미지 로드 실패: ' + error.message });
  }
});

// ===== 공통 AI 프록시 엔드포인트 =====
// 모든 앱 프론트에서 /ai/generate 로 호출하면 Claude API로 전달
// ANTHROPIC_API_KEY는 설정 탭에서 등록한 키를 자동 사용
app.post('/ai/generate', async (req, res) => {
  // 내부 호출만 허용 (127.0.0.1 또는 ::1)
  const clientIp = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').replace('::ffff:', '');
  if (clientIp !== '127.0.0.1' && clientIp !== '::1' && clientIp !== 'localhost') {
    return res.status(403).json({ error: '내부 호출만 허용됩니다' });
  }

  try {
    // API 키: 환경변수 우선 → settings.json 폴백
    // ★ defaultModel은 API 키 유무와 무관하게 항상 settings.json에서 읽음
    let apiKey = process.env.ANTHROPIC_API_KEY || null;
    let defaultModel = null;
    if (await fs.pathExists(CONFIG.SETTINGS_FILE)) {
      const settings = await fs.readJson(CONFIG.SETTINGS_FILE).catch(() => ({}));
      if (!apiKey) apiKey = settings.anthropicApiKey || null;  // API 키는 환경변수 없을 때만 폴백
      defaultModel = settings.defaultModel || null;             // 기본 모델은 항상 읽음
    }

    if (!apiKey) {
      return res.status(500).json({
        error: 'ANTHROPIC_API_KEY가 설정되지 않았습니다. 앱매니저 환경변수 또는 설정 탭에서 등록해주세요.'
      });
    }

    const { messages, system, model, max_tokens, temperature, app_id, mode = 'instant' } = req.body;
    if (!messages || !Array.isArray(messages)) {
      return res.status(400).json({ error: 'messages 배열이 필요합니다' });
    }

    // 앱별 AI 설정 로드 (apps.json)
    let appAiModel = null, appAiAgent = null;
    let appRegistered = false; // apps.json에 등록된 앱인지 여부
    const appIdResolved = app_id || extractAppId(req, app_id);
    if (appIdResolved) {
      try {
        const appsConfig = path.join(CONFIG.APPS_DIR, 'apps.json');
        if (await fs.pathExists(appsConfig)) {
          const cfg = await fs.readJson(appsConfig);
          const appInfo = cfg.apps?.find(a => a.url === appIdResolved);
          if (appInfo) {
            appRegistered = true;               // 앱이 등록돼 있음
            if (appInfo.ai_model) appAiModel = appInfo.ai_model;
            if (appInfo.ai_agent) appAiAgent = appInfo.ai_agent;
          }
        }
      } catch(_) {}
    }

    // ★ 앱이 등록돼 있고 ai_model이 미설정이면 → AI 사용 안 함 (차단)
    // 등록되지 않은 앱이나 app_id 없는 호출은 글로벌 기본값으로 허용 (하위 호환)
    if (appRegistered && !appAiModel) {
      return res.status(403).json({
        error: `[${appIdResolved}] AI가 비활성화된 앱입니다. 앱매니저 > 해당 앱 수정 > AI 설정에서 모델을 선택하세요.`
      });
    }

    // 우선순위: 요청의 model > 앱별 설정 > 글로벌 기본값
    const resolvedModel = model || appAiModel || defaultModel || 'claude-sonnet-4-6';

    // ── 프로바이더 판별 ────────────────────────────────────────
    const provider = getProvider(resolvedModel);  // 단일 판별 함수 사용

    // 프로바이더별 API 키 로드
    let providerKey = null;
    if (provider === 'anthropic') {
      providerKey = apiKey;  // 이미 로드됨
    } else {
      const settings2 = await fs.pathExists(CONFIG.SETTINGS_FILE)
        ? await fs.readJson(CONFIG.SETTINGS_FILE).catch(() => ({})) : {};
      if (provider === 'openai')  providerKey = process.env.OPENAI_API_KEY  || settings2.openaiApiKey  || null;
      if (provider === 'google')  providerKey = process.env.GOOGLE_API_KEY  || settings2.googleApiKey  || null;
    }

    if (!providerKey) {
      return res.status(500).json({
        error: `${provider === 'openai' ? 'OpenAI' : provider === 'google' ? 'Google Gemini' : 'Anthropic'} API 키가 설정되지 않았습니다. 앱매니저 설정 탭에서 등록해주세요.`
      });
    }

    // 앱별 AI 에이전트 설정 (Anthropic 전용)
    const effectiveAgent = appAiAgent;
    const nodeFetch = globalThis.fetch || (await import('node-fetch')).default;

    const controller = new AbortController();
    const timeoutId  = setTimeout(() => controller.abort(), 170000);

    let response, data, normalizedData;
    try {
      // ── Anthropic ───────────────────────────────────────────
      if (provider === 'anthropic') {
        const body = { model: resolvedModel, max_tokens: max_tokens || 16000, messages };
        if (system) body.system = system;
        if (temperature !== undefined) body.temperature = temperature;
        // ★ Prompt Caching: 즉시 모드에서 반복 시스템 프롬프트 90% 절감
        if (mode === 'instant') body.cache_control = { type: 'ephemeral' };
        if (effectiveAgent === 'extended_thinking') {
          body.thinking = { type: 'enabled', budget_tokens: Math.min(max_tokens || 8000, 16000) };
        } else if (effectiveAgent === 'fast') {
          body.temperature = temperature ?? 0.9;
        } else if (effectiveAgent === 'precise') {
          body.temperature = temperature ?? 0.1;
        }
        response = await nodeFetch('https://api.anthropic.com/v1/messages', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'x-api-key': providerKey, 'anthropic-version': '2023-06-01' },
          body: JSON.stringify(body),
          signal: controller.signal,
        });
        data = await response.json();
        if (!response.ok) throw new Error(data.error?.message || 'Anthropic API 오류');
        normalizedData = data;  // Anthropic 형식 그대로

      // ── OpenAI ──────────────────────────────────────────────
      } else if (provider === 'openai') {
        // reasoning 모델 여부 판별 (o1, o3, o4 계열)
        const isReasoning = resolvedModel.startsWith('o1') ||
                            resolvedModel.startsWith('o3') ||
                            resolvedModel.startsWith('o4');
        // system 메시지: reasoning 모델은 developer 역할 사용
        const oaiMessages = system
          ? [{ role: isReasoning ? 'developer' : 'system', content: system }, ...messages]
          : messages;
        const body = { model: resolvedModel, messages: oaiMessages };
        // max_tokens: reasoning 모델은 max_completion_tokens 사용
        if (isReasoning) {
          body.max_completion_tokens = max_tokens || 4000;
        } else {
          body.max_tokens = max_tokens || 4000;
          if (temperature !== undefined) body.temperature = temperature;
        }
        response = await nodeFetch('https://api.openai.com/v1/chat/completions', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + providerKey },
          body: JSON.stringify(body),
          signal: controller.signal,
        });
        data = await response.json();
        if (!response.ok) throw new Error(data.error?.message || 'OpenAI API 오류');
        // Anthropic 형식으로 정규화 (기존 extractAIText 호환)
        normalizedData = {
          content: [{ type: 'text', text: data.choices?.[0]?.message?.content || '' }],
          usage: { input_tokens: data.usage?.prompt_tokens || 0, output_tokens: data.usage?.completion_tokens || 0 },
          model: resolvedModel, provider: 'openai',
        };

      // ── Google Gemini ────────────────────────────────────────
      } else if (provider === 'google') {
        // Gemini: user/model 교대 필수 — 연속 동일 role 병합
        const rawGeminiMsgs = messages.map(m => ({
          role: m.role === 'assistant' ? 'model' : 'user',
          parts: [{ text: m.content }],
        }));
        const geminiMessages = rawGeminiMsgs.reduce((acc, msg) => {
          const last = acc[acc.length - 1];
          if (last && last.role === msg.role) {
            // 같은 role이면 parts 병합
            last.parts.push(...msg.parts);
          } else {
            acc.push({ role: msg.role, parts: [...msg.parts] });
          }
          return acc;
        }, []);
        // 첫 메시지가 model이면 user로 교정
        if (geminiMessages.length && geminiMessages[0].role === 'model') {
          geminiMessages.unshift({ role: 'user', parts: [{ text: '' }] });
        }
        const body = {
          contents: geminiMessages,
          generationConfig: { maxOutputTokens: max_tokens || 4000, ...(temperature !== undefined ? { temperature } : {}) },
          ...(system ? { systemInstruction: { parts: [{ text: system }] } } : {}),
        };
        response = await nodeFetch(
          `https://generativelanguage.googleapis.com/v1beta/models/${resolvedModel}:generateContent?key=${providerKey}`,
          { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: controller.signal }
        );
        data = await response.json();
        if (!response.ok) throw new Error(data.error?.message || 'Google Gemini API 오류');
        const geminiText = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
        const promptTok  = data.usageMetadata?.promptTokenCount || 0;
        const outputTok  = data.usageMetadata?.candidatesTokenCount || 0;
        // Anthropic 형식으로 정규화
        normalizedData = {
          content: [{ type: 'text', text: geminiText }],
          usage: { input_tokens: promptTok, output_tokens: outputTok },
          model: resolvedModel, provider: 'google',
        };
      }
    } catch(fetchErr) {
      clearTimeout(timeoutId);
      if (fetchErr.name === 'AbortError') {
        return res.status(504).json({ error: 'AI 응답 시간 초과 (170초). 더 짧은 요청으로 시도해주세요.' });
      }
      throw fetchErr;
    } finally {
      clearTimeout(timeoutId);
    }

    // 앱별 사용량 로컬 로그 기록
    try {
      const usage = normalizedData.usage || {};
      const logEntry = {
        ts: new Date().toISOString(),
        date: new Date().toISOString().split('T')[0],
        app: app_id || extractAppId(req, app_id),
        model: resolvedModel,
        provider,
        input_tokens:  usage.input_tokens  || 0,
        output_tokens: usage.output_tokens || 0,
      };
      const log = await fs.pathExists(CONFIG.AI_LOG_FILE)
        ? await fs.readJson(CONFIG.AI_LOG_FILE).catch(() => [])
        : [];
      log.push(logEntry);
      if (log.length > 10000) log.splice(0, log.length - 10000);
      await fs.ensureDir(path.dirname(CONFIG.AI_LOG_FILE));
      await fs.writeJson(CONFIG.AI_LOG_FILE, log);
    } catch (logErr) {
      console.warn('[AI Log] 로그 기록 실패:', logErr.message);
    }

    res.json(normalizedData);

  } catch (e) {
    console.error('[AI 프록시] 호출 실패:', e.message);
    res.status(500).json({ error: '서버 오류: ' + e.message });
  }
});


// ═══════════════════════════════════════════════════════
// 환경변수 암호화 관리 API
// ═══════════════════════════════════════════════════════
const ENV_ENCRYPT_SECRET = process.env.ENV_ENCRYPT_SECRET || 'chanjin-env-secret-2025';
const ENV_ALGORITHM = 'aes-256-gcm';

function encryptEnv(text) {
  const key = crypto.scryptSync(ENV_ENCRYPT_SECRET, 'salt', 32);
  const iv  = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ENV_ALGORITHM, key, iv);
  const enc = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return iv.toString('hex') + ':' + enc.toString('hex') + ':' + tag.toString('hex');
}

function decryptEnv(encrypted) {
  const [ivHex, encHex, tagHex] = encrypted.split(':');
  const key = crypto.scryptSync(ENV_ENCRYPT_SECRET, 'salt', 32);
  const decipher = crypto.createDecipheriv(ENV_ALGORITHM, key, Buffer.from(ivHex,'hex'));
  decipher.setAuthTag(Buffer.from(tagHex,'hex'));
  return decipher.update(Buffer.from(encHex,'hex')) + decipher.final('utf8');
}

async function getAppEnvPath(appUrl) {
  return path.join(CONFIG.APPS_DIR, appUrl, '.env.encrypted');
}

// GET /api/admin/apps/:appUrl/env
app.get('/api/admin/apps/:appUrl/env', requireAuth, async (req, res) => {
  try {
    const envPath = await getAppEnvPath(req.params.appUrl);
    if (!await fs.pathExists(envPath)) return res.json({ success: true, env: {} });
    const encrypted = await fs.readFile(envPath, 'utf8');
    const raw = decryptEnv(encrypted.trim());
    const env = {};
    raw.split('\n').forEach(line => {
      const m = line.match(/^([^=]+)=(.*)$/);
      if (m) env[m[1].trim()] = m[2].trim();
    });
    res.json({ success: true, env });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// PUT /api/admin/apps/:appUrl/env
app.put('/api/admin/apps/:appUrl/env', requireAuth, async (req, res) => {
  try {
    const { env } = req.body; // { KEY: 'VALUE', ... }
    const envPath = await getAppEnvPath(req.params.appUrl);
    const raw = Object.entries(env).map(([k,v]) => `${k}=${v}`).join('\n');
    const encrypted = encryptEnv(raw);
    await fs.ensureDir(path.dirname(envPath));
    await fs.writeFile(envPath, encrypted, 'utf8');
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// DELETE /api/admin/apps/:appUrl/env
app.delete('/api/admin/apps/:appUrl/env', requireAuth, async (req, res) => {
  try {
    const envPath = await getAppEnvPath(req.params.appUrl);
    if (await fs.pathExists(envPath)) await fs.remove(envPath);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});


// ===== Anthropic Admin API 사용량 조회 =====
// ── 모델별 토큰 단가 (USD / 1M tokens) ──────────────────────────
const TOKEN_PRICING = {
  'claude-sonnet-4-6':         { in: 3.0,   out: 15.0,  provider: 'anthropic' },
  'claude-opus-4-6':           { in: 15.0,  out: 75.0,  provider: 'anthropic' },
  'claude-haiku-4-5-20251001': { in: 0.8,   out: 4.0,   provider: 'anthropic' },
  'claude-opus-4-5':           { in: 15.0,  out: 75.0,  provider: 'anthropic' },
  'claude-sonnet-4-5':         { in: 3.0,   out: 15.0,  provider: 'anthropic' },
  'gpt-4o':                    { in: 2.5,   out: 10.0,  provider: 'openai' },
  'gpt-4o-mini':               { in: 0.15,  out: 0.6,   provider: 'openai' },
  'o3':                        { in: 10.0,  out: 40.0,  provider: 'openai' },
  'o4-mini':                   { in: 1.1,   out: 4.4,   provider: 'openai' },
  'gemini-2.5-pro':            { in: 1.25,  out: 10.0,  provider: 'google' },
  'gemini-2.5-flash':          { in: 0.15,  out: 0.6,   provider: 'google' },
  'gemini-2.0-flash':          { in: 0.1,   out: 0.4,   provider: 'google' },
  'gemini-1.5-pro':            { in: 1.25,  out: 5.0,   provider: 'google' },
};

function estimateCost(model, inputTokens, outputTokens) {
  const p = TOKEN_PRICING[model];
  if (!p) return 0;
  return (inputTokens / 1_000_000) * p.in + (outputTokens / 1_000_000) * p.out;
}

function getProvider(model) {
  if (!model) return 'anthropic';
  // OpenAI: gpt-*, o1*, o3*, o4* (reasoning 모델 포함)
  if (model.startsWith('gpt-') || model.startsWith('o1') ||
      model.startsWith('o3')   || model.startsWith('o4')) return 'openai';
  if (model.startsWith('gemini-')) return 'google';
  return 'anthropic';
}

app.get('/api/admin/ai-usage', requireAuth, async (req, res) => {
  try {
    const now = new Date();
    const monthStart = new Date(now.getFullYear(), now.getMonth(), 1).toISOString().split('T')[0];
    const today = now.toISOString().split('T')[0];

    // 설정 로드 (API 키들)
    const settings = await fs.pathExists(CONFIG.SETTINGS_FILE)
      ? await fs.readJson(CONFIG.SETTINGS_FILE).catch(() => ({})) : {};

    // ① 로컬 로그 집계 ───────────────────────────────────────────
    let localLog = [];
    if (await fs.pathExists(CONFIG.AI_LOG_FILE)) {
      localLog = await fs.readJson(CONFIG.AI_LOG_FILE).catch(() => []);
    }
    const monthlyLog = localLog.filter(e => e.date >= monthStart && e.date <= today);

    const byApp      = {};
    const byDate     = {};
    const byModel    = {};
    const byProvider = { anthropic: { input:0, output:0, requests:0, cost:0 },
                         openai:    { input:0, output:0, requests:0, cost:0 },
                         google:    { input:0, output:0, requests:0, cost:0 } };

    monthlyLog.forEach(e => {
      const prov = e.provider || getProvider(e.model);
      const cost = estimateCost(e.model, e.input_tokens||0, e.output_tokens||0);

      // 앱별
      if (!byApp[e.app]) byApp[e.app] = { input:0, output:0, requests:0, cost:0 };
      byApp[e.app].input    += e.input_tokens  || 0;
      byApp[e.app].output   += e.output_tokens || 0;
      byApp[e.app].requests += 1;
      byApp[e.app].cost     += cost;

      // 날짜별
      if (!byDate[e.date]) byDate[e.date] = { input:0, output:0, requests:0, cost:0 };
      byDate[e.date].input    += e.input_tokens  || 0;
      byDate[e.date].output   += e.output_tokens || 0;
      byDate[e.date].requests += 1;
      byDate[e.date].cost     += cost;

      // 모델별
      if (!byModel[e.model]) byModel[e.model] = { input:0, output:0, requests:0, cost:0, provider: prov };
      byModel[e.model].input    += e.input_tokens  || 0;
      byModel[e.model].output   += e.output_tokens || 0;
      byModel[e.model].requests += 1;
      byModel[e.model].cost     += cost;

      // 프로바이더별
      if (byProvider[prov]) {
        byProvider[prov].input    += e.input_tokens  || 0;
        byProvider[prov].output   += e.output_tokens || 0;
        byProvider[prov].requests += 1;
        byProvider[prov].cost     += cost;
      }
    });

    const totalCost = Object.values(byProvider).reduce((s,p) => s + p.cost, 0);
    const localStats = { byApp, byDate, byModel, byProvider, totalCost,
                         totalEntries: monthlyLog.length };

    // ② Anthropic Admin API (공식 데이터) ────────────────────────
    let anthropicUsage = null;
    const adminApiKey = settings.anthropicAdminApiKey || null;
    if (adminApiKey) {
      try {
        const nodeFetch = globalThis.fetch || (await import('node-fetch')).default;
        const usageRes = await nodeFetch(
          `https://api.anthropic.com/v1/usage?start_time=${monthStart}T00:00:00Z&end_time=${today}T23:59:59Z`,
          { headers: { 'x-api-key': adminApiKey, 'anthropic-version': '2023-06-01' } }
        );
        if (usageRes.ok) anthropicUsage = await usageRes.json();
        else console.warn('[AI Usage] Anthropic Admin API 오류:', (await usageRes.json().catch(()=>({}))).error?.message);
      } catch(e) { console.warn('[AI Usage] Anthropic Admin API 실패:', e.message); }
    }

    // ③ OpenAI Usage API (Organization API Key 필요) ──────────────
    let openaiUsage = null;
    const openaiKey = process.env.OPENAI_API_KEY || settings.openaiApiKey || null;
    if (openaiKey && byProvider.openai.requests > 0) {
      try {
        const nodeFetch = globalThis.fetch || (await import('node-fetch')).default;
        // OpenAI /v1/organization/usage/completions (2024.11+ 지원)
        const oaiRes = await nodeFetch(
          `https://api.openai.com/v1/organization/usage/completions?start_time=${Math.floor(new Date(monthStart).getTime()/1000)}&limit=30`,
          { headers: { 'Authorization': 'Bearer ' + openaiKey, 'Content-Type': 'application/json' } }
        );
        if (oaiRes.ok) {
          const oaiData = await oaiRes.json();
          // 집계
          const totalIn  = oaiData.data?.reduce((s,b) => s + (b.input_tokens||0), 0) || 0;
          const totalOut = oaiData.data?.reduce((s,b) => s + (b.output_tokens||0), 0) || 0;
          openaiUsage = { total_input_tokens: totalIn, total_output_tokens: totalOut,
                          source: 'official', raw: oaiData };
        } else {
          // API 미지원 or 권한 없음 → 로컬 로그 사용
          openaiUsage = { ...byProvider.openai, source: 'local_log',
                          note: 'OpenAI Organization API 미지원 → 로컬 로그 기반 추정' };
        }
      } catch(e) {
        openaiUsage = { ...byProvider.openai, source: 'local_log', note: e.message };
      }
    } else if (byProvider.openai.requests > 0) {
      openaiUsage = { ...byProvider.openai, source: 'local_log' };
    }

    // ④ Google Gemini — 공식 Usage API 없음 → 로컬 로그 ──────────
    let googleUsage = null;
    if (byProvider.google.requests > 0) {
      googleUsage = { ...byProvider.google, source: 'local_log',
                      note: 'Google AI Studio는 공식 Usage API 미제공 → 로컬 로그 기반 추정' };
    }

    res.json({
      success: true,
      local:        localStats,
      anthropic:    anthropicUsage,
      openai:       openaiUsage,
      google:       googleUsage,
      hasAdminKey:  !!adminApiKey,
      hasOpenaiKey: !!openaiKey,
      hasGoogleKey: !!(process.env.GOOGLE_API_KEY || settings.googleApiKey),
      pricing:      TOKEN_PRICING,
    });

  } catch (e) {
    console.error('[AI Usage] 조회 실패:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ===== ★ AI 배치 API (50% 할인 — 실시간 불필요한 대량 생성) =====
// 내부 IP 체크 공통 미들웨어
function requireInternalIp(req, res, next) {
  const clientIp = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').replace('::ffff:', '');
  if (clientIp !== '127.0.0.1' && clientIp !== '::1' && clientIp !== 'localhost') {
    return res.status(403).json({ error: '내부 호출만 허용됩니다' });
  }
  next();
}

// 배치 로그 로드/저장 헬퍼
async function loadBatchLog() {
  if (await fs.pathExists(CONFIG.BATCH_LOG_FILE)) {
    return await fs.readJson(CONFIG.BATCH_LOG_FILE).catch(() => []);
  }
  return [];
}
async function saveBatchLog(log) {
  await fs.ensureDir(path.dirname(CONFIG.BATCH_LOG_FILE));
  await fs.writeJson(CONFIG.BATCH_LOG_FILE, log, { spaces: 2 });
}

// ① 배치 생성: POST /ai/batch/create
// body: { requests: [{ custom_id, system, userPrompt, max_tokens }], app_id, model }
app.post('/ai/batch/create', requireInternalIp, async (req, res) => {
  try {
    let apiKey = process.env.ANTHROPIC_API_KEY || null;
    let globalDefaultModel = null;
    if (await fs.pathExists(CONFIG.SETTINGS_FILE)) {
      const s = await fs.readJson(CONFIG.SETTINGS_FILE).catch(() => ({}));
      if (!apiKey) apiKey = s.anthropicApiKey || null;
      globalDefaultModel = s.defaultModel || null;  // ★ 글로벌 기본 모델 항상 읽음
    }
    if (!apiKey) return res.status(500).json({ error: 'ANTHROPIC_API_KEY가 설정되지 않았습니다' });

    const { requests, app_id = 'unknown', model } = req.body;
    if (!requests || !Array.isArray(requests) || requests.length === 0) {
      return res.status(400).json({ error: 'requests 배열이 필요합니다' });
    }

    // 앱별 기본 모델 로드
    let resolvedModel = model || globalDefaultModel || 'claude-sonnet-4-6';
    let batchAppRegistered = false;
    let batchAppModel = null;
    try {
      const appsConfig = path.join(CONFIG.APPS_DIR, 'apps.json');
      if (await fs.pathExists(appsConfig)) {
        const cfg = await fs.readJson(appsConfig);
        const appInfo = cfg.apps?.find(a => a.url === app_id);
        if (appInfo) {
          batchAppRegistered = true;
          batchAppModel = appInfo.ai_model || null;
          if (batchAppModel) resolvedModel = model || batchAppModel;
        }
      }
    } catch(_) {}

    // ★ 등록된 앱인데 ai_model 미설정이면 차단
    if (batchAppRegistered && !batchAppModel && !model) {
      return res.status(403).json({
        error: `[${app_id}] AI가 비활성화된 앱입니다. 앱매니저에서 AI 모델을 설정하세요.`
      });
    }

    // Anthropic Batch API 요청 포맷 변환
    // 배치 + 캐싱 병행: 1시간 캐시 TTL 사용 (배치 처리 시간 고려)
    const batchRequests = requests.map(r => ({
      custom_id: r.custom_id,
      params: {
        model: resolvedModel,
        max_tokens: r.max_tokens || 4000,
        ...(r.system ? {
          system: [
            { type: 'text', text: r.system },
            // ★ 시스템 프롬프트 캐시 — 배치 내 동일 system은 1h 캐시 적용
            // 주의: 배치 내 모든 요청의 system이 동일해야 캐시 히트
          ]
        } : {}),
        messages: [{ role: 'user', content: r.userPrompt || r.prompt || '' }]
      }
    }));

    const nodeFetch = globalThis.fetch || (await import('node-fetch')).default;
    const response = await nodeFetch('https://api.anthropic.com/v1/messages/batches', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({ requests: batchRequests })
    });

    const data = await response.json();
    if (!response.ok) throw new Error(data.error?.message || 'Batch API 오류');

    // 배치 로그 기록
    const log = await loadBatchLog();
    log.push({
      batch_id: data.id,
      app_id,
      model: resolvedModel,
      request_count: requests.length,
      status: 'in_progress',
      created_at: new Date().toISOString(),
      custom_ids: requests.map(r => r.custom_id)
    });
    await saveBatchLog(log);

    console.log(`[Batch] 생성됨: ${data.id} (${requests.length}건, 앱: ${app_id})`);
    res.json({ success: true, batch_id: data.id, request_count: requests.length, status: 'in_progress' });

  } catch (e) {
    console.error('[Batch] 생성 실패:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ② 배치 상태 확인: GET /ai/batch/status/:batchId
app.get('/ai/batch/status/:batchId', requireInternalIp, async (req, res) => {
  try {
    let apiKey = process.env.ANTHROPIC_API_KEY || null;
    if (!apiKey && await fs.pathExists(CONFIG.SETTINGS_FILE)) {
      const s = await fs.readJson(CONFIG.SETTINGS_FILE).catch(() => ({}));
      apiKey = s.anthropicApiKey || null;
    }
    if (!apiKey) return res.status(500).json({ error: 'ANTHROPIC_API_KEY가 설정되지 않았습니다' });

    const { batchId } = req.params;
    const nodeFetch = globalThis.fetch || (await import('node-fetch')).default;
    const response = await nodeFetch(`https://api.anthropic.com/v1/messages/batches/${batchId}`, {
      headers: { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' }
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error?.message || '배치 조회 오류');

    res.json({
      batch_id: batchId,
      status: data.processing_status,  // 'in_progress' | 'ended'
      counts: data.request_counts,     // { processing, succeeded, errored, canceled, expired }
      ended_at: data.ended_at
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ③ 배치 결과 수신: GET /ai/batch/results/:batchId
app.get('/ai/batch/results/:batchId', requireInternalIp, async (req, res) => {
  try {
    let apiKey = process.env.ANTHROPIC_API_KEY || null;
    if (!apiKey && await fs.pathExists(CONFIG.SETTINGS_FILE)) {
      const s = await fs.readJson(CONFIG.SETTINGS_FILE).catch(() => ({}));
      apiKey = s.anthropicApiKey || null;
    }
    if (!apiKey) return res.status(500).json({ error: 'ANTHROPIC_API_KEY가 설정되지 않았습니다' });

    const { batchId } = req.params;
    const nodeFetch = globalThis.fetch || (await import('node-fetch')).default;

    // 상태 확인 먼저
    const statusRes = await nodeFetch(`https://api.anthropic.com/v1/messages/batches/${batchId}`, {
      headers: { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' }
    });
    const statusData = await statusRes.json();
    if (statusData.processing_status !== 'ended') {
      return res.json({ ready: false, status: statusData.processing_status, counts: statusData.request_counts });
    }

    // 결과 JSONL 수신
    const resultsRes = await nodeFetch(`https://api.anthropic.com/v1/messages/batches/${batchId}/results`, {
      headers: { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' }
    });
    const text = await resultsRes.text();

    // JSONL 파싱
    const results = text.trim().split('\n').map(line => {
      try {
        const r = JSON.parse(line);
        return {
          custom_id: r.custom_id,
          success: r.result?.type === 'succeeded',
          content: r.result?.message?.content?.[0]?.text || null,
          usage: r.result?.message?.usage || null,
          error: r.result?.error || null
        };
      } catch (_) { return null; }
    }).filter(Boolean);

    // 배치 로그 상태 업데이트
    const log = await loadBatchLog();
    const entry = log.find(e => e.batch_id === batchId);
    if (entry) {
      entry.status = 'done';
      entry.done_at = new Date().toISOString();
      entry.succeeded = results.filter(r => r.success).length;
      await saveBatchLog(log);
    }

    // AI 사용량 로그 기록 (배치 결과도 통합 집계)
    try {
      const appId = entry?.app_id || 'batch-unknown';
      const model = entry?.model || 'unknown';
      const usageLog = await fs.pathExists(CONFIG.AI_LOG_FILE)
        ? await fs.readJson(CONFIG.AI_LOG_FILE).catch(() => []) : [];
      for (const r of results) {
        if (r.success && r.usage) {
          usageLog.push({
            ts: new Date().toISOString(),
            date: new Date().toISOString().split('T')[0],
            app: appId, model, provider: 'anthropic',
            input_tokens: r.usage.input_tokens || 0,
            output_tokens: r.usage.output_tokens || 0,
            batch: true
          });
        }
      }
      if (usageLog.length > 10000) usageLog.splice(0, usageLog.length - 10000);
      await fs.writeJson(CONFIG.AI_LOG_FILE, usageLog);
    } catch(_) {}

    console.log(`[Batch] 결과 수신: ${batchId} (성공: ${results.filter(r=>r.success).length}/${results.length}건)`);
    res.json({ ready: true, batch_id: batchId, results, total: results.length });

  } catch (e) {
    console.error('[Batch] 결과 수신 실패:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ④ 배치 목록 조회 (관리자용): GET /api/admin/ai-batches
app.get('/api/admin/ai-batches', requireAuth, async (req, res) => {
  try {
    const log = await loadBatchLog();
    // 최신순 정렬
    log.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    res.json({ success: true, batches: log.slice(0, 100) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===== ★ 배치 완료 폴러 (30초마다 — 내보내기센터용 알림) =====
function startBatchPoller() {
  setInterval(async () => {
    try {
      let apiKey = process.env.ANTHROPIC_API_KEY || null;
      if (!apiKey && await fs.pathExists(CONFIG.SETTINGS_FILE)) {
        const s = await fs.readJson(CONFIG.SETTINGS_FILE).catch(() => ({}));
        apiKey = s.anthropicApiKey || null;
      }
      if (!apiKey) return;

      const log = await loadBatchLog();
      const pending = log.filter(e => e.status === 'in_progress');
      if (pending.length === 0) return;

      const nodeFetch = globalThis.fetch || (await import('node-fetch')).default;

      for (const entry of pending) {
        try {
          const r = await nodeFetch(`https://api.anthropic.com/v1/messages/batches/${entry.batch_id}`, {
            headers: { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' }
          });
          const data = await r.json();
          if (data.processing_status === 'ended') {
            entry.status = 'ended_pending_fetch';
            console.log(`[Batch Poller] 완료 감지: ${entry.batch_id} (앱: ${entry.app_id})`);
            // TODO: Socket.io 연동 시 io.emit('batch_done', { batch_id: entry.batch_id, app_id: entry.app_id });
          }
        } catch(_) {}
      }
      await saveBatchLog(log);
    } catch(_) {}
  }, 30_000);
}

// ===== 서버 시작 시 기존 백엔드 앱들 자동 실행 =====
async function initializeBackendServers() {
  try {
    const appsConfigPath = path.join(CONFIG.APPS_DIR, 'apps.json');
    if (!await fs.pathExists(appsConfigPath)) return;
    
    const config = await fs.readJson(appsConfigPath);
    
    for (const appItem of config.apps) {
      if (appItem.active && appItem.hasBackend && appItem.port) {
        console.log(`초기화: ${appItem.url} 백엔드 서버 시작 (포트: ${appItem.port})...`);
        await startBackendServer(appItem.url, appItem.port);
      }
    }
  } catch (error) {
    console.error('백엔드 서버 초기화 실패:', error.message);
  }
}

// ===== 다운로드 파일 관리 API =====

// 다운로드 파일 목록 조회
app.get('/api/admin/downloads', requireAuth, async (req, res) => {
  try {
    // 디렉토리 없으면 생성 후 빈 목록 반환 (500 방지)
    await fs.ensureDir(CONFIG.DOWNLOADS_DIR).catch(() => {});
    const dirExists = await fs.pathExists(CONFIG.DOWNLOADS_DIR);
    if (!dirExists) return res.json({ success: true, files: [] });
    const files = await fs.readdir(CONFIG.DOWNLOADS_DIR);
    
    const fileList = [];
    for (const file of files) {
      const filePath = path.join(CONFIG.DOWNLOADS_DIR, file);
      const stat = await fs.stat(filePath);
      if (stat.isFile()) {
        fileList.push({
          name: file,
          size: stat.size,
          sizeFormatted: formatFileSize(stat.size),
          uploadedAt: stat.mtime,
          url: `/downloads/${file}`
        });
      }
    }
    
    // 최신순 정렬
    fileList.sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));
    
    res.json({ success: true, files: fileList });
  } catch (error) {
    res.status(500).json({ error: '파일 목록 조회 실패: ' + error.message });
  }
});

// 다운로드 파일 업로드
app.post('/api/admin/downloads', requireAuth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: '파일을 선택하세요' });
    }
    
    await fs.ensureDir(CONFIG.DOWNLOADS_DIR);
    
    const originalName = req.file.originalname;
    const destPath = path.join(CONFIG.DOWNLOADS_DIR, originalName);
    
    // 이미 존재하면 덮어쓰기
    await fs.move(req.file.path, destPath, { overwrite: true });
    
    const stat = await fs.stat(destPath);
    
    res.json({
      success: true,
      file: {
        name: originalName,
        size: stat.size,
        sizeFormatted: formatFileSize(stat.size),
        uploadedAt: stat.mtime,
        url: `/downloads/${originalName}`
      }
    });
  } catch (error) {
    res.status(500).json({ error: '파일 업로드 실패: ' + error.message });
  }
});

// 다운로드 파일 삭제
app.delete('/api/admin/downloads/:filename', requireAuth, async (req, res) => {
  try {
    const { filename } = req.params;
    const filePath = path.join(CONFIG.DOWNLOADS_DIR, filename);
    
    if (!await fs.pathExists(filePath)) {
      return res.status(404).json({ error: '파일을 찾을 수 없습니다' });
    }
    
    await fs.remove(filePath);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: '파일 삭제 실패: ' + error.message });
  }
});

// 다운로드 파일 서빙 (공개)
app.get('/downloads/:filename', async (req, res) => {
  try {
    const { filename } = req.params;
    const filePath = path.join(CONFIG.DOWNLOADS_DIR, filename);
    
    if (!await fs.pathExists(filePath)) {
      return res.status(404).json({ error: '파일을 찾을 수 없습니다' });
    }

    // CORS 허용 (유아스토리 등 외부 도메인에서 접근 가능하도록)
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET');

    // 파일 확장자별 Content-Type 설정 후 sendFile로 인라인 서빙
    const ext = filename.split('.').pop().toLowerCase();
    const mimeMap = {
      'json': 'application/json',
      'jpg': 'image/jpeg', 'jpeg': 'image/jpeg',
      'png': 'image/png', 'gif': 'image/gif',
      'webp': 'image/webp', 'svg': 'image/svg+xml',
      'mp4': 'video/mp4', 'webm': 'video/webm',
    };
    if (mimeMap[ext]) res.setHeader('Content-Type', mimeMap[ext]);

    return res.sendFile(filePath);
  } catch (error) {
    res.status(500).json({ error: '파일 서빙 실패: ' + error.message });
  }
});

// ===== 이미지 폴더 / 다운로드 파일 카테고리 매핑 API =====

// GET  /api/admin/image-folder-categories
app.get('/api/admin/image-folder-categories', requireAuth, async (req, res) => {
  try {
    const cats = await fs.pathExists(CONFIG.IMAGE_CATS_FILE)
      ? await fs.readJson(CONFIG.IMAGE_CATS_FILE) : {};
    res.json({ success: true, categories: cats });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// PUT  /api/admin/image-folder-categories  { folder, categoryId }
app.put('/api/admin/image-folder-categories', requireAuth, async (req, res) => {
  try {
    const { folder, categoryId } = req.body;
    if (!folder) return res.status(400).json({ error: 'folder 필요' });
    const cats = await fs.pathExists(CONFIG.IMAGE_CATS_FILE)
      ? await fs.readJson(CONFIG.IMAGE_CATS_FILE) : {};
    if (categoryId) cats[folder] = categoryId;
    else delete cats[folder];
    await fs.ensureDir(path.dirname(CONFIG.IMAGE_CATS_FILE));
    await fs.writeJson(CONFIG.IMAGE_CATS_FILE, cats, { spaces: 2 });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// GET  /api/admin/download-file-categories
app.get('/api/admin/download-file-categories', requireAuth, async (req, res) => {
  try {
    const cats = await fs.pathExists(CONFIG.DOWNLOAD_CATS_FILE)
      ? await fs.readJson(CONFIG.DOWNLOAD_CATS_FILE) : {};
    res.json({ success: true, categories: cats });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// PUT  /api/admin/download-file-categories  { filename, categoryId }
app.put('/api/admin/download-file-categories', requireAuth, async (req, res) => {
  try {
    const { filename, categoryId } = req.body;
    if (!filename) return res.status(400).json({ error: 'filename 필요' });
    const cats = await fs.pathExists(CONFIG.DOWNLOAD_CATS_FILE)
      ? await fs.readJson(CONFIG.DOWNLOAD_CATS_FILE) : {};
    if (categoryId) cats[filename] = categoryId;
    else delete cats[filename];
    await fs.ensureDir(path.dirname(CONFIG.DOWNLOAD_CATS_FILE));
    await fs.writeJson(CONFIG.DOWNLOAD_CATS_FILE, cats, { spaces: 2 });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// 파일 크기 포맷
function formatFileSize(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// ===== 원본 ZIP 다운로드 API =====
app.get('/api/admin/download/:appUrl/:type', async (req, res) => {
  // 헤더 또는 쿼리에서 토큰 확인
  const token = req.headers['x-auth-token'] || req.query.token;
  
  if (!token || !sessions.has(token)) {
    return res.status(401).json({ error: '로그인이 필요합니다' });
  }
  
  const session = sessions.get(token);
  if (Date.now() - session.createdAt > 24 * 60 * 60 * 1000) {
    sessions.delete(token);
    return res.status(401).json({ error: '세션이 만료되었습니다' });
  }

  const { appUrl, type } = req.params;
  
  if (!['frontend', 'backend'].includes(type)) {
    return res.status(400).json({ error: '유효하지 않은 타입입니다' });
  }
  
  try {
    const zipPath = path.join(CONFIG.APP_ZIPS_DIR, appUrl, `${type}.zip`);
    
    if (!await fs.pathExists(zipPath)) {
      return res.status(404).json({ error: `${type} ZIP 파일이 없습니다` });
    }
    
    const fileName = `${appUrl}-${type}.zip`;
    res.download(zipPath, fileName);
  } catch (error) {
    res.status(500).json({ error: '다운로드 실패: ' + error.message });
  }
});

// ===== 앱 ZIP 존재 여부 확인 API =====
app.get('/api/admin/zips/:appUrl', requireAuth, async (req, res) => {
  const { appUrl } = req.params;
  
  try {
    const appZipsPath = path.join(CONFIG.APP_ZIPS_DIR, appUrl);
    
    const hasFrontend = await fs.pathExists(path.join(appZipsPath, 'frontend.zip'));
    const hasBackend = await fs.pathExists(path.join(appZipsPath, 'backend.zip'));
    
    res.json({ hasFrontend, hasBackend });
  } catch (error) {
    res.status(500).json({ error: '확인 실패: ' + error.message });
  }
});

// ===== IP 허용 목록 조회 API =====
app.get('/api/admin/ip-config', requireAuth, async (req, res) => {
  try {
    const ipConfig = await getIpConfig();
    res.json(ipConfig);
  } catch (error) {
    res.status(500).json({ error: 'IP 설정 조회 실패: ' + error.message });
  }
});

// ===== IP 추가 API =====
app.post('/api/admin/ip-config', requireAuth, async (req, res) => {
  const { ip, ips } = req.body;  // 단일 ip 또는 복수 ips 배열 지원
  
  // 추가할 IP 목록 생성
  let ipsToAdd = [];
  if (ips && Array.isArray(ips)) {
    ipsToAdd = ips;
  } else if (ip) {
    ipsToAdd = [ip];
  } else {
    return res.status(400).json({ error: 'IP 주소를 입력하세요' });
  }
  
  // IP 형식 검증 (IPv4)
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  for (const ipAddr of ipsToAdd) {
    if (!ipv4Regex.test(ipAddr)) {
      return res.status(400).json({ error: `유효하지 않은 IP 형식: ${ipAddr}` });
    }
  }
  
  try {
    const ipConfig = await getIpConfig();
    
    // 현재 접속자 IP 추출 (첫 IP 추가 시 자동 포함)
    const clientIp = getClientIp(req);
    const normalizedClientIp = clientIp === '::1' ? '127.0.0.1' : clientIp.replace('::ffff:', '');
    
    // 목록이 비어있으면 현재 접속 IP도 자동 추가
    if (ipConfig.allowedIps.length === 0 && !ipsToAdd.includes(normalizedClientIp)) {
      ipsToAdd.unshift(normalizedClientIp);
    }
    
    // 중복 제외하고 추가
    let addedCount = 0;
    for (const ipAddr of ipsToAdd) {
      if (!ipConfig.allowedIps.includes(ipAddr)) {
        ipConfig.allowedIps.push(ipAddr);
        addedCount++;
      }
    }
    
    if (addedCount === 0) {
      return res.status(400).json({ error: '이미 등록된 IP입니다' });
    }
    
    await saveIpConfig(ipConfig);
    
    res.json({ success: true, allowedIps: ipConfig.allowedIps, addedCount });
  } catch (error) {
    res.status(500).json({ error: 'IP 추가 실패: ' + error.message });
  }
});

// ===== IP 삭제 API =====
app.delete('/api/admin/ip-config/:ip', requireAuth, async (req, res) => {
  const { ip } = req.params;
  
  try {
    const ipConfig = await getIpConfig();
    
    const index = ipConfig.allowedIps.indexOf(ip);
    if (index === -1) {
      return res.status(404).json({ error: '등록되지 않은 IP입니다' });
    }
    
    ipConfig.allowedIps.splice(index, 1);
    await saveIpConfig(ipConfig);
    
    res.json({ success: true, allowedIps: ipConfig.allowedIps });
  } catch (error) {
    res.status(500).json({ error: 'IP 삭제 실패: ' + error.message });
  }
});

// ===== 현재 접속 IP 확인 API =====
app.get('/api/admin/my-ip', requireAuth, (req, res) => {
  const clientIp = getClientIp(req);
  const normalizedIp = clientIp === '::1' ? '127.0.0.1' : clientIp.replace('::ffff:', '');
  res.json({ ip: normalizedIp });
});


// ===== 서버 시작 =====
app.listen(PORT, async () => {
  console.log(`====================================`);
  console.log(`앱 관리 서버가 포트 ${PORT}에서 실행 중입니다`);
  console.log(`초기 계정: ${CONFIG.DEFAULT_USERNAME} / ${CONFIG.DEFAULT_PASSWORD}`);
  console.log(`앱 백엔드 포트 범위: ${CONFIG.PORT_START} ~ ${CONFIG.PORT_END}`);
  console.log(`====================================`);
  console.log(`★ 공통 프록시: /api/apps/{앱URL}/* → 각 앱 백엔드로 자동 전달`);
  console.log(`★ 수정사항: 프록시 라우트가 body parser보다 먼저 처리됨`);
  console.log(`====================================`);

  // ★ 필수 디렉토리 자동 생성 (non-blocking — 서버 기동에 영향 없음)
  const requiredDirs = [
    CONFIG.APPS_DIR,
    CONFIG.APP_ZIPS_DIR,
    CONFIG.BACKUPS_DIR,
    CONFIG.DOWNLOADS_DIR || '/var/www/downloads',
    path.dirname(CONFIG.SETTINGS_FILE),
    path.dirname(CONFIG.AUTH_FILE),
    path.dirname(CONFIG.AI_LOG_FILE),
  ];

  // 서버 기동을 블록하지 않도록 Promise.allSettled 사용
  Promise.allSettled(
    requiredDirs.map(async dir => {
      try {
        await fs.ensureDir(dir);
      } catch (e) {
        if (e.code === 'EACCES') {
          // 타임아웃 10초 — sudo가 password 요구하면 hang 방지
          const timer = setTimeout(() => {}, 0); // placeholder
          try {
            await Promise.race([
              execPromise(`sudo mkdir -p "${dir}" && sudo chown -R ${process.env.USER || 'ubuntu'} "${dir}"`),
              new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 10000))
            ]);
            console.log(`✅ 디렉토리 생성: ${dir}`);
          } catch (sudoErr) {
            console.error(`⚠️  디렉토리 생성 실패: ${dir}`);
            console.error(`   → 서버에서 직접 실행: sudo mkdir -p ${dir} && sudo chown -R $(whoami) ${dir}`);
          } finally {
            clearTimeout(timer);
          }
        }
      }
    })
  ).then(() => console.log('디렉토리 초기화 완료'));

  await initializeBackendServers();
  startBatchPoller();  // ★ 배치 완료 폴러 시작
});