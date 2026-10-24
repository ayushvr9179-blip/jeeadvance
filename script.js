'use strict';

/* Obsidian Vault
   - Two independent password-derived AES-GCM keys
   - PBKDF2-SHA-256 with per-locker random salts
   - Video bytes and filenames encrypted before IndexedDB storage
   - Passwords and decryption keys are never persisted
*/
const CONFIG_KEY = 'obsidianVaultConfigV1';
const DB_NAME = 'obsidianVaultDB';
const DB_VERSION = 1;
const STORE_NAME = 'encryptedVideos';
const PBKDF2_ITERATIONS = 310000;
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const $ = (id) => document.getElementById(id);

const views = { setup: $('setupView'), login: $('loginView'), vault: $('vaultView') };
let db;
let activeLocker = null;
let activeKey = null;
let objectUrls = new Map();
let pendingDeleteId = null;
let toastTimeout;

function showView(name) {
  Object.entries(views).forEach(([key, el]) => el.classList.toggle('hidden', key !== name));
  $('lockNowBtn').classList.toggle('hidden', name !== 'vault');
}
function readConfig() {
  try { return JSON.parse(localStorage.getItem(CONFIG_KEY) || 'null'); }
  catch { return null; }
}
function randomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}
function bytesToBase64(bytes) {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  return btoa(binary);
}
function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
async function deriveKey(password, salt) {
  const material = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function encryptBytes(key, bytes) {
  const iv = randomBytes(12);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes);
  return { iv: bytesToBase64(iv), ciphertext };
}
async function decryptBytes(key, ivBase64, ciphertext) {
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: base64ToBytes(ivBase64) }, key, ciphertext);
}
async function createLocker(password, number) {
  const salt = randomBytes(16);
  const key = await deriveKey(password, salt);
  const sentinel = encoder.encode(`obsidian-vault-locker-${number}-auth-v1`);
  const verifier = await encryptBytes(key, sentinel);
  return { salt: bytesToBase64(salt), verifierIv: verifier.iv, verifierCipher: bytesToBase64(new Uint8Array(verifier.ciphertext)) };
}
async function authenticateLocker(password, lockerConfig, number) {
  const key = await deriveKey(password, base64ToBytes(lockerConfig.salt));
  const plain = await decryptBytes(key, lockerConfig.verifierIv, base64ToBytes(lockerConfig.verifierCipher));
  if (decoder.decode(plain) !== `obsidian-vault-locker-${number}-auth-v1`) throw new Error('Invalid password');
  return key;
}
function openDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains(STORE_NAME)) {
        const store = database.createObjectStore(STORE_NAME, { keyPath: 'id' });
        store.createIndex('locker', 'locker', { unique: false });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error('Could not open local database'));
  });
}
function transaction(mode, action) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, mode);
    const store = tx.objectStore(STORE_NAME);
    let request;
    try { request = action(store); } catch (err) { reject(err); return; }
    tx.oncomplete = () => resolve(request ? request.result : undefined);
    tx.onerror = () => reject(tx.error || new Error('Database operation failed'));
    tx.onabort = () => reject(tx.error || new Error('Database operation aborted'));
  });
}
function getAllRecords() { return transaction('readonly', store => store.getAll()); }
function putRecord(record) { return transaction('readwrite', store => store.put(record)); }
function deleteRecord(id) { return transaction('readwrite', store => store.delete(id)); }
function bytesToMB(bytes) { return bytes < 1024 * 1024 ? `${Math.max(1, Math.round(bytes / 1024))} KB` : `${(bytes / (1024 * 1024)).toFixed(1)} MB`; }
function safeError(error) {
  if (error && error.name === 'QuotaExceededError') return 'This browser is out of storage space. Free some space and try again.';
  return error?.message || 'Something went wrong. Please try again.';
}
function showToast(message) {
  const toast = $('toast'); toast.textContent = message; toast.classList.add('show');
  clearTimeout(toastTimeout); toastTimeout = setTimeout(() => toast.classList.remove('show'), 3200);
}
function clearObjectUrls() {
  for (const url of objectUrls.values()) URL.revokeObjectURL(url);
  objectUrls.clear();
}
function lockVault() {
  clearObjectUrls();
  activeKey = null;
  activeLocker = null;
  $('loginPassword').value = '';
  $('searchInput').value = '';
  $('videoPlayer').pause(); $('videoPlayer').removeAttribute('src'); $('videoPlayer').load();
  $('playerModal').classList.add('hidden');
  showView('login');
}
function formatDate(timestamp) {
  try { return new Intl.DateTimeFormat(undefined, { year: 'numeric', month: 'short', day: 'numeric' }).format(new Date(timestamp)); }
  catch { return 'Saved video'; }
}
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
}
async function decryptMetadata(record) {
  const plain = await decryptBytes(activeKey, record.metaIv, record.encryptedMeta);
  return JSON.parse(decoder.decode(plain));
}
async function renderVideos() {
  if (!activeKey || activeLocker === null) return;
  const grid = $('videoGrid');
  grid.innerHTML = '';
  $('emptyState').classList.add('hidden');
  const all = await getAllRecords();
  const records = all.filter(record => record.locker === activeLocker).sort((a, b) => b.createdAt - a.createdAt);
  const prepared = [];
  for (const record of records) {
    try { prepared.push({ record, meta: await decryptMetadata(record) }); }
    catch (error) { console.error('Could not read encrypted metadata for record', record.id, error); }
  }
  const query = $('searchInput').value.trim().toLowerCase();
  const filtered = prepared.filter(item => item.meta.name.toLowerCase().includes(query));
  $('videoCount').textContent = records.length;
  $('storageUsed').textContent = bytesToMB(records.reduce((sum, record) => sum + (record.size || 0), 0));
  if (!filtered.length) {
    if (records.length && query) {
      grid.innerHTML = `<div class="empty-state" style="grid-column:1/-1"><h3>No matching videos</h3><p>Try a different search term.</p></div>`;
    } else {
      $('emptyState').classList.remove('hidden');
    }
    return;
  }
  for (const { record, meta } of filtered) {
    const card = document.createElement('article');
    card.className = 'video-card';
    card.innerHTML = `<div class="video-thumb"><button class="play-button" data-play="${record.id}" aria-label="Play ${escapeHtml(meta.name)}"><svg viewBox="0 0 24 24"><path d="M7 4.8c0-.8.9-1.3 1.6-.9l11 7.1a1.2 1.2 0 0 1 0 2L8.6 20.1c-.7.4-1.6-.1-1.6-.9V4.8Z"/></svg></button><span class="video-label">PRIVATE VIDEO</span><span class="video-chip">AES-256</span></div><div class="video-info"><p class="video-name" title="${escapeHtml(meta.name)}">${escapeHtml(meta.name)}</p><div class="video-meta"><span>${bytesToMB(record.size || 0)}</span><span>${formatDate(record.createdAt)}</span></div><div class="video-actions"><span>● Encrypted</span><div class="video-action-buttons"><button class="small-action" data-download="${record.id}" title="Decrypt and download" aria-label="Decrypt and download ${escapeHtml(meta.name)}"><svg viewBox="0 0 24 24"><path d="M12 3v12m-5-5 5 5 5-5M5 20h14"/></svg></button><button class="small-action delete" data-delete="${record.id}" title="Delete video" aria-label="Delete ${escapeHtml(meta.name)}"><svg viewBox="0 0 24 24"><path d="M4 7h16M10 11v6m4-6v6M6 7l1 13h10l1-13M9 7V4h6v3"/></svg></button></div></div></div>`;
    grid.appendChild(card);
  }
  grid.querySelectorAll('[data-play]').forEach(button => button.addEventListener('click', () => playVideo(button.dataset.play)));
  grid.querySelectorAll('[data-download]').forEach(button => button.addEventListener('click', () => downloadVideo(button.dataset.download)));
  grid.querySelectorAll('[data-delete]').forEach(button => button.addEventListener('click', () => askDelete(button.dataset.delete)));
}
async function findRecord(id) {
  const records = await getAllRecords();
  return records.find(record => record.id === id && record.locker === activeLocker);
}
async function decryptVideoRecord(record) {
  const plainBuffer = await decryptBytes(activeKey, record.videoIv, record.encryptedVideo);
  return new Blob([plainBuffer], { type: record.mimeType || 'video/mp4' });
}
async function playVideo(id) {
  try {
    const record = await findRecord(id);
    if (!record) throw new Error('Video not found in this locker.');
    showToast('Decrypting video for playback…');
    const blob = await decryptVideoRecord(record);
    const oldUrl = objectUrls.get(`player-${id}`);
    if (oldUrl) URL.revokeObjectURL(oldUrl);
    const url = URL.createObjectURL(blob);
    objectUrls.set(`player-${id}`, url);
    const meta = await decryptMetadata(record);
    $('playerTitle').textContent = meta.name;
    $('videoPlayer').src = url;
    $('playerModal').classList.remove('hidden');
    $('videoPlayer').play().catch(() => {});
  } catch (error) { showToast(`Could not open video: ${safeError(error)}`); }
}
function closePlayer() {
  $('videoPlayer').pause(); $('videoPlayer').removeAttribute('src'); $('videoPlayer').load(); $('playerModal').classList.add('hidden');
  for (const [key, url] of objectUrls.entries()) if (key.startsWith('player-')) { URL.revokeObjectURL(url); objectUrls.delete(key); }
}
async function downloadVideo(id) {
  try {
    const record = await findRecord(id);
    if (!record) throw new Error('Video not found in this locker.');
    showToast('Decrypting file…');
    const blob = await decryptVideoRecord(record);
    const meta = await decryptMetadata(record);
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = meta.name; document.body.appendChild(anchor); anchor.click(); anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
    showToast('Decrypted download started. Keep the downloaded file private.');
  } catch (error) { showToast(`Download failed: ${safeError(error)}`); }
}
function askDelete(id) {
  pendingDeleteId = id;
  $('confirmText').textContent = 'This encrypted file will be permanently removed from this browser. This cannot be undone.';
  $('confirmModal').classList.remove('hidden');
}
async function deletePendingVideo() {
  if (!pendingDeleteId) return;
  const id = pendingDeleteId; pendingDeleteId = null; $('confirmModal').classList.add('hidden');
  try { await deleteRecord(id); showToast('Encrypted video deleted.'); await renderVideos(); }
  catch (error) { showToast(`Could not delete video: ${safeError(error)}`); }
}
function setProgress(percent, label) {
  $('uploadProgressWrap').classList.remove('hidden'); $('progressBar').style.width = `${percent}%`;
  $('progressPercent').textContent = `${percent}%`; $('progressLabel').textContent = label;
}
async function importFiles(fileList) {
  const files = Array.from(fileList || []).filter(file => file.type.startsWith('video/'));
  if (!files.length) { showToast('Choose one or more video files.'); return; }
  if (!activeKey || activeLocker === null) return;
  $('addVideoBtn').disabled = true; $('emptyAddBtn').disabled = true;
  let completed = 0;
  try {
    for (const file of files) {
      if (!file.size) { showToast(`${file.name} is empty and was skipped.`); continue; }
      setProgress(Math.round(completed / files.length * 100), `Encrypting ${file.name}`);
      // Whole-file Web Crypto encryption uses memory proportional to the video size.
      // For very large videos, use smaller files or an encrypted chunked-storage implementation.
      const raw = await file.arrayBuffer();
      const [videoEncrypted, metaEncrypted] = await Promise.all([
        encryptBytes(activeKey, raw),
        encryptBytes(activeKey, encoder.encode(JSON.stringify({ name: file.name, type: file.type || 'video/mp4' })))
      ]);
      const record = {
        id: crypto.randomUUID(), locker: activeLocker, createdAt: Date.now(), size: file.size,
        mimeType: file.type || 'video/mp4', videoIv: videoEncrypted.iv, encryptedVideo: videoEncrypted.ciphertext,
        metaIv: metaEncrypted.iv, encryptedMeta: metaEncrypted.ciphertext
      };
      await putRecord(record);
      completed++;
      setProgress(Math.round(completed / files.length * 100), `Saved ${completed} of ${files.length} video${files.length === 1 ? '' : 's'}`);
    }
    showToast(`${completed} video${completed === 1 ? '' : 's'} encrypted and saved.`);
    await renderVideos();
  } catch (error) {
    console.error(error); showToast(`Import stopped: ${safeError(error)}`);
    try { await navigator.storage?.persist?.(); } catch {}
    await renderVideos();
  } finally {
    $('addVideoBtn').disabled = false; $('emptyAddBtn').disabled = false;
    setTimeout(() => $('uploadProgressWrap').classList.add('hidden'), 1300);
    $('fileInput').value = '';
  }
}

$('setupForm').addEventListener('submit', async event => {
  event.preventDefault(); $('setupError').textContent = '';
  const p1 = $('passOne').value, c1 = $('passOneConfirm').value, p2 = $('passTwo').value, c2 = $('passTwoConfirm').value;
  if (p1.length < 8 || p2.length < 8) { $('setupError').textContent = 'Each password must be at least 8 characters.'; return; }
  if (p1 !== c1 || p2 !== c2) { $('setupError').textContent = 'Each password and its confirmation must match.'; return; }
  if (p1 === p2) { $('setupError').textContent = 'Use two different passwords for the two lockers.'; return; }
  const submit = $('setupForm').querySelector('button[type="submit"]'); submit.disabled = true; submit.textContent = 'Creating encrypted vaults…';
  try {
    if (!crypto?.subtle || !indexedDB) throw new Error('This browser does not support the required secure storage features. Open the site through localhost or HTTPS in a modern browser.');
    const config = { version: 1, lockers: [await createLocker(p1, 1), await createLocker(p2, 2)] };
    localStorage.setItem(CONFIG_KEY, JSON.stringify(config));
    $('setupForm').reset(); showView('login'); showToast('Your two encrypted lockers are ready.');
  } catch (error) { $('setupError').textContent = safeError(error); }
  finally { submit.disabled = false; submit.innerHTML = 'Create secure vault <span>→</span>'; }
});
$('loginForm').addEventListener('submit', async event => {
  event.preventDefault(); $('loginError').textContent = '';
  const password = $('loginPassword').value; const config = readConfig();
  if (!config?.lockers?.length) { showView('setup'); return; }
  const submit = $('loginForm').querySelector('button[type="submit"]'); submit.disabled = true; submit.textContent = 'Checking password…';
  try {
    let key, locker;
    // Try each locker verifier. No locker is opened unless AES-GCM authentication succeeds.
    for (let i = 0; i < config.lockers.length; i++) {
      try { key = await authenticateLocker(password, config.lockers[i], i + 1); locker = i + 1; break; }
      catch (error) { if (error?.name !== 'OperationError' && error?.message !== 'Invalid password') throw error; }
    }
    if (!key) throw new Error('That password did not unlock either locker.');
    activeKey = key; activeLocker = locker; $('loginPassword').value = '';
    $('vaultNumber').textContent = `LOCKER 0${locker}`; $('searchInput').value = '';
    showView('vault'); await renderVideos();
    try { await navigator.storage?.persist?.(); } catch {}
  } catch (error) { $('loginError').textContent = safeError(error); }
  finally { submit.disabled = false; submit.innerHTML = 'Unlock vault <span>→</span>'; }
});
$('togglePassword').addEventListener('click', () => {
  const input = $('loginPassword'); const showing = input.type === 'text'; input.type = showing ? 'password' : 'text'; $('togglePassword').textContent = showing ? 'Show' : 'Hide';
});
$('addVideoBtn').addEventListener('click', () => $('fileInput').click());
$('emptyAddBtn').addEventListener('click', () => $('fileInput').click());
$('fileInput').addEventListener('change', event => importFiles(event.target.files));
$('searchInput').addEventListener('input', () => renderVideos().catch(error => showToast(safeError(error))));
$('lockNowBtn').addEventListener('click', lockVault); $('footerLockBtn').addEventListener('click', lockVault);
$('closePlayerBtn').addEventListener('click', closePlayer);
document.querySelectorAll('[data-close-player]').forEach(el => el.addEventListener('click', closePlayer));
$('cancelDeleteBtn').addEventListener('click', () => { pendingDeleteId = null; $('confirmModal').classList.add('hidden'); });
$('confirmDeleteBtn').addEventListener('click', deletePendingVideo);
document.querySelectorAll('[data-close-confirm]').forEach(el => el.addEventListener('click', () => { pendingDeleteId = null; $('confirmModal').classList.add('hidden'); }));
document.addEventListener('keydown', event => {
  if (event.key === 'Escape') { if (!$('playerModal').classList.contains('hidden')) closePlayer(); if (!$('confirmModal').classList.contains('hidden')) { pendingDeleteId = null; $('confirmModal').classList.add('hidden'); } }
});
window.addEventListener('pagehide', () => { clearObjectUrls(); activeKey = null; });

(async function init() {
  try {
    if (!window.isSecureContext || !crypto?.subtle) {
      showView(readConfig() ? 'login' : 'setup');
      const error = readConfig() ? $('loginError') : $('setupError');
      error.textContent = 'For secure encryption, run this site from http://localhost using VS Code Live Server, or use HTTPS.';
      return;
    }
    db = await openDatabase();
    showView(readConfig() ? 'login' : 'setup');
  } catch (error) {
    showView('setup'); $('setupError').textContent = `Local database could not start: ${safeError(error)}. Try a current version of Chrome or Edge.`;
  }
})();
