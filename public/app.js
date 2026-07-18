// ========================================
// NIA BAGS — INVENTORY APP (SECURED)
// ========================================

const STORAGE_KEYS = {
  users:    'nia_inv_users',
  items:    'nia_inv_items',
  session:  'nia_inv_session',
  lockout:  'nia_inv_lockout',
  auditLog: 'nia_inv_audit',
};

// ================================================================
// API INTEGRATION
// ================================================================
let _items = [];
let _users = [];
let _auditLogs = [];
let _trims = [];
let _fabrics = [];
let _batches = [];
let _stockMovements = [];
let _sales = [];

function apiHeaders() {
    const s = getSession();
    return {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + (s ? s.token : '')
    };
}

async function fetchAllData() {
    try {
        const [resItems, resTrims, resFabrics, resBatches, resMove, resSales] = await Promise.all([
            fetch('/api/items', { headers: apiHeaders() }),
            fetch('/api/trims', { headers: apiHeaders() }),
            fetch('/api/fabrics', { headers: apiHeaders() }),
            fetch('/api/batches', { headers: apiHeaders() }),
            fetch('/api/stock-movements', { headers: apiHeaders() }),
            fetch('/api/sales', { headers: apiHeaders() })
        ]);
        if(resItems.ok) _items = await resItems.json();
        if(resTrims.ok) _trims = await resTrims.json();
        if(resFabrics.ok) _fabrics = await resFabrics.json();
        if(resBatches.ok) _batches = await resBatches.json();
        if(resMove.ok) _stockMovements = await resMove.json();
        if(resSales.ok) _sales = await resSales.json();
        
        if (getSession() && getSession().role === 'admin') {
            const [resUsers, resLogs] = await Promise.all([
                fetch('/api/users', { headers: apiHeaders() }),
                fetch('/api/audit', { headers: apiHeaders() })
            ]);
            if(resUsers.ok) _users = await resUsers.json();
            if(resLogs.ok) _auditLogs = await resLogs.json();
        }
        
        populateDynamicDropdowns();
    } catch(e) { console.error('Fetch error', e); }
}


const SECURITY = {
  MAX_ATTEMPTS:      5,
  LOCKOUT_MS:        5 * 60 * 1000,   // 5 minutes
  SESSION_TIMEOUT_MS: 15 * 60 * 1000, // 15 min inactivity
  WARN_BEFORE_MS:    2 * 60 * 1000,   // warn at 2 min remaining
  MAX_LOG_ENTRIES:   500,
  PBKDF2_ITERATIONS: 100000,
};

// ================================================================
// CRYPTO — PBKDF2 password hashing via WebCrypto
// ================================================================
async function hashPassword(password, saltHex) {
  try {
    if (!window.crypto || !window.crypto.subtle) throw new Error("WebCrypto unavailable");
    const enc = new TextEncoder();
    const salt = saltHex
      ? hexToBytes(saltHex)
      : crypto.getRandomValues(new Uint8Array(16));

    const keyMaterial = await crypto.subtle.importKey(
      'raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt, hash: 'SHA-256', iterations: SECURITY.PBKDF2_ITERATIONS },
      keyMaterial, 256
    );
    return {
      hash:    bytesToHex(new Uint8Array(bits)),
      saltHex: bytesToHex(salt),
    };
  } catch (err) {
    // Fallback for file:// execution where WebCrypto Secure Context is missing
    const fbSalt = saltHex || 'local_fallback_salt';
    const fbHash = btoa(encodeURIComponent(password + '_' + fbSalt));
    return { hash: fbHash, saltHex: fbSalt };
  }
}

async function verifyPassword(password, storedHash, storedSalt) {
  const { hash } = await hashPassword(password, storedSalt);
  return hash === storedHash;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
function hexToBytes(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++) arr[i] = parseInt(hex.slice(i*2, i*2+2), 16);
  return arr;
}

// ================================================================
// PASSWORD RULES
// ================================================================
function validatePassword(pw) {
  const errors = [];
  if (pw.length < 8)              errors.push('At least 8 characters');
  if (!/[A-Z]/.test(pw))          errors.push('One uppercase letter');
  if (!/[a-z]/.test(pw))          errors.push('One lowercase letter');
  if (!/[0-9]/.test(pw))          errors.push('One number');
  if (!/[^A-Za-z0-9]/.test(pw))  errors.push('One special character (!@#$%^&* etc.)');
  return errors;
}

// ================================================================
// INPUT VALIDATION & SANITIZATION
// ================================================================
function esc(str) {
  return String(str)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;')
    .replace(/'/g,'&#x27;');
}

function validateUsername(u) {
  if (!u || u.length < 3 || u.length > 30) return 'Username must be 3–30 characters.';
  if (!/^[a-z0-9._]+$/.test(u)) return 'Username may only contain letters, numbers, dots and underscores.';
  return null;
}

function validateSKU(sku) {
  if (!sku || sku.length < 2 || sku.length > 40) return 'SKU must be 2–40 characters.';
  if (!/^[A-Za-z0-9\-]+$/.test(sku)) return 'SKU may only contain letters, numbers and hyphens.';
  return null;
}

function sanitizeText(str, maxLen = 200) {
  return String(str || '').trim().slice(0, maxLen);
}

// ================================================================
// STORAGE HELPERS
// ================================================================
function getData(key, fallback) {
  try { return JSON.parse(localStorage.getItem(key)) ?? fallback; }
  catch { return fallback; }
}
function setData(key, val) { localStorage.setItem(key, JSON.stringify(val)); }

// ================================================================
// DEFAULT SEED DATA
// ================================================================
const DEFAULT_ITEMS = [
  { id: 'i1',  name: 'Classic Tote Bag',          sku: 'NB-TOT-001', category: 'Products',      qty: 42,  unit: 'pcs',   threshold: 10, notes: 'Bestseller. Tan leather.' },
  { id: 'i2',  name: 'Laptop Backpack',            sku: 'NB-LAP-002', category: 'Products',      qty: 18,  unit: 'pcs',   threshold: 5,  notes: '15" padded compartment.' },
  { id: 'i3',  name: 'Mini Crossbody',             sku: 'NB-CRS-003', category: 'Products',      qty: 7,   unit: 'pcs',   threshold: 8,  notes: 'Low stock - reorder soon.' },
  { id: 'i4',  name: 'Duffle Bag',                 sku: 'NB-DUF-004', category: 'Products',      qty: 0,   unit: 'pcs',   threshold: 5,  notes: 'Out of stock.' },
  { id: 'i5',  name: 'Full-Grain Cowhide Leather', sku: 'RM-LTH-001', category: 'Raw Materials', qty: 120, unit: 'meters',threshold: 30, notes: 'Primary material. Ethiopian sourced.' },
  { id: 'i6',  name: 'Waxed Canvas',               sku: 'RM-CNV-002', category: 'Raw Materials', qty: 22,  unit: 'meters',threshold: 25, notes: 'Low stock.' },
  { id: 'i7',  name: 'YKK Zippers (Gold)',          sku: 'RM-ZIP-003', category: 'Raw Materials', qty: 500, unit: 'pcs',   threshold: 100,notes: 'Size 5 & 8 mixed.' },
  { id: 'i8',  name: 'Branded Dust Bags',           sku: 'PK-DST-001', category: 'Packaging',    qty: 80,  unit: 'pcs',   threshold: 50, notes: 'White cotton with NIA logo.' },
  { id: 'i9',  name: 'Gift Boxes (Large)',           sku: 'PK-BOX-002', category: 'Packaging',    qty: 30,  unit: 'pcs',   threshold: 40, notes: 'Low stock — reorder.' },
  { id: 'i10', name: 'Brass Hardware Set',           sku: 'RM-HRD-004', category: 'Raw Materials', qty: 200, unit: 'sets',  threshold: 50, notes: 'Buckles, D-rings and studs.' },
];

async function initStorage() { }

// ================================================================
// LOCAL STORAGE HELPERS
// ================================================================
function getData(key, defaultValue = null) {
  try {
    const item = localStorage.getItem(key);
    return item ? JSON.parse(item) : defaultValue;
  } catch (err) {
    console.error('Error reading from localStorage:', err);
    return defaultValue;
  }
}

function setData(key, value) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch (err) {
    console.error('Error writing to localStorage:', err);
  }
}

// ================================================================
// AUDIT LOG
// ================================================================
function auditLog(event, detail = '') {
  fetch('/api/audit', { method: 'POST', headers: apiHeaders(), body: JSON.stringify({ event, detail }) }).catch(()=>{}).then(()=> { if(getSession()?.role==='admin') fetchAllData(); });
}

// ================================================================
// AUTH — SESSION
// ================================================================
function getSession() { return getData(STORAGE_KEYS.session, null); }
function saveSession(user, token) {
  setData(STORAGE_KEYS.session, {
    id: user.id, name: user.name, username: user.username, 
    role: user.role, initials: user.initials, token: token || user.token, lastActive: Date.now()
  });
}
function clearSession() { localStorage.removeItem(STORAGE_KEYS.session); }

function requireAuth() {
  if (!getSession()) { window.location.href = 'index.html'; return false; }
  return true;
}
function requireAdmin() {
  const s = getSession();
  if (!s || s.role !== 'admin') {
    showToast('Access denied. Admins only.', 'error');
    navigateTo('overview');
    return false;
  }
  return true;
}
function redirectIfLoggedIn() {
  if (getSession()) window.location.href = 'dashboard.html';
}

// ================================================================
// RATE LIMITING — LOGIN LOCKOUT
// ================================================================
function getLockout()         { return getData(STORAGE_KEYS.lockout, { attempts: 0, until: 0 }); }
function saveLockout(data)    { setData(STORAGE_KEYS.lockout, data); }
function resetLockout()       { saveLockout({ attempts: 0, until: 0 }); }

function checkLockout() {
  const lo = getLockout();
  if (lo.until && Date.now() < lo.until) {
    const secsLeft = Math.ceil((lo.until - Date.now()) / 1000);
    const mins = Math.floor(secsLeft / 60);
    const secs = secsLeft % 60;
    return `Too many failed attempts. Try again in ${mins}m ${secs}s.`;
  }
  if (lo.until && Date.now() >= lo.until) resetLockout();
  return null;
}

function recordFailedAttempt(username) {
  const lo = getLockout();
  lo.attempts++;
  if (lo.attempts >= SECURITY.MAX_ATTEMPTS) {
    lo.until = Date.now() + SECURITY.LOCKOUT_MS;
    auditLog('LOGIN_LOCKOUT', `Account locked after ${lo.attempts} failed attempts for: ${username}`);
  }
  saveLockout(lo);
}

// ================================================================
// SESSION TIMEOUT
// ================================================================
let _timeoutTimer = null;
let _warnTimer    = null;
let _warnBanner   = null;

function updateLastActive() {
  const s = getSession();
  if (!s) return;
  s.lastActive = Date.now();
  setData(STORAGE_KEYS.session, s);
}

function setupSessionTimers() {
  // Update lastActive on user interaction
  ['mousemove','keydown','click','scroll','touchstart'].forEach(ev =>
    document.addEventListener(ev, updateLastActive, { passive: true })
  );

  _warnBanner = document.getElementById('sessionWarnBanner');

  function tick() {
    const s = getSession();
    if (!s) return;
    const idle = Date.now() - s.lastActive;
    const remaining = SECURITY.SESSION_TIMEOUT_MS - idle;

    if (remaining <= 0) {
      auditLog('SESSION_TIMEOUT', 'Auto-logged out due to inactivity');
      clearSession();
      window.location.href = 'index.html';
      return;
    }

    if (_warnBanner) {
      if (remaining <= SECURITY.WARN_BEFORE_MS) {
        const secsLeft = Math.ceil(remaining / 1000);
        const m = Math.floor(secsLeft / 60), sc = secsLeft % 60;
        _warnBanner.textContent = `⏱ You'll be automatically signed out in ${m}m ${sc}s due to inactivity.`;
        _warnBanner.classList.remove('hidden');
      } else {
        _warnBanner.classList.add('hidden');
      }
    }

    _timeoutTimer = setTimeout(tick, 1000);
  }
  tick();
}

function stopSessionWatcher() {
  clearTimeout(_timeoutTimer);
  clearTimeout(_warnTimer);
}

// ================================================================
// ITEMS CRUD
// ================================================================
function getItems() { return _items || []; }
function saveItems(items)   { setData(STORAGE_KEYS.items, items); }

async function addItem(data) {
  try {
    const res = await fetch('/api/items', { 
        method: 'POST', 
        headers: apiHeaders(), 
        body: JSON.stringify(data) 
    });
    if (!res.ok) throw new Error('Failed to add item');
    const result = await res.json();
    await fetchAllData();
    auditLog('ITEM_ADD', `Added: ${data.name} (${data.sku})`);
    return result.id;
  } catch (e) {
    showToast(e.message, 'error');
    throw e;
  }
}
async function updateItem(id, data) {
  try {
    const res = await fetch('/api/items/' + id, { 
        method: 'PUT', 
        headers: apiHeaders(), 
        body: JSON.stringify(data) 
    });
    if (!res.ok) throw new Error('Failed to update item');
    await fetchAllData();
    auditLog('ITEM_EDIT', `Edited: ${data.name} (${data.sku})`);
  } catch (e) {
    showToast(e.message, 'error');
    throw e;
  }
}
async function deleteItem(id) {
  try {
    const item = getItems().find(i => i.id === id);
    const res = await fetch('/api/items/' + id, { method: 'DELETE', headers: apiHeaders() });
    if (!res.ok) throw new Error('Failed to delete item');
    await fetchAllData();
    if (item) auditLog('ITEM_DELETE', `Deleted: ${item.name} (${item.sku})`);
  } catch (e) {
    showToast(e.message, 'error');
  }
}

// ================================================================
// USER MANAGEMENT (Admin only)
// ================================================================
function getUsers() { return _users || []; }

async function deleteUser(id) {
  const session = getSession();
  if (session?.role !== 'admin') return;
  if (id === session.id) { showToast("You can't delete your own account.", 'error'); return; }
  await fetch('/api/users/' + id, { method: 'DELETE', headers: apiHeaders() });
  auditLog('USER_DELETE', `Deleted user ID: ${id}`);
  await fetchAllData();
  renderUsersPage();
}

function renderUsersPage() {
  if (!requireAdmin()) return;
  const users = getUsers();
  const tbody = document.getElementById('usersTbody');
  if (!tbody) return;
  const session = getSession();

  if (users.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4"><div class="empty-state"><p>No users found.</p></div></td></tr>`;
    return;
  }
  tbody.innerHTML = users.map(u => {
    const isMe = u.id === session.id;
    return `
      <tr>
        <td><div class="item-name">${esc(u.name)}</div><div class="item-sku">${esc(u.username)}</div></td>
        <td>
          ${isMe ? `<span class="badge badge-product">${esc(u.role)}</span>` : `
            <select onchange="updateUserRole('${u.id}', this.value)" style="padding:4px 8px; border-radius:4px; border:1px solid var(--border); background:var(--surface); color:var(--text); font-family:inherit;">
              <option value="staff" ${u.role === 'staff' ? 'selected' : ''}>Staff</option>
              <option value="admin" ${u.role === 'admin' ? 'selected' : ''}>Admin</option>
            </select>
          `}
        </td>
        <td>${isMe
          ? '<span style="color:var(--muted);font-size:13px;">Current user</span>'
          : `<button class="btn btn-danger btn-sm" onclick="confirmDeleteUser('${u.id}','${esc(u.name)}')">Delete</button>`
        }</td>
      </tr>`;
  }).join('');
}

async function updateUserRole(id, newRole) {
    if (!confirm(`Change this user's role to ${newRole}?`)) return;
    try {
        const res = await fetch(`/api/users/${id}/role`, {
            method: 'PUT',
            headers: apiHeaders(),
            body: JSON.stringify({ role: newRole })
        });
        if (res.ok) {
            showToast('User role updated successfully', 'success');
            await fetchAllData();
            renderUsersPage();
        } else {
            const data = await res.json();
            throw new Error(data.error);
        }
    } catch (err) {
        showToast(err.message, 'error');
        renderUsersPage(); // revert UI
    }
}

let _pendingDeleteUserId = null;
function confirmDeleteUser(id, name) {
  _pendingDeleteUserId = id;
  document.getElementById('confirmUserName').textContent = name;
  document.getElementById('confirmUserOverlay').classList.add('open');
}
function cancelDeleteUser() {
  _pendingDeleteUserId = null;
  document.getElementById('confirmUserOverlay').classList.remove('open');
}
async function executeDeleteUser() {
  if (_pendingDeleteUserId) await deleteUser(_pendingDeleteUserId);
  cancelDeleteUser();
}

// ================================================================
// SECURITY LOG PAGE (Admin only)
// ================================================================
function renderSecurityLog() {
  if (!requireAdmin()) return;
  const logs = _auditLogs || [];
  const tbody = document.getElementById('logTbody');
  if (!tbody) return;

  if (logs.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4"><div class="empty-state"><p>No log entries yet.</p></div></td></tr>`;
    return;
  }
  tbody.innerHTML = logs.map(l => {
    const isBad = ['LOGIN_FAIL','LOGIN_LOCKOUT','AUTH_FAIL'].includes(l.event);
    return `<tr>
      <td style="font-size:12px;white-space:nowrap;color:var(--muted);">${new Date(l.ts).toLocaleString()}</td>
      <td><span class="badge ${isBad ? 'badge-out' : 'badge-in'}">${esc(l.event)}</span></td>
      <td>${esc(l.user)}</td>
      <td style="font-size:13px;">${esc(l.detail)}</td>
    </tr>`;
  }).join('');
}

// ================================================================
// TOAST
// ================================================================
function showToast(msg, type = 'default') {
  const container = document.getElementById('toastContainer');
  if (!container) return;
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  const icon = type === 'success' ? '✓' : type === 'error' ? '✕' : '●';
  t.innerHTML = `<span>${icon}</span><span>${esc(msg)}</span>`;
  container.appendChild(t);
  setTimeout(() => {
    t.style.opacity = '0'; t.style.transform = 'translateX(20px)';
    t.style.transition = 'all 0.3s'; setTimeout(() => t.remove(), 300);
  }, 3500);
}

// ================================================================
// LOGIN PAGE
// ================================================================
window.initLoginPage = async function() {
  await initStorage();
  redirectIfLoggedIn();

  const form   = document.getElementById('loginForm');
  const errBox = document.getElementById('loginError');
  if (!form) return;

  // Show lockout state immediately if applicable
  function refreshLockoutUI() {
    const msg = checkLockout();
    if (msg) {
      errBox.textContent = msg;
      errBox.classList.add('show');
      document.getElementById('loginBtn').disabled = true;
      setTimeout(refreshLockoutUI, 1000);
    } else {
      errBox.classList.remove('show');
      document.getElementById('loginBtn').disabled = false;
    }
  }
  refreshLockoutUI();

  form.addEventListener('submit', async e => {
    e.preventDefault();
    errBox.classList.remove('show');
    const lockMsg = checkLockout();
    if (lockMsg) { errBox.textContent = lockMsg; errBox.classList.add('show'); return; }

    const username = sanitizeText(document.getElementById('username').value).toLowerCase();
    const password = document.getElementById('password').value;
    const btn = document.getElementById('loginBtn');
    btn.disabled = true;
    btn.textContent = 'Signing in…';

    try {
      const res = await fetch('/api/auth/login', { 
        method: 'POST', 
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      const data = await res.json();
      if (res.ok) {
        resetLockout();
        saveSession(data.user, data.token);
        window.location.href = 'dashboard.html';
      } else {
        throw new Error(data.error || 'Server error');
      }
    } catch(err) {
      recordFailedAttempt(username);
      errBox.textContent = 'Invalid credentials. Please try again.';
      errBox.classList.add('show');
      document.getElementById('password').value = '';
      btn.disabled = false;
      btn.textContent = 'Sign In';
      refreshLockoutUI();
    }
  });
}

// ================================================================
// REGISTER PAGE
// ================================================================
window.initRegisterPage = async function() {
  await initStorage();
  redirectIfLoggedIn();

  const form   = document.getElementById('registerForm');
  const errBox = document.getElementById('registerError');
  if (!form) return;

  // Live password strength indicator
  const pwInput = document.getElementById('reg-password');
  const strengthDiv = document.getElementById('pw-strength');
  if (pwInput && strengthDiv) {
    pwInput.addEventListener('input', () => {
      const errs = validatePassword(pwInput.value);
      if (pwInput.value.length === 0) { strengthDiv.innerHTML = ''; return; }
      if (errs.length === 0) {
        strengthDiv.innerHTML = `<span class="pw-rule pw-ok">✓ Strong password</span>`;
      } else {
        strengthDiv.innerHTML = errs.map(e => `<span class="pw-rule pw-fail">✗ ${e}</span>`).join('');
      }
    });
  }

  form.addEventListener('submit', async e => {
    e.preventDefault();
    errBox.classList.remove('show');

    const name     = sanitizeText(document.getElementById('reg-name').value);
    const username = sanitizeText(document.getElementById('reg-username').value).toLowerCase();
    const password = document.getElementById('reg-password').value;
    const confirm  = document.getElementById('reg-confirm').value;
    const role     = 'staff';

    const uErr = validateUsername(username);
    if (uErr) { errBox.textContent = uErr; errBox.classList.add('show'); return; }
    if (!name || name.length < 2) { errBox.textContent = 'Please enter your full name.'; errBox.classList.add('show'); return; }
    const pwErrors = validatePassword(password);
    if (pwErrors.length > 0) { errBox.textContent = 'Password must have: ' + pwErrors.join(', ') + '.'; errBox.classList.add('show'); return; }
    if (password !== confirm) { errBox.textContent = 'Passwords do not match.'; errBox.classList.add('show'); return; }

    const btn = document.getElementById('registerBtn');
    btn.disabled = true;
    btn.textContent = 'Creating account…';

    try {
      const res = await fetch('/api/auth/register', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, username, password, role })
      });
      const data = await res.json();
      if(res.ok) {
        saveSession(data.user, data.token);
        window.location.href = 'dashboard.html';
      } else {
        throw new Error(data.error);
      }
    } catch(err) {
      errBox.textContent = err.message || 'Error creating account.';
      errBox.classList.add('show');
      btn.disabled = false;
      btn.textContent = 'Register';
    }
  });
}

// ================================================================
// DASHBOARD
// ================================================================
async function initDashboard() {
  if (!requireAuth()) return;

  const session = getSession();

  // Populate user info
  document.getElementById('userAvatarText').textContent = session.initials || session.name[0].toUpperCase();
  document.getElementById('userName').textContent = session.name;
  document.getElementById('userRole').textContent = session.role;

  // Hide admin-only nav items from staff
  if (session.role !== 'admin') {
    document.querySelectorAll('.admin-only').forEach(el => el.style.display = 'none');
  }

  // Logout
  document.getElementById('logoutBtn').addEventListener('click', () => {
    auditLog('LOGOUT', 'User signed out');
    clearSession();
    window.location.href = 'index.html';
  });

  // Nav
  document.querySelectorAll('.nav-item[data-page]').forEach(el => {
    el.addEventListener('click', () => navigateTo(el.dataset.page));
  });

  // Session timeout watcher
  startSessionWatcher();

  // Mobile Menu Toggle
  const mobileBtn = document.getElementById('mobileMenuBtn');
  if (mobileBtn) {
    mobileBtn.addEventListener('click', () => {
      document.querySelector('.sidebar').classList.toggle('mobile-open');
    });
  }

  await fetchAllData();
  navigateTo('overview');
}
window.toggleMobileMenu = function() {
  const sidebar = document.querySelector('.sidebar');
  const overlay = document.getElementById('sidebarOverlay');
  if (sidebar) sidebar.classList.toggle('open');
  if (overlay) overlay.classList.toggle('open');
};

function navigateTo(pageId) {
  // Close mobile sidebar if open
  const sidebar = document.querySelector('.sidebar');
  const overlay = document.getElementById('sidebarOverlay');
  if (sidebar && sidebar.classList.contains('open')) {
    sidebar.classList.remove('open');
    if (overlay) overlay.classList.remove('open');
  }
  // Role guard for admin-only pages
  if ((pageId === 'users' || pageId === 'seclog' || pageId === 'sales' || pageId === 'inventory') && getSession()?.role !== 'admin') {
    auditLog('AUTH_FAIL', `Unauthorized access attempt to page: ${pageId}`);
    showToast('Access denied. Admins only.', 'error');
    pageId = 'overview';
  }

  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

  const page = document.getElementById('page-' + pageId);
  const nav  = document.querySelector(`.nav-item[data-page="${pageId}"]`);
  if (page) page.classList.add('active');
  if (nav)  nav.classList.add('active');

  if (pageId === 'overview')  renderOverview();
  if (pageId === 'inventory') renderInventory();
  if (pageId === 'reports')   renderReports();
  if (pageId === 'users')     renderUsersPage();
  if (pageId === 'seclog')    renderSecurityLog();
  if (pageId === 'trims')     renderTrimStock();
  if (pageId === 'fabrics')   renderFabrics();
  if (pageId === 'products')  renderProductStock();
  if (pageId === 'production')renderBatches();
  if (pageId === 'movements') renderMovements();
  if (pageId === 'sales')     renderSales();
}

function getMaterialsByCategory(category) {
    return _items.filter(item => {
        if (item.category === category) return true;
        if (item.category !== 'Raw Materials') return false;
        
        const n = item.name.toLowerCase();
        const s = item.sku.toUpperCase();
        if (category === 'Trim') {
            return (s.startsWith('TRM') || n.includes('zipper') || n.includes('webbing') || n.includes('strap') || n.includes('hook') || n.includes('d-ring') || n.includes('label') || n.includes('binding'));
        }
        if (category === 'Fabric') {
            return (s.startsWith('FC') || n.includes('canvas') || n.includes('leather') || n.includes('fabric') || n.includes('lining') || n.includes('foam') || n.includes('interfacing') || n.includes('mesh') || n.includes('tafeta') || item.unit === 'meters');
        }
        return false;
    });
}

function populateDynamicDropdowns() {
    const customTrims = getMaterialsByCategory('Trim').filter(i => i.qty > 0);
    const customFabrics = getMaterialsByCategory('Fabric').filter(i => i.qty > 0);

    function appendDynamicOpts(selectId, items, groupLabel) {
        const selectEl = document.getElementById(selectId);
        if(!selectEl) return;
        const existing = selectEl.querySelector(`optgroup[label="${groupLabel}"]`);
        if (existing) existing.remove();
        
        if (items.length > 0) {
            const optGroup = document.createElement('optgroup');
            optGroup.label = groupLabel;
            items.forEach(item => {
                const opt = document.createElement('option');
                opt.value = item.id;
                opt.textContent = `[${item.sku}] ${item.name} (${item.qty} ${item.unit || (item.category === 'Fabric' ? 'm' : 'pcs')})`;
                optGroup.appendChild(opt);
            });
            selectEl.appendChild(optGroup);
        }
    }

    appendDynamicOpts('f-trim-item', customTrims, 'Live Inventory (Trims)');
    appendDynamicOpts('f-fab-name', customFabrics, 'Live Inventory (Fabrics)');
}

// ================================================================
// OVERVIEW
// ================================================================
window.toggleDashboardAccordion = function(id) {
  const allAcc = document.querySelectorAll('.dash-accordion');
  const target = document.getElementById(id);
  
  if (target.classList.contains('open')) {
    target.classList.remove('open');
  } else {
    allAcc.forEach(acc => acc.classList.remove('open'));
    target.classList.add('open');
  }
}

function renderOverview() {
  const items = getItems();
  
  const getImg = (i) => i.image_url ? `<img src="${esc(i.image_url)}" style="width:40px;height:40px;object-fit:cover;border-radius:4px;">` : `<div style="width:40px;height:40px;background:var(--border);border-radius:4px;display:flex;align-items:center;justify-content:center;font-size:16px;">📦</div>`;
  const getPrice = (i) => parseFloat(i.unit_cost) || 0;
  
  const isAdmin = getSession()?.role === 'admin';
  
  const fmtN = (n) => typeof n === 'number' ? n.toLocaleString() : n;
  const fmtP = (n) => typeof n === 'number' ? n.toLocaleString(undefined, {minimumFractionDigits:2, maximumFractionDigits:2}) : n;

  // 1. Products
  const products = items.filter(i => i.category === 'Products');
  const prodTotal = products.reduce((sum, i) => sum + i.qty, 0);
  const prodPriceTotal = products.reduce((sum, i) => sum + (i.qty * getPrice(i)), 0);
  document.getElementById('do-prod-total').textContent = fmtN(prodTotal);
  const prodPriceTotalEl = document.getElementById('do-prod-price-total');
  if(prodPriceTotalEl) prodPriceTotalEl.textContent = '$' + fmtP(prodPriceTotal);
  
  const prodBody = document.getElementById('do-prod-tbody');
  if (prodBody) {
      if (products.length === 0) {
          prodBody.innerHTML = `<tr><td colspan="${isAdmin ? 5 : 3}"><p class="empty-state">No products found</p></td></tr>`;
      } else {
          prodBody.innerHTML = products.map(p => {
              const uPrice = getPrice(p);
              return `<tr>
                  <td>${getImg(p)}</td>
                  <td>${esc(p.name)}<br><span style="font-size:11px;color:var(--muted)">(${esc(p.sku)})</span></td>
                  <td style="font-weight:600;">${fmtN(p.qty)}</td>
                  ${isAdmin ? `<td>$${fmtP(uPrice)}</td><td style="font-weight:600; color:var(--success);">$${fmtP(p.qty * uPrice)}</td>` : ''}
              </tr>`;
          }).join('');
      }
  }

  // 2. Trims
  const trims = items.filter(i => i.category === 'Trim');
  const trimTotal = trims.reduce((sum, i) => sum + i.qty, 0);
  const trimPriceTotal = trims.reduce((sum, i) => sum + (i.qty * getPrice(i)), 0);
  document.getElementById('do-trim-total').textContent = fmtN(trimTotal);
  const trimPriceTotalEl = document.getElementById('do-trim-price-total');
  if(trimPriceTotalEl) trimPriceTotalEl.textContent = '$' + fmtP(trimPriceTotal);
  
  const trimBody = document.getElementById('do-trim-tbody');
  if (trimBody) {
      if (trims.length === 0) {
          trimBody.innerHTML = `<tr><td colspan="${isAdmin ? 5 : 3}"><p class="empty-state">No trims found</p></td></tr>`;
      } else {
          trimBody.innerHTML = trims.map(t => {
              const uPrice = getPrice(t);
              return `<tr>
                  <td>${getImg(t)}</td>
                  <td>${esc(t.name)}<br><span style="font-size:11px;color:var(--muted)">(${esc(t.sku)})</span></td>
                  <td style="font-weight:600;">${fmtN(t.qty)}</td>
                  ${isAdmin ? `<td>$${fmtP(uPrice)}</td><td style="font-weight:600; color:var(--success);">$${fmtP(t.qty * uPrice)}</td>` : ''}
              </tr>`;
          }).join('');
      }
  }

  // 3. Fabrics
  const fabrics = items.filter(i => i.category === 'Fabric' || i.category === 'Raw Materials' && i.unit === 'meters');
  const fabTotal = fabrics.reduce((sum, i) => sum + i.qty, 0);
  const fabPriceTotal = fabrics.reduce((sum, i) => sum + (i.qty * getPrice(i)), 0);
  document.getElementById('do-fab-total').textContent = fmtN(fabTotal) + 'm';
  const fabPriceTotalEl = document.getElementById('do-fab-price-total');
  if(fabPriceTotalEl) fabPriceTotalEl.textContent = '$' + fmtP(fabPriceTotal);
  
  const fabBody = document.getElementById('do-fab-tbody');
  if (fabBody) {
      if (fabrics.length === 0) {
          fabBody.innerHTML = `<tr><td colspan="${isAdmin ? 5 : 3}"><p class="empty-state">No fabrics found</p></td></tr>`;
      } else {
          fabBody.innerHTML = fabrics.map(f => {
              const uPrice = getPrice(f);
              return `<tr>
                  <td>${getImg(f)}</td>
                  <td>${esc(f.name)}<br><span style="font-size:11px;color:var(--muted)">(${esc(f.sku)})</span></td>
                  <td style="font-weight:600;">${fmtN(f.qty)} ${esc(f.unit)}</td>
                  ${isAdmin ? `<td>$${fmtP(uPrice)}</td><td style="font-weight:600; color:var(--success);">$${fmtP(f.qty * uPrice)}</td>` : ''}
              </tr>`;
          }).join('');
      }
  }

  // 4. Low Stock
  const lowItems = items.filter(i => stockStatus(i) === 'low' || stockStatus(i) === 'out');
  const alertCount = lowItems.length;
  
  const lowContainer = document.getElementById('do-low-container');
  if (lowContainer) {
      if (lowItems.length === 0) {
          lowContainer.style.display = 'none';
      } else {
          lowContainer.style.display = 'flex';
          lowContainer.innerHTML = lowItems.map(i => {
              const isOut = stockStatus(i) === 'out';
              const colorVar = isOut ? 'var(--danger)' : 'var(--warning)';
              return `
              <div class="low-stock-card">
                <div style="position:absolute; top:0; left:0; width:4px; height:100%; background:${colorVar};"></div>
                <div class="ls-card-header">
                  <div class="ls-card-title">${esc(i.name)}</div>
                  <div class="ls-card-type">${esc(i.category)}</div>
                </div>
                <div class="ls-card-body">
                  <div>
                    <div class="ls-card-qty" style="color:${colorVar};">${i.qty} <span style="font-size:12px; font-weight:400; color:var(--text);">${esc(i.unit || 'pcs')}</span></div>
                    <div class="ls-card-limit">Threshold: ${i.threshold}</div>
                  </div>
                </div>
              </div>`;
          }).join('');
      }
  }

  // 5. Monthly Batches Summary
  const thisMonth = new Date().getMonth();
  const thisYear = new Date().getFullYear();
  const monthlyBatches = _batches.filter(b => {
      const d = new Date(b.created_at);
      return d.getMonth() === thisMonth && d.getFullYear() === thisYear;
  });
  
  const mProdQty = monthlyBatches.reduce((sum, b) => sum + (b.produced_qty || 0), 0);
  let mTrimQty = 0; let mFabQty = 0; let mTotalCost = 0;
  monthlyBatches.forEach(b => {
      if (Array.isArray(b.materials)) {
          b.materials.forEach(m => {
              const mItem = _items.find(i => i.id === m.material_id);
              const uCost = mItem ? (parseFloat(mItem.unit_cost) || 0) : 0;
              if (m.material_type === 'trim') { mTrimQty += (m.consumed_qty || 0); mTotalCost += ((m.consumed_qty || 0) * uCost); }
              if (m.material_type === 'fabric') { mFabQty += (m.consumed_qty || 0); mTotalCost += ((m.consumed_qty || 0) * uCost); }
          });
      }
  });

  const doMonProd = document.getElementById('do-month-prod');
  if (doMonProd) doMonProd.textContent = fmtN(mProdQty);
  const doMonTrim = document.getElementById('do-month-trim');
  if (doMonTrim) doMonTrim.textContent = fmtN(mTrimQty);
  const doMonFab = document.getElementById('do-month-fab');
  if (doMonFab) doMonFab.textContent = fmtN(mFabQty) + 'm';
  const doMonCost = document.getElementById('do-month-cost');
  if (doMonCost) doMonCost.textContent = '$' + fmtP(mTotalCost);

  // Global Alert Badges
  const banner = document.getElementById('alertBanner');
  const bannerCount = document.getElementById('alertCount');
  if (banner && bannerCount) {
      if (alertCount > 0) { bannerCount.textContent = alertCount; banner.classList.remove('hidden'); }
      else { banner.classList.add('hidden'); }
  }

  const badge = document.getElementById('alertBadge');
  if (badge) {
      if (alertCount > 0) { badge.textContent = alertCount; badge.style.display = 'inline-block'; }
      else { badge.style.display = 'none'; }
  }
}

// ================================================================
// INVENTORY
// ================================================================
let currentFilters = { search: '', category: 'all', status: 'all' };
let editingId = null;

function renderInventory() {
  // Update filters from the HTML inputs
  const searchEl = document.getElementById('invSearch');
  const catEl = document.getElementById('invCatFilter');
  
  if (searchEl) currentFilters.search = searchEl.value || '';
  if (catEl) currentFilters.category = catEl.value || 'all';
  
  applyFilters(getItems());
  updateAlertBadge();
}

function updateAlertBadge() {
  const alertCount = getItems().filter(i => stockStatus(i) !== 'in').length;
  const badge = document.getElementById('alertBadge');
  if (alertCount > 0) { badge.textContent = alertCount; badge.style.display = 'inline-block'; }
  else { badge.style.display = 'none'; }
}

function applyFilters(items) {
  const { search, category, status } = currentFilters;
  let filtered = items;
  if (search)          filtered = filtered.filter(i => i.name.toLowerCase().includes(search.toLowerCase()) || i.sku.toLowerCase().includes(search.toLowerCase()));
  if (category !== 'all') filtered = filtered.filter(i => i.category === category);
  if (status   !== 'all') filtered = filtered.filter(i => stockStatus(i) === status);
  
  // Sort by SKU in ascending order (Task #4)
  filtered.sort((a, b) => a.sku.localeCompare(b.sku));
  
  renderInventoryTable(filtered);
}

function renderInventoryTable(items) {
  const tbody = document.getElementById('invTbody');
  if (!tbody) return;

  if (items.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6"><div class="empty-state">
      <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"/></svg>
      <p>No items match your filters</p><span>Try adjusting your search or filters</span>
    </div></td></tr>`;
    return;
  }

  const isAdmin = getSession()?.role === 'admin';

  tbody.innerHTML = items.map(item => {
    // Create image thumbnail HTML
    let imageHtml = '';
    if (item.image_url) {
      imageHtml = `<img src="${item.image_url}" alt="${esc(item.name)}" style="width:50px; height:50px; object-fit:cover; border-radius:6px; border:1px solid var(--border);"/>`;
    } else {
      imageHtml = `<span style="color:var(--muted); font-size:12px;">No image</span>`;
    }
    
    return `<tr data-id="${item.id}">
      <td><div class="item-name">${esc(item.name)}</div><div class="item-sku">${esc(item.sku)}</div></td>
      <td><span class="badge badge-${catBadge(item.category)}">${esc(item.category)}</span></td>
      ${isAdmin ? `<td>${item.unit_cost ? item.unit_cost.toLocaleString() + ' ETB' : '0.00 ETB'}</td>` : ''}
      <td>
        <div style="display:flex; align-items:center; gap:8px; font-weight:600;">
          <button class="btn btn-secondary btn-sm" onclick="quickAdjustStock('${item.id}', -1)" style="padding:2px 8px; border-radius:4px; font-size:14px; font-weight:bold;">-</button>
          <span id="qty-val-${item.id}">${item.qty.toLocaleString()} ${esc(item.unit || 'pcs')}</span>
          <button class="btn btn-secondary btn-sm" onclick="quickAdjustStock('${item.id}', 1)" style="padding:2px 8px; border-radius:4px; font-size:14px; font-weight:bold;">+</button>
        </div>
      </td>
      <td>${imageHtml}</td>
      <td>
        <div class="actions">
          <button class="btn btn-secondary btn-sm" onclick="openEditModal('${item.id}')">
            <svg width="13" height="13" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/></svg>
            Edit
          </button>
          <button class="btn btn-danger btn-sm" onclick="confirmDelete('${item.id}','${esc(item.name)}')">
            <svg width="13" height="13" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
          </button>
        </div>
      </td>
    </tr>`;
  }).join('');
}

// Render inventory with filters
window.renderInventory = function() {
  const searchTerm = document.getElementById('invSearch')?.value.toLowerCase() || '';
  const categoryFilter = document.getElementById('invCatFilter')?.value || 'all';
  
  let filtered = _items;
  
  // Apply search filter
  if (searchTerm) {
    filtered = filtered.filter(item => 
      item.name.toLowerCase().includes(searchTerm) || 
      item.sku.toLowerCase().includes(searchTerm)
    );
  }
  
  // Apply category filter
  if (categoryFilter !== 'all') {
    filtered = filtered.filter(item => item.category === categoryFilter);
  }
  
  // Sort by SKU ascending
  filtered.sort((a, b) => a.sku.localeCompare(b.sku));
  
  renderInventoryTable(filtered);
};

// Helper functions
function getItems() {
  return _items || [];
}

function esc(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function catBadge(category) {
  const map = {
    'Products': 'product',
    'Trim': 'trim',
    'Fabric': 'fabric',
    'Raw Materials': 'raw',
    'Packaging': 'pack',
    'Other': 'other'
  };
  return map[category] || 'other';
}


// ================================================================
// SECURITY LOGS
// ================================================================
window.renderSecurityLog = async function() {
  const tbody = document.getElementById('logTbody');
  if (!tbody) return;
  
  try {
    const res = await fetch('/api/audit', { headers: apiHeaders() });
    if (!res.ok) throw new Error('Failed to fetch logs');
    const logs = await res.json();
    
    if (logs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4"><div class="empty-state"><p>No activity logs found</p></div></td></tr>';
      return;
    }
    
    tbody.innerHTML = logs.map(log => {
      const date = new Date(log.ts).toLocaleString('en-GB');
      // Style different event types
      let typeClass = 'badge-other';
      if (log.event.includes('Entry')) typeClass = 'badge-in';
      if (log.event.includes('Update')) typeClass = 'badge-warning';
      if (log.event.includes('Output')) typeClass = 'badge-out';
      
      return `<tr>
        <td style="white-space:nowrap; color:var(--muted); font-size:12px;">${date}</td>
        <td><span class="badge ${typeClass}">${esc(log.event)}</span></td>
        <td style="font-weight:600;">${esc(log.user)}</td>
        <td style="font-size:13px;">${esc(log.detail)}</td>
      </tr>`;
    }).join('');
  } catch(e) {
    tbody.innerHTML = `<tr><td colspan="4"><div class="empty-state" style="color:var(--danger);"><p>${e.message}</p></div></td></tr>`;
  }
};

// --- Add/Edit Modal ---
let currentImageData = null;

window.previewImage = function(input) {
  if (input.files && input.files[0]) {
    const file = input.files[0];
    
    // Task #1: Validate file size (max 2MB to prevent DB issues)
    const maxSize = 2 * 1024 * 1024; // 2MB
    if (file.size > maxSize) {
      showToast('Image too large! Please choose an image smaller than 2MB.', 'error');
      input.value = '';
      return;
    }
    
    // Validate file type
    if (!file.type.startsWith('image/')) {
      showToast('Please select a valid image file.', 'error');
      input.value = '';
      return;
    }
    
    const reader = new FileReader();
    reader.onload = function(e) {
      currentImageData = e.target.result;
      document.getElementById('previewImg').src = e.target.result;
      document.getElementById('imagePreview').style.display = 'block';
    };
    reader.onerror = function() {
      showToast('Failed to read image file.', 'error');
      input.value = '';
    };
    reader.readAsDataURL(file);
  }
};

window.removeImage = function() {
  currentImageData = null;
  document.getElementById('f-image').value = '';
  document.getElementById('imagePreview').style.display = 'none';
};

// Task #2 & #6: Toggle image field and quantity field based on category
window.toggleImageField = function() {
  const category = document.getElementById('f-category').value;
  const imageGroup = document.getElementById('f-image').closest('.form-group');
  const qtyGroup = document.getElementById('initial-qty-group');
  
  if (category === 'Products') {
    // Products: show image, hide quantity
    if (imageGroup) {
      imageGroup.style.display = 'block';
      document.getElementById('f-image').disabled = false;
    }
    if (qtyGroup) qtyGroup.style.display = 'none';
  } else if (category === 'Trim' || category === 'Fabric') {
    // Trim/Fabric: hide image, show quantity
    if (imageGroup) {
      imageGroup.style.display = 'none';
      document.getElementById('f-image').disabled = true;
      removeImage(); // Clear any selected image
    }
    if (qtyGroup) qtyGroup.style.display = 'block';
  } else {
    // Other: hide both
    if (imageGroup) {
      imageGroup.style.display = 'none';
      document.getElementById('f-image').disabled = true;
      removeImage();
    }
    if (qtyGroup) qtyGroup.style.display = 'none';
  }
};

function openAddModal() {
  editingId = null;
  currentImageData = null;
  document.getElementById('modalTitle').textContent = 'Add New Item';
  document.getElementById('itemForm').reset();
  document.getElementById('imagePreview').style.display = 'none';
  
  const isAdmin = getSession()?.role === 'admin';
  const costGroup = document.getElementById('f-unit-cost').closest('.form-group');
  if (costGroup) costGroup.style.display = isAdmin ? 'block' : 'none';
  
  // Task #2 & #6: Set initial visibility based on default category
  toggleImageField();
  
  document.getElementById('itemModal').classList.add('open');
}
function openEditModal(id) {
  const item = getItems().find(i => i.id === id);
  if (!item) return;
  editingId = id;
  currentImageData = null;
  document.getElementById('modalTitle').textContent = 'Edit Item';
  document.getElementById('f-name').value      = item.name;
  document.getElementById('f-sku').value       = item.sku;
  document.getElementById('f-category').value  = item.category;
  document.getElementById('f-unit').value      = item.unit;
  document.getElementById('f-unit-cost').value = item.unit_cost || 0;
  
  const isAdmin = getSession()?.role === 'admin';
  const costGroup = document.getElementById('f-unit-cost').closest('.form-group');
  if (costGroup) costGroup.style.display = isAdmin ? 'block' : 'none';
  
  document.getElementById('f-threshold').value = item.threshold;
  document.getElementById('f-notes').value     = item.notes || '';
  
  // Show existing image if available
  if (item.image_url) {
    currentImageData = item.image_url;
    document.getElementById('previewImg').src = item.image_url;
    document.getElementById('imagePreview').style.display = 'block';
  } else {
    document.getElementById('imagePreview').style.display = 'none';
  }
  
  // Task #2 & #6: Set field visibility based on category
  toggleImageField();
  
  document.getElementById('itemModal').classList.add('open');
}

// Task #1: Image upload handling with 10MB limit
// (currentImageData is already declared at line 992)

window.previewImage = async function(input) {
  const MAX_SIZE = 10 * 1024 * 1024; // 10MB
  
  if (!input.files || !input.files[0]) return;
  
  const file = input.files[0];
  
  if (file.size > MAX_SIZE) {
    showToast(`Image too large! Maximum size is 10MB. Your file is ${(file.size / (1024 * 1024)).toFixed(2)}MB`, 'error');
    input.value = ''; 
    return;
  }
  
  if (!file.type.startsWith('image/')) {
    showToast('Please select a valid image file (JPG, PNG, GIF, etc.)', 'error');
    input.value = '';
    return;
  }
  
  const reader = new FileReader();
  reader.onload = function(e) {
    const img = new Image();
    img.onload = function() {
      // Compress the image before saving
      const canvas = document.createElement('canvas');
      const MAX_DIMENSION = 600;
      let width = img.width;
      let height = img.height;
      
      if (width > height) {
        if (width > MAX_DIMENSION) {
          height *= MAX_DIMENSION / width;
          width = MAX_DIMENSION;
        }
      } else {
        if (height > MAX_DIMENSION) {
          width *= MAX_DIMENSION / height;
          height = MAX_DIMENSION;
        }
      }
      
      canvas.width = width;
      canvas.height = height;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(img, 0, 0, width, height);
      
      // Get compressed data URL
      currentImageData = canvas.toDataURL('image/jpeg', 0.7);
      document.getElementById('previewImg').src = currentImageData;
      document.getElementById('imagePreview').style.display = 'block';
    };
    img.src = e.target.result;
  };
  reader.onerror = function() {
    showToast('Failed to read image file', 'error');
    input.value = '';
  };
  reader.readAsDataURL(file);
};

window.removeImage = function() {
  currentImageData = null;
  document.getElementById('f-image').value = '';
  document.getElementById('imagePreview').style.display = 'none';
  document.getElementById('previewImg').src = '';
};

window.toggleImageField = function() {
  const category = document.getElementById('f-category').value;
  const qtyGroup = document.getElementById('initial-qty-group');
  
  // Initial quantity for Trim, Fabric, AND Products
  if (qtyGroup) {
    if (category === 'Trim' || category === 'Fabric' || category === 'Products') {
      qtyGroup.style.display = 'block';
    } else {
      qtyGroup.style.display = 'none';
    }
  }
};

function closeModal() {
  document.getElementById('itemModal').classList.remove('open');
  currentImageData = null;
  editingId = null;
}

async function saveItem() {
  const nameRaw = sanitizeText(document.getElementById('f-name').value);
  const skuRaw  = sanitizeText(document.getElementById('f-sku').value).toUpperCase();

  if (!nameRaw || nameRaw.length < 2) { showToast('Item name must be at least 2 characters.', 'error'); return; }

  const skuErr = validateSKU(skuRaw);
  if (skuErr) { showToast(skuErr, 'error'); return; }

  // Task #3: Check for duplicate SKU
  const existingItem = _items.find(i => i.sku.toUpperCase() === skuRaw && i.id !== editingId);
  if (existingItem) {
    showToast('SKU already exists! Each SKU must be unique.', 'error');
    return;
  }

  const unitRaw = sanitizeText(document.getElementById('f-unit').value);
  if (unitRaw !== 'pcs' && unitRaw !== 'meters') {
    showToast('Invalid unit selected. Must be pcs or meters.', 'error');
    return;
  }

  const category = document.getElementById('f-category').value;
  
  // Calculate initial qty based on category
  let initialQty = 0;
  if (editingId) {
    initialQty = _items.find(i => i.id === editingId)?.qty || 0;
  } else {
    if (category === 'Trim' || category === 'Fabric' || category === 'Products') {
      initialQty = parseFloat(document.getElementById('f-initial-qty').value) || 0;
    }
  }

  const data = {
    name:      nameRaw,
    sku:       skuRaw,
    category:  category,
    qty:       initialQty,
    unit:      unitRaw,
    unit_cost: parseFloat(document.getElementById('f-unit-cost').value) || 0,
    threshold: Math.max(0, parseInt(document.getElementById('f-threshold').value) || 0),
    notes:     sanitizeText(document.getElementById('f-notes').value, 500),
    image_url: currentImageData || null
  };

  try {
    if (editingId) { await updateItem(editingId, data); showToast('Item updated!', 'success'); }
    else           { await addItem(data);               showToast('Item added!',   'success'); }
    
    closeModal();
    renderInventory();
    renderOverview();
  } catch (err) {
    console.error('Save error:', err);
    showToast(err.message || 'Failed to save item', 'error');
  }
}

// API functions for items
async function addItem(data) {
  try {
    console.log('Adding item with data:', data);
    console.log('Session:', getSession());
    console.log('Headers:', apiHeaders());
    
    const res = await fetch('/api/items', {
      method: 'POST',
      headers: apiHeaders(),
      body: JSON.stringify(data)
    });
    
    console.log('Response status:', res.status);
    console.log('Response headers:', res.headers.get('content-type'));
    
    // Check if response is JSON
    const contentType = res.headers.get('content-type');
    if (!contentType || !contentType.includes('application/json')) {
      console.error('Server returned non-JSON response');
      const textResponse = await res.text();
      console.error('Response body:', textResponse);
      throw new Error('Server error - please check if you are logged in');
    }
    
    const responseData = await res.json();
    console.log('Response data:', responseData);
    
    if (!res.ok) {
      throw new Error(responseData.error || 'Failed to add item');
    }
    
    await fetchAllData(); // Refresh data
    return responseData;
  } catch (err) {
    console.error('Add item error:', err);
    throw err;
  }
}

async function updateItem(id, data) {
  try {
    const res = await fetch(`/api/items/${id}`, {
      method: 'PUT',
      headers: apiHeaders(),
      body: JSON.stringify(data)
    });
    
    // Check if response is JSON
    const contentType = res.headers.get('content-type');
    if (!contentType || !contentType.includes('application/json')) {
      console.error('Server returned non-JSON response:', res.status);
      throw new Error('Server error - please check if you are logged in');
    }
    
    const responseData = await res.json();
    
    if (!res.ok) {
      throw new Error(responseData.error || 'Failed to update item');
    }
    
    await fetchAllData(); // Refresh data
    return responseData;
  } catch (err) {
    console.error('Update item error:', err);
    throw err;
  }
}

window.quickAdjustStock = async function(id, change) {
  const items = getItems();
  const item = items.find(i => i.id === id);
  if(!item) return;
  const newQty = item.qty + change;
  if(newQty < 0) {
    showToast('Stock cannot go below 0', 'error');
    return;
  }

  // Optimistic UI update instantly without refreshing layout
  item.qty = newQty;
  const qtySpan = document.getElementById(`qty-val-${item.id}`);
  if (qtySpan) qtySpan.textContent = `${newQty.toLocaleString()} ${item.unit || 'pcs'}`;

  try {
    const updated = { ...item, qty: newQty };
    await fetch('/api/items/' + item.id, { method: 'PUT', headers: apiHeaders(), body: JSON.stringify(updated) });
    
    // Background refresh
    fetchAllData().then(() => {
        if(typeof updateAlertBadge === 'function') updateAlertBadge();
    });
    
    const sign = change > 0 ? '+' : '';
    const note = 'Quick Adjustment';
    
    // Attempt audit log
    await fetch('/api/audit', {
      method: 'POST',
      headers: apiHeaders(),
      body: JSON.stringify({ event: 'STOCK_ADJUST', detail: `[${item.sku}] ${item.name} Qt: ${item.qty - change} → ${newQty} (${sign}${change}). Note: ${note}` })
    });

  } catch(e) {
    showToast('Failed to sync stock adjustment', 'error');
    // Rollback
    item.qty = item.qty - change;
    if (qtySpan) qtySpan.textContent = `${item.qty.toLocaleString()} ${item.unit || 'pcs'}`;
  }
};

// --- Stock Adjustment Modal ---
let _adjId = null;
function openAdjustModal(id) {
  const item = getItems().find(i => i.id === id);
  if (!item) return;
  _adjId = id;
  document.getElementById('adjItemName').textContent = item.name;
  document.getElementById('adjCurrentQty').textContent = `${item.qty} ${item.unit}`;
  document.getElementById('adjustForm').reset();
  
  const typeSelect = document.getElementById('f-adj-type');
  if (item.category === 'Fabric' || item.category === 'Trim' || item.category === 'Raw Materials') {
     typeSelect.value = 'add';
     typeSelect.disabled = true;
     typeSelect.title = 'Subtraction disabled for raw materials. (Automatic via batches)';
  } else {
     typeSelect.disabled = false;
     typeSelect.title = '';
  }

  document.getElementById('adjustModal').classList.add('open');
}
function closeAdjustModal() {
  document.getElementById('adjustModal').classList.remove('open');
  _adjId = null;
}
async function saveAdjustment() {
  const amount = parseInt(document.getElementById('f-adj-qty').value);
  const type   = document.getElementById('f-adj-type').value;
  const note   = sanitizeText(document.getElementById('f-adj-note').value);

  if (!_adjId || isNaN(amount) || amount <= 0 || !note) {
    showToast('Please enter a valid amount and a reason.', 'error');
    return;
  }

  const items = getItems();
  const idx = items.findIndex(i => i.id === _adjId);
  if (idx === -1) return;
  
  const item = items[idx];
  const oldQty = item.qty;
  const newQty = type === 'add' ? oldQty + amount : Math.max(0, oldQty - amount);
  if (newQty === oldQty) { closeAdjustModal(); return; }

  await fetch('/api/items/' + item.id, { method: 'PUT', headers: apiHeaders(), body: JSON.stringify({...item, qty: newQty}) });
  await fetchAllData();

  const sign = type === 'add' ? '+' : '-';
  auditLog('STOCK_ADJUST', `[${item.sku}] ${item.name} Qt: ${oldQty} → ${newQty} (${sign}${amount}). Note: ${note}`);
  
  showToast('Stock adjusted successfully!', 'success');
  closeAdjustModal();
  renderInventory();
  renderOverview();
}

// --- Delete Confirm ---
let pendingDeleteId = null;
function confirmDelete(id, name) {
  pendingDeleteId = id;
  document.getElementById('confirmItemName').textContent = name;
  document.getElementById('confirmOverlay').classList.add('open');
}
function cancelDelete() { pendingDeleteId = null; document.getElementById('confirmOverlay').classList.remove('open'); }
async function executeDelete() {
  if (!pendingDeleteId) return;
  await deleteItem(pendingDeleteId);
  cancelDelete();
  showToast('Item deleted.', 'default');
  renderInventory();
  renderOverview();
}

// --- Filters ---
function setupFilters() {
  const searchEl = document.getElementById('searchInput');
  const catEl    = document.getElementById('catFilter');
  const statEl   = document.getElementById('statusFilter');
  if (!searchEl) return;
  searchEl.addEventListener('input',  () => { currentFilters.search   = sanitizeText(searchEl.value, 100); applyFilters(getItems()); });
  catEl.addEventListener('change',    () => { currentFilters.category = catEl.value;  applyFilters(getItems()); });
  statEl.addEventListener('change',   () => { currentFilters.status   = statEl.value; applyFilters(getItems()); });
}

// ================================================================
// REPORTS
// ================================================================
window.chartInstances = window.chartInstances || {};

window.switchReportTab = function(tabId, btnEl) {
  document.querySelectorAll('.report-tab-content').forEach(el => el.style.display = 'none');
  document.querySelectorAll('.reports-tabs .tab-btn').forEach(el => {
    el.classList.remove('active');
    el.style.borderBottomColor = 'transparent';
  });
  
  document.getElementById('rep-' + tabId).style.display = 'block';
  btnEl.classList.add('active');
  btnEl.style.borderBottomColor = 'var(--primary)';
}

window.renderReports = function() {
  const monthFilter = document.getElementById('reportMonthFilter').value; // 'YYYY-MM' or empty
  let targetYear = null, targetMonth = null;
  if (monthFilter) {
    const parts = monthFilter.split('-');
    targetYear = parseInt(parts[0]);
    targetMonth = parseInt(parts[1]) - 1; // 0-indexed month
  }
  
  const inMonth = (dateStr) => {
    if (!targetYear) return true;
    const d = new Date(dateStr);
    return d.getFullYear() === targetYear && d.getMonth() === targetMonth;
  };
  
  // 1. Monthly Summary Data
  const monthlyBatches = _batches.filter(b => inMonth(b.created_at));
  const mProdQty = monthlyBatches.reduce((sum, b) => sum + b.produced_qty, 0);
  
  let mTrimQty = 0;
  let mFabQty = 0;
  let mTotalCost = 0;
  monthlyBatches.forEach(b => {
      b.materials.forEach(m => {
          const mItem = _items.find(i => i.id === m.material_id);
          const uCost = mItem ? (parseFloat(mItem.unit_cost) || 0) : 0;
          if (m.material_type === 'trim') { mTrimQty += m.consumed_qty; mTotalCost += (m.consumed_qty * uCost); }
          if (m.material_type === 'fabric') { mFabQty += m.consumed_qty; mTotalCost += (m.consumed_qty * uCost); }
      });
  });

  const fmtN = (n) => typeof n === 'number' ? n.toLocaleString() : n;
  const fmtP = (n) => typeof n === 'number' ? n.toLocaleString(undefined, {minimumFractionDigits:2, maximumFractionDigits:2}) : n;

  const rmProd = document.getElementById('rm-prod-qty');
  if (rmProd) rmProd.textContent = fmtN(mProdQty);
  const rmTrim = document.getElementById('rm-trim-qty');
  if (rmTrim) rmTrim.textContent = fmtN(mTrimQty);
  const rmFab = document.getElementById('rm-fab-qty');
  if (rmFab) rmFab.textContent = fmtN(mFabQty) + 'm';
  const rmCost = document.getElementById('do-month-cost');
  if (rmCost) rmCost.textContent = '$' + fmtP(mTotalCost);
  const rmTotalCost = document.getElementById('rm-total-cost');
  if (rmTotalCost) rmTotalCost.textContent = '$' + fmtP(mTotalCost);
  
  // Low Stock
  const lowItems = _items.filter(i => stockStatus(i) === 'low' || stockStatus(i) === 'out');
  const rmLowBody = document.getElementById('rm-lowstock-tbody');
  if (rmLowBody) {
      if (lowItems.length === 0) {
          rmLowBody.innerHTML = '<tr><td colspan="5"><p class="empty-state">No low stock items</p></td></tr>';
      } else {
          rmLowBody.innerHTML = lowItems.map(i => {
              const isOut = stockStatus(i) === 'out';
              return `<tr>
                  <td>${esc(i.name)}</td>
                  <td><span class="badge badge-${catBadge(i.category)}">${esc(i.category)}</span></td>
                  <td style="color:var(--${isOut ? 'danger' : 'warning'}); font-weight:bold;">${fmtN(i.qty)}</td>
                  <td>${fmtN(i.threshold)}</td>
                  <td>${isOut ? 'Empty' : 'Low'}</td>
              </tr>`;
          }).join('');
      }
  }

  // 2. Product Report
  const productBody = document.getElementById('rep-product-tbody');
  if (productBody) {
      if (monthlyBatches.length === 0) {
          productBody.innerHTML = '<tr><td colspan="4"><p class="empty-state">No batches found for this month</p></td></tr>';
      } else {
          productBody.innerHTML = monthlyBatches.map(b => {
              const prod = _items.find(i => i.id === b.product_id || i.sku === b.product_id || i.name === b.product_id) || { name: b.product_id };
              return `<tr>
                  <td>#${b.batch_number}</td>
                  <td>${esc(prod.name)}</td>
                  <td>${b.produced_qty}</td>
                  <td>${new Date(b.created_at).toLocaleDateString()}</td>
              </tr>`;
          }).join('');
      }
  }
  
  // 3. Trim Report
  const trimBody = document.getElementById('rep-trim-tbody');
  if (trimBody) {
      const trims = _items.filter(i => i.category === 'Trim');
      if (trims.length === 0) {
          trimBody.innerHTML = '<tr><td colspan="4"><p class="empty-state">No trims found</p></td></tr>';
      } else {
          trimBody.innerHTML = trims.map(i => {
              const st = stockStatus(i);
              return `<tr>
                  <td>${esc(i.name)}</td>
                  <td style="font-weight:600; color:${st === 'low' ? 'var(--warning)' : st === 'out' ? 'var(--danger)' : 'var(--text)'}">${i.qty}</td>
                  <td>${i.threshold}</td>
                  <td><span class="badge badge-${st==='in'?'in':(st==='out'?'out':'low')}">${st.toUpperCase()}</span></td>
              </tr>`;
          }).join('');
      }
  }

  // 4. Fabric Report
  const fabBody = document.getElementById('rep-fabric-tbody');
  if (fabBody) {
      const fabs = _items.filter(i => i.category === 'Fabric' || i.category === 'Raw Materials' && i.unit==='meters');
      if (fabs.length === 0) {
          fabBody.innerHTML = '<tr><td colspan="4"><p class="empty-state">No fabrics found</p></td></tr>';
      } else {
          fabBody.innerHTML = fabs.map(i => {
              const st = stockStatus(i);
              return `<tr>
                  <td>${esc(i.name)}</td>
                  <td style="font-weight:600; color:${st === 'low' ? 'var(--warning)' : st === 'out' ? 'var(--danger)' : 'var(--text)'}">${i.qty} ${esc(i.unit)}</td>
                  <td>${i.threshold}</td>
                  <td><span class="badge badge-${st==='in'?'in':(st==='out'?'out':'low')}">${st.toUpperCase()}</span></td>
              </tr>`;
          }).join('');
      }
  }

  // 5. Production Report
  const prodRepBody = document.getElementById('rep-production-tbody');
  if (prodRepBody) {
      if (monthlyBatches.length === 0) {
          prodRepBody.innerHTML = '<tr><td colspan="5"><p class="empty-state">No production runs found for this month</p></td></tr>';
      } else {
          prodRepBody.innerHTML = monthlyBatches.map(b => {
              const prod = _items.find(i => i.id === b.product_id || i.sku === b.product_id || i.name === b.product_id) || { name: b.product_id };
              const sortedStages = (b.stages || []).slice().sort((a, b) => new Date(a.start_date) - new Date(b.start_date));
              const stageDetails = sortedStages.map(s => `<div><strong>${esc(s.stage_name)}:</strong> ${esc(s.start_date)} to ${esc(s.end_date)} <em style="color:var(--muted)">(${esc(s.duration)})</em></div>`).join('');
              return `<tr>
                  <td style="font-weight:bold;">#${b.batch_number}</td>
                  <td>${esc(prod.name)}</td>
                  <td>${b.produced_qty}</td>
                  <td>${esc(b.total_duration)}</td>
                  <td style="font-size:12px; line-height:1.5;">${stageDetails}</td>
              </tr>`;
          }).join('');
      }
  }
}

// ================================================================
// EXPORT CSV
// ================================================================
window.exportCSV = function() {
  const items = getItems();
  if (items.length === 0) { showToast('No data to export', 'error'); return; }
  
  const h = ['ID','Name','SKU','Category','Quantity','Unit','Low Threshold','Notes'];
  const rows = items.map(i => [
    i.id, i.name, i.sku, i.category, i.qty, i.unit, i.threshold, i.notes || ''
  ].map(field => `"${String(field).replace(/"/g, '""')}"`).join(','));
  
  const csvStr = h.join(',') + '\n' + rows.join('\n');
  const blob = new Blob([csvStr], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  
  const a = document.createElement('a');
  a.setAttribute('href', url);
  a.setAttribute('download', `nia_inventory_${new Date().toISOString().split('T')[0]}.csv`);
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  showToast('Inventory exported successfully', 'success');
};

// Theme is initialized at the end of the file.

// ================================================================
// HELPERS
// ================================================================
function stockStatus(item) {
  if (item.qty <= 0)             return 'out';
  if (item.qty <= item.threshold) return 'low';
  return 'in';
}
function catBadge(cat) {
  return { 'Products':'product', 'Trim':'raw', 'Fabric':'raw', 'Raw Materials':'raw', 'Packaging':'packaging', 'Other':'other' }[cat] || 'other';
}

// --- UI Helpers ---
window.togglePw = function(id, btn) {
  const input = document.getElementById(id);
  if (!input) return;
  if (input.type === 'password') {
    input.type = 'text';
    btn.innerHTML = `<svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21"/></svg>`;
  } else {
    input.type = 'password';
    btn.innerHTML = `<svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/></svg>`;
  }
};

// ================================================================
// MANUFACTURING: TRIMS
// ================================================================
window.toggleTrimAccordion = function(id) {
  const allAcc = document.querySelectorAll('.dash-accordion.trim-acc');
  const target = document.getElementById(id);
  
  if (target.classList.contains('open')) {
    target.classList.remove('open');
  } else {
    allAcc.forEach(acc => acc.classList.remove('open'));
    target.classList.add('open');
  }
}

window.addTrimStock = async function(trimId) {
  const inputEl = document.getElementById(`adj-trim-${trimId}`);
  if (!inputEl) return;
  const amount = parseFloat(inputEl.value);
  if (!amount || amount <= 0) return showToast('Enter a valid amount to add', 'error');

  const item = _items.find(i => i.id === trimId);
  if (!item) return;

  try {
    const res = await fetch('/api/items/stock', {
      method: 'POST',
      headers: apiHeaders(),
      body: JSON.stringify({ item_id: trimId, type: 'in', amount: amount, notes: 'Manual Trim Addition' })
    });
    if (!res.ok) throw new Error('Failed to add trim stock');
    inputEl.value = '';
    showToast('Trim stock added successfully', 'success');
    await fetchAllData();
    renderTrimStock();
    renderInventory();
    renderOverview();
  } catch(e) {
    showToast(e.message, 'error');
  }
}

window.renderTrimStock = function() {
  const container = document.getElementById('trimsAccordionContainer');
  if (!container) return;
  
  const trims = _items.filter(i => i.category === 'Trim' || i.category === 'Raw Material — Trim');
  if (trims.length === 0) {
    container.innerHTML = '<div class="empty-state"><p>No trim items found in inventory.</p></div>';
    return;
  }

  container.innerHTML = trims.map(t => {
    const isLowStock = t.qty <= t.threshold;
    const badgeHtml = isLowStock ? `<span class="badge badge-out" style="margin-left:12px;">Low Stock</span>` : '';

    return `
      <div class="dash-accordion trim-acc" id="t-acc-${t.id}">
        <div class="dash-accordion-header" onclick="toggleTrimAccordion('t-acc-${t.id}')">
          <div class="dash-accordion-title">
            <svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.121 14.121L19 19m-4.879-4.879l-4.242-4.242m4.242 4.242L11.293 17m2.828-2.828l2.828-2.828m-7.071 7.071L7.05 16.95m7.071-7.071L9.172 4.929M4.929 9.172l4.243 4.243m0 0L4.93 17.657"/></svg>
            ${esc(t.name)}
            ${badgeHtml}
          </div>
          <div style="display:flex; align-items:center; gap:16px;">
            <span class="dash-accordion-stat">${t.qty} ${esc(t.unit || 'pcs')}</span>
            <svg class="dash-accordion-chevron" width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/></svg>
          </div>
        </div>
        <div class="dash-accordion-body">
          <div class="dash-accordion-content">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:16px;">
              <div style="display:flex; gap:24px;">
                <div>
                  <div style="font-size:12px; color:var(--muted); font-weight:600; text-transform:uppercase;">Trim SKU</div>
                  <div style="font-size:16px; font-weight:600;">${esc(t.sku)}</div>
                </div>
              </div>
              <div style="display:flex; gap:8px; align-items:center;">
                <input type="number" step="any" id="adj-trim-${t.id}" placeholder="Qty" style="width:80px; padding:8px; border:1px solid var(--border); border-radius:4px; font-family:inherit;">
                <button class="btn btn-secondary" style="border-color:var(--success); color:var(--success);" onclick="addTrimStock('${t.id}')">
                  <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg> Add
                </button>
              </div>
            </div>
            <div style="margin-top:12px; font-size:13px; color:var(--muted);">
              Note: Trim stock can only be manually added. Subtractions happen automatically when creating a Production Batch.
            </div>
          </div>
        </div>
      </div>
    `;
  }).join('');
}

window.openTrimCreationModal = function() {
  openAddModal();
  setTimeout(() => {
    const cat = document.getElementById('f-category');
    if (cat) {
      cat.value = 'Trim';
      const row = cat.closest('.form-group');
      if (row) row.style.display = 'none';
    }
  }, 20);
};

window.openFabricCreationModal = function() {
  openAddModal();
  setTimeout(() => {
    const cat = document.getElementById('f-category');
    if (cat) {
      cat.value = 'Fabric';
      const row = cat.closest('.form-group');
      if (row) row.style.display = 'none';
    }
  }, 20);
};

// Modal triggers for specific categories
window.openTrimCreationModal = function() {
  openAddModal();
  document.getElementById('modalTitle').textContent = 'Add New Trim Material';
  const cat = document.getElementById('f-category');
  cat.value = 'Trim';
  cat.closest('.form-group').style.display = 'none';
};

window.openFabricCreationModal = function() {
  openAddModal();
  document.getElementById('modalTitle').textContent = 'Add New Fabric Material';
  const cat = document.getElementById('f-category');
  cat.value = 'Fabric';
  cat.closest('.form-group').style.display = 'none';
};

// Restore category row visibility when modal closes
const _baseCloseModal = closeModal;
window.closeModal = function() {
  _baseCloseModal();
  const cat = document.getElementById('f-category');
  if (cat) {
    const row = cat.closest('.form-group');
    if (row) row.style.display = '';
  }
};

// ================================================================
// MANUFACTURING: FABRICS (accordion, add-only)
// ================================================================

window.toggleFabricAccordion = function(id) {
  const allAcc = document.querySelectorAll('.dash-accordion.fab-acc');
  const target = document.getElementById(id);
  if (target.classList.contains('open')) {
    target.classList.remove('open');
  } else {
    allAcc.forEach(acc => acc.classList.remove('open'));
    target.classList.add('open');
  }
};

window.addFabricStock = async function(fabricId) {
  const inputEl = document.getElementById(`adj-fab-${fabricId}`);
  if (!inputEl) return;
  const amount = parseFloat(inputEl.value);
  if (!amount || amount <= 0) return showToast('Enter a valid amount to add', 'error');
  try {
    const res = await fetch('/api/items/stock', {
      method: 'POST',
      headers: apiHeaders(),
      body: JSON.stringify({ item_id: fabricId, type: 'in', amount, notes: 'Manual Fabric Addition' })
    });
    if (!res.ok) throw new Error('Failed to add fabric stock');
    inputEl.value = '';
    showToast('Fabric stock added successfully', 'success');
    await fetchAllData();
    renderFabricStock();
    renderInventory();
    renderOverview();
  } catch(e) {
    showToast(e.message, 'error');
  }
};

window.renderFabricStock = function() {
  const container = document.getElementById('fabricsAccordionContainer');
  if (!container) return;

  const fabrics = getMaterialsByCategory('Fabric');
  if (fabrics.length === 0) {
    container.innerHTML = '<div class="empty-state"><p>No fabric items found in inventory.</p></div>';
    return;
  }

  container.innerHTML = fabrics.map(f => {
    const isLowStock = f.qty <= f.threshold;
    const badgeHtml = isLowStock ? `<span class="badge badge-out" style="margin-left:12px;">Low Stock</span>` : '';
    return `
      <div class="dash-accordion fab-acc" id="f-acc-${f.id}">
        <div class="dash-accordion-header" onclick="toggleFabricAccordion('f-acc-${f.id}')">
          <div style="display:flex; align-items:center;">
            <span style="font-size:18px; margin-right:10px;">🧵</span>
            <div>
              <div style="font-weight:600; font-size:15px;">${esc(f.name)}${badgeHtml}</div>
              <div style="font-size:13px; color:var(--muted);">SKU: ${esc(f.sku)}</div>
            </div>
          </div>
          <div style="display:flex; align-items:center; gap:16px;">
            <div style="text-align:right;">
              <div style="font-size:22px; font-weight:700; color:${isLowStock ? 'var(--danger)' : 'var(--success)'}">${f.qty}</div>
              <div style="font-size:11px; color:var(--muted); text-transform:uppercase;">${esc(f.unit || 'm')}</div>
            </div>
            <svg class="acc-chevron" width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/></svg>
          </div>
        </div>
        <div class="dash-accordion-body">
          <div class="dash-accordion-content">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:16px;">
              <div style="display:flex; gap:24px;">
                <div>
                  <div style="font-size:12px; color:var(--muted); font-weight:600; text-transform:uppercase;">Fabric SKU</div>
                  <div style="font-size:16px; font-weight:600;">${esc(f.sku)}</div>
                </div>
              </div>
              <div style="display:flex; gap:8px; align-items:center;">
                <input type="number" step="any" id="adj-fab-${f.id}" placeholder="Qty" style="width:80px; padding:8px; border:1px solid var(--border); border-radius:4px; font-family:inherit;">
                <button class="btn btn-secondary" style="border-color:var(--success); color:var(--success);" onclick="addFabricStock('${f.id}')">
                  <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg> Add
                </button>
              </div>
            </div>
            <div style="margin-top:12px; font-size:13px; color:var(--muted);">
              Note: Fabric stock can only be manually added. Subtractions happen automatically when creating a Production Batch.
            </div>
          </div>
        </div>
      </div>
    `;
  }).join('');
};

// Alias so existing navigateTo dispatch still works
window.renderFabrics = window.renderFabricStock;

// ================================================================
// PRODUCTS (STOCK)
// ================================================================

window.toggleProductAccordion = function(id) {
  const allAcc = document.querySelectorAll('.dash-accordion.prod-acc');
  const target = document.getElementById(id);
  
  if (target.classList.contains('open')) {
    target.classList.remove('open');
  } else {
    allAcc.forEach(acc => acc.classList.remove('open'));
    target.classList.add('open');
  }
}

window.adjustProductStock = async function(productId, action) {
  const inputEl = document.getElementById(`adj-prod-${productId}`);
  if (!inputEl) return;
  const amount = parseInt(inputEl.value);
  if (!amount || amount <= 0) return showToast('Enter a valid amount', 'error');

  const item = _items.find(i => i.id === productId);
  if (!item) return;

  if (action === 'sub') {
    // Task #4: Standard stock subtraction
    if (item.qty < amount) return showToast('Insufficient stock to subtract', 'error');
    try {
      const res = await fetch('/api/items/stock', {
        method: 'POST',
        headers: apiHeaders(),
        body: JSON.stringify({ item_id: productId, type: 'out', amount: amount, notes: 'Manual Product Subtraction' })
      });
      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.error || 'Failed to subtract stock');
      }
      inputEl.value = '';
      showToast('Stock subtracted successfully', 'success');
      await fetchAllData();
      renderProductStock();
      renderInventory();
      renderOverview();
    } catch(e) {
      showToast(e.message, 'error');
    }
  } else {
    // Add stock via simple stock-in endpoint (not production)
    try {
      const res = await fetch('/api/items/stock', {
        method: 'POST',
        headers: apiHeaders(),
        body: JSON.stringify({ item_id: productId, type: 'in', amount: amount, notes: 'Product stock added' })
      });
      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.error || 'Failed to add stock');
      }
      inputEl.value = '';
      showToast('Stock added successfully', 'success');
      await fetchAllData();
      renderProductStock();
      renderInventory();
      renderOverview();
    } catch(e) {
      showToast(e.message, 'error');
    }
  }
}

window.renderProductStock = function() {
  const container = document.getElementById('productCardContainer');
  if (!container) return;
  
  const products = _items.filter(i => i.category === 'Products');
  if (products.length === 0) {
    container.innerHTML = '<div class="empty-state" style="grid-column:1/-1"><p>No products found. Add products in the Material Master List.</p></div>';
    return;
  }

  container.innerHTML = products.map(p => {
    const imgHtml = p.image_url
      ? `<img src="${esc(p.image_url)}" alt="${esc(p.name)}"/>`
      : `<div class="no-img">📦</div>`;
    const stockColor = p.qty <= 0 ? 'var(--danger)' : p.qty <= p.threshold ? 'var(--warning)' : 'var(--success)';
    return `
      <div class="product-card" id="pcard-${p.id}" onclick="toggleProductCardSelect('${p.id}')">
        <div class="product-card-img">${imgHtml}</div>
        <div class="product-card-body">
          <div class="product-card-name">${esc(p.name)}</div>
          <div class="product-card-sku">${esc(p.sku)}</div>
          <div class="product-card-qty" style="color:${stockColor}">${p.qty} in stock</div>
        </div>
      </div>
    `;
  }).join('');
};

window.toggleProductCardSelect = function(id) {
  // Cards just show the product; actual selection happens in the Sale modal
};

window.toggleProductAccordion = function(id) {};

// ================================================================
// PRODUCTION REPORT (BATCHES)
// ================================================================

window.toggleBatchAccordion = function(id) {
  const allAcc = document.querySelectorAll('.dash-accordion.batch-acc');
  const target = document.getElementById(id);
  if (target.classList.contains('open')) {
    target.classList.remove('open');
  } else {
    allAcc.forEach(acc => acc.classList.remove('open'));
    target.classList.add('open');
  }
};

window.openProductionModal = function() {
  const modal = document.getElementById('productionModal');
  const selectEl = document.getElementById('prod-product');
  
  // Populate product dropdown
  const products = _items.filter(i => i.category === 'Products');
  selectEl.innerHTML = '<option value="" disabled selected>Select a product...</option>' + 
    products.map(p => `<option value="${esc(p.id)}">${esc(p.name)} (${esc(p.sku)})</option>`).join('');

  // Reset basic info
  selectEl.value = '';
  const isAdmin = getSession()?.role === 'admin';
  document.getElementById('prod-summary-cost-container').style.display = isAdmin ? 'block' : 'none';
  document.getElementById('prod-summary-cost').textContent = '0.00 ETB';
  
  const gridCols = isAdmin ? '2fr 1fr 1fr 1fr 30px' : '2fr 1fr 30px';
  const headerHtml = `<div style="display:grid; grid-template-columns: ${gridCols}; gap:8px; padding:0 0 8px 0; font-size:11px; font-weight:700; color:var(--muted); text-transform:uppercase;">
    <div>Type/color</div>
    <div>Quantity</div>
    ${isAdmin ? '<div>Unit Cost</div><div>Total</div>' : ''}
    <div></div>
  </div>`;
  
  document.getElementById('prod-trim-rows').innerHTML = headerHtml + '<div class="empty-placeholder" style="font-size:13px; color:var(--muted); padding:8px 0;">Click "+ Add Trim" to log trim usage.</div>';
  document.getElementById('prod-fabric-rows').innerHTML = headerHtml + '<div class="empty-placeholder" style="font-size:13px; color:var(--muted); padding:8px 0;">Click "+ Add Fabric" to log fabric usage.</div>';
  
  // Render Stages (fixed 5)
  const stages = ['Trim Prep', 'Fabric Cut Prep', 'Print Prep', 'Sewing', 'Finishing & QC'];
  const stageContainer = document.getElementById('prod-stages-container');
  stageContainer.innerHTML = stages.map((s, i) => `
    <div style="display:grid; grid-template-columns: 1fr 1fr 1fr; gap:8px; align-items:center; background:var(--bg); padding:10px; border-radius:6px; border:1px solid var(--border);">
      <div style="font-weight:600; font-size:13px;">${s}</div>
      <input type="date" class="stage-start" data-stage="${s}" data-index="${i}" onchange="validateStageDates(this); updateProductionSummary()" style="padding:6px; font-size:12px; border:1px solid var(--border); border-radius:4px; font-family:inherit;">
      <input type="date" class="stage-end" data-stage="${s}" data-index="${i}" onchange="validateStageDates(this); updateProductionSummary()" style="padding:6px; font-size:12px; border:1px solid var(--border); border-radius:4px; font-family:inherit;">
    </div>
  `).join('');

  updateProductionSummary();
  modal.classList.add('open');
};

window.closeProductionModal = function() {
  document.getElementById('productionModal').classList.remove('open');
};

window.addProductionTrimRow = function() {
  const container = document.getElementById('prod-trim-rows');
  const placeholder = container.querySelector('.empty-placeholder');
  if (placeholder) placeholder.remove();

  const trims = getMaterialsByCategory('Trim');
  const isAdmin = getSession()?.role === 'admin';
  const div = document.createElement('div');
  div.className = 'prod-material-row';
  div.style = `display:grid; grid-template-columns: ${isAdmin ? '2fr 1fr 1fr 1fr 30px' : '2fr 1fr 30px'}; gap:8px; align-items:center; margin-bottom:8px;`;
  
  div.innerHTML = `
    <select class="mat-id" onchange="const c=this.options[this.selectedIndex].dataset.cost; const row=this.closest('.prod-material-row'); const costIn=row.querySelector('.mat-cost'); if(costIn){costIn.value=c; calcRowTotal(costIn);}" style="padding:8px; border:1px solid var(--border); border-radius:4px; font-family:inherit;">
      <option value="" disabled selected>Select Trim...</option>
      ${trims.map(t => `<option value="${t.id}" data-cost="${t.unit_cost||0}">${esc(t.name)}</option>`).join('')}
    </select>
    <input type="number" class="mat-qty" placeholder="Qty" oninput="calcRowTotal(this)" style="padding:8px; border:1px solid var(--border); border-radius:4px; font-family:inherit;">
    ${isAdmin ? `
      <input type="number" class="mat-cost" placeholder="Cost" readonly oninput="calcRowTotal(this)" style="padding:8px; border:1px solid var(--border); border-radius:4px; font-family:inherit; background:var(--bg);">
      <div class="row-total" style="font-weight:700; font-size:13px; text-align:right;">0.00</div>
    ` : ''}
    <button onclick="this.parentElement.remove(); updateGrandTotal();" style="background:none; border:none; color:var(--danger); cursor:pointer; font-size:18px;">×</button>
  `;
  container.appendChild(div);
};

window.addProductionFabricRow = function() {
  const container = document.getElementById('prod-fabric-rows');
  const placeholder = container.querySelector('.empty-placeholder');
  if (placeholder) placeholder.remove();

  const fabrics = getMaterialsByCategory('Fabric');
  const isAdmin = getSession()?.role === 'admin';
  const div = document.createElement('div');
  div.className = 'prod-material-row';
  div.style = `display:grid; grid-template-columns: ${isAdmin ? '2fr 1fr 1fr 1fr 30px' : '2fr 1fr 30px'}; gap:8px; align-items:center; margin-bottom:8px;`;
  
  div.innerHTML = `
    <select class="mat-id" onchange="const c=this.options[this.selectedIndex].dataset.cost; const row=this.closest('.prod-material-row'); const costIn=row.querySelector('.mat-cost'); if(costIn){costIn.value=c; calcRowTotal(costIn);}" style="padding:8px; border:1px solid var(--border); border-radius:4px; font-family:inherit;">
      <option value="" disabled selected>Select Fabric...</option>
      ${fabrics.map(f => `<option value="${f.id}" data-cost="${f.unit_cost||0}">${esc(f.name)}</option>`).join('')}
    </select>
    <input type="number" step="any" class="mat-qty" placeholder="Meters" oninput="calcRowTotal(this)" style="padding:8px; border:1px solid var(--border); border-radius:4px; font-family:inherit;">
    ${isAdmin ? `
      <input type="number" class="mat-cost" placeholder="Cost" readonly oninput="calcRowTotal(this)" style="padding:8px; border:1px solid var(--border); border-radius:4px; font-family:inherit; background:var(--bg);">
      <div class="row-total" style="font-weight:700; font-size:13px; text-align:right;">0.00</div>
    ` : ''}
    <button onclick="this.parentElement.remove(); updateGrandTotal();" style="background:none; border:none; color:var(--danger); cursor:pointer; font-size:18px;">×</button>
  `;
  container.appendChild(div);
};

window.calcRowTotal = function(el) {
  const row = el.closest('.prod-material-row');
  const qty = parseFloat(row.querySelector('.mat-qty').value) || 0;
  const costInput = row.querySelector('.mat-cost');
  const cost = costInput ? parseFloat(costInput.value) || 0 : 0;
  const total = row.querySelector('.row-total');
  if (total) total.textContent = (qty * cost).toFixed(2);
  updateGrandTotal();
};

window.updateGrandTotal = function() {
  const totals = document.querySelectorAll('.row-total');
  let grandTotal = 0;
  totals.forEach(t => {
    grandTotal += parseFloat(t.textContent) || 0;
  });
  const sumEl = document.getElementById('prod-summary-cost');
  if (sumEl) sumEl.textContent = grandTotal.toFixed(2) + ' ETB';
};

window.updateProductionSummary = function() {
  const qty = document.getElementById('prod-qty').value || '—';
  document.getElementById('prod-summary-qty').textContent = qty;

  const starts = Array.from(document.querySelectorAll('.stage-start')).map(i => i.value).filter(v => v);
  const ends = Array.from(document.querySelectorAll('.stage-end')).map(i => i.value).filter(v => v);
  
  if (starts.length > 0 && ends.length > 0) {
    const minStart = new Date(Math.min(...starts.map(s => new Date(s))));
    const maxEnd = new Date(Math.max(...ends.map(e => new Date(e))));
    document.getElementById('prod-summary-duration').textContent = formatDuration(minStart, maxEnd);
  } else {
    document.getElementById('prod-summary-duration').textContent = '—';
  }
};

// Task #15 & #2: Real-time date validation for production stages with overlap detection
window.validateStageDates = function(inputElement) {
  const row = inputElement.closest('div[style*="grid-template-columns"]');
  if (!row) return;
  
  const startInput = row.querySelector('.stage-start');
  const endInput = row.querySelector('.stage-end');
  
  if (!startInput || !endInput) return;
  
  const startDate = startInput.value;
  const endDate = endInput.value;
  const currentIndex = parseInt(startInput.dataset.index);
  
  // Validate within same stage: end date must be >= start date
  if (startDate && endDate) {
    const start = new Date(startDate);
    const end = new Date(endDate);
    
    if (end < start) {
      // Show error
      endInput.style.borderColor = 'var(--danger)';
      endInput.style.borderWidth = '2px';
      showToast('End date cannot be before start date!', 'error');
      
      // Reset the end date
      endInput.value = '';
      setTimeout(() => {
        endInput.style.borderColor = '';
        endInput.style.borderWidth = '';
      }, 2000);
      return;
    }
  }

  
  // Valid date range - clear any error styling
  startInput.style.borderColor = '';
  startInput.style.borderWidth = '';
  endInput.style.borderColor = '';
  endInput.style.borderWidth = '';
  
  // Set min attribute on end date based on start date
  if (startDate && inputElement.classList.contains('stage-start')) {
    endInput.setAttribute('min', startDate);
  }
};

function formatDuration(d1, d2) {
  const diff = d2 - d1;
  const days = Math.ceil(diff / (1000 * 60 * 60 * 24)) + 1;
  if (days <= 0) return '0 days';
  if (days < 7) return days + (days === 1 ? ' day' : ' days');
  const w = Math.floor(days / 7);
  return w + (w === 1 ? ' Week' : ' Weeks');
}

window.saveProduction = async function() {
  const productId = document.getElementById('prod-product').value;
  const producedQty = parseInt(document.getElementById('prod-qty').value);
  if (!productId || !producedQty) return showToast('Please enter a product and quantity', 'error');

  const materials = [];
  document.querySelectorAll('#prod-trim-rows .prod-material-row').forEach(row => {
    const mId = row.querySelector('.mat-id').value;
    const mQty = parseFloat(row.querySelector('.mat-qty').value);
    if (mId && mQty > 0) {
      materials.push({
        material_id: mId,
        type: 'trim',
        consumed_qty: mQty,
        unit_cost: parseFloat(row.querySelector('.mat-cost')?.value) || 0,
        total_cost: parseFloat(row.querySelector('.row-total')?.textContent) || 0
      });
    }
  });
  document.querySelectorAll('#prod-fabric-rows .prod-material-row').forEach(row => {
    const mId = row.querySelector('.mat-id').value;
    const mQty = parseFloat(row.querySelector('.mat-qty').value);
    if (mId && mQty > 0) {
      materials.push({
        material_id: mId,
        type: 'fabric',
        consumed_qty: mQty,
        unit_cost: parseFloat(row.querySelector('.mat-cost')?.value) || 0,
        total_cost: parseFloat(row.querySelector('.row-total')?.textContent) || 0
      });
    }
  });

  // Task #7: Validate sufficient stock for materials
  for (let mat of materials) {
    const item = _items.find(i => i.id === mat.material_id);
    if (item && item.qty < mat.consumed_qty) {
      showToast(`Insufficient stock for ${item.name}! Available: ${item.qty}, Required: ${mat.consumed_qty}`, 'error');
      return;
    }
  }

  const stages = [];
  document.querySelectorAll('#prod-stages-container > div').forEach(row => {
    const name = row.children[0].textContent;
    const start = row.querySelector('.stage-start').value;
    const end = row.querySelector('.stage-end').value;
    if (start && end) {
      // Task #9: Validate no date overlaps
      const startDate = new Date(start);
      const endDate = new Date(end);
      if (endDate < startDate) {
        showToast(`Invalid dates for ${name}: End date cannot be before start date`, 'error');
        return;
      }
      stages.push({
        stage_name: name,
        start_date: start,
        end_date: end,
        duration: formatDuration(startDate, endDate)
      });
    }
  });

  if (stages.length === 0) return showToast('Please enter dates for at least one stage', 'error');

  // Sort stages chronologically by start date
  stages.sort((a, b) => new Date(a.start_date) - new Date(b.start_date));

  const totalDuration = document.getElementById('prod-summary-duration').textContent;

  try {
    const res = await fetch('/api/batches', {
      method: 'POST',
      headers: apiHeaders(),
      body: JSON.stringify({ product_id: productId, produced_qty: producedQty, total_duration: totalDuration, materials, stages })
    });
    if (!res.ok) {
      const errorData = await res.json();
      throw new Error(errorData.error || 'Failed to save production batch');
    }
    showToast('Production entry saved and inventory updated!', 'success');
    closeProductionModal();
    await fetchAllData();
    renderBatches();
    renderInventory();
    renderOverview();
  } catch(e) {
    showToast(e.message, 'error');
  }
};

window.renderBatches = function() {
  const container = document.getElementById('batchAccordionContainer');
  if (!container) return;
  if (_batches.length === 0) {
    container.innerHTML = '<div class="empty-state"><p>No production batches recorded</p></div>';
    return;
  }

  const isAdmin = getSession()?.role === 'admin';

  container.innerHTML = _batches.map(b => {
    const date = new Date(b.created_at).toLocaleDateString('en-GB');
    const product = _items.find(i => i.id === b.product_id || i.sku === b.product_id || i.name === b.product_id);
    const productName = product ? product.name : b.product_id;
    const batchDisplay = `#${b.batch_number.toString().padStart(3, '0')}`;
    
    let materialHtml = '';
    if (b.materials && b.materials.length > 0) {
      materialHtml = b.materials.map(m => {
        const mat = _items.find(i => i.id === m.material_id);
        const name = mat ? mat.name : m.material_id;
        return `
          <tr style="border-bottom:1px solid var(--border);">
            <td style="padding:10px 0;">
              <div style="font-weight:600; font-size:13px;">${esc(name)}</div>
              <div style="font-size:11px; color:var(--muted); text-transform:uppercase;">${m.material_type}</div>
            </td>
            <td style="padding:10px 0; font-weight:600;">${m.consumed_qty}</td>
            ${isAdmin ? `
              <td style="padding:10px 0; color:var(--muted);">$${(m.unit_cost||0).toFixed(2)}</td>
              <td style="padding:10px 0; font-weight:600; text-align:right;">$${(m.total_cost||0).toFixed(2)}</td>
            ` : ''}
          </tr>
        `;
      }).join('');
    } else {
      materialHtml = '<tr><td colspan="4" style="padding:12px; text-align:center; color:var(--muted); font-size:13px;">No materials recorded for this batch.</td></tr>';
    }

    let stageHtml = '';
    if (b.stages && b.stages.length > 0) {
      const sortedBatchStages = b.stages.slice().sort((a, c) => new Date(a.start_date) - new Date(c.start_date));
      stageHtml = sortedBatchStages.map(s => `
        <div style="display:flex; justify-content:space-between; align-items:center; padding:10px; background:var(--bg); border-radius:6px; margin-bottom:6px; font-size:13px;">
          <div style="font-weight:600;">${esc(s.stage_name)}</div>
          <div style="color:var(--muted); font-size:12px;">${new Date(s.start_date).toLocaleDateString()} — ${new Date(s.end_date).toLocaleDateString()}</div>
          <div style="font-weight:700; color:var(--primary);">${esc(s.duration)}</div>
        </div>
      `).join('');
    }

    return `
      <div class="dash-accordion">
        <div class="dash-accordion-header" onclick="this.parentElement.classList.toggle('open')">
          <div class="dash-accordion-title">
            <span class="dash-accordion-stat">${batchDisplay}</span>
            <div>
              <div style="font-weight:600; font-size:15px;">${esc(productName)}</div>
              <div style="font-size:12px; color:var(--muted);">${date}</div>
            </div>
          </div>
          <div style="display:flex; align-items:center; gap:16px;">
            <div style="text-align:right;">
              <div style="font-size:20px; font-weight:700;">${b.produced_qty}</div>
              <div style="font-size:11px; color:var(--muted); text-transform:uppercase;">Produced</div>
            </div>
            <svg class="dash-accordion-chevron" width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/></svg>
          </div>
        </div>
        <div class="dash-accordion-body">
          <div class="dash-accordion-content" style="display:grid; grid-template-columns: 1.5fr 1fr; gap:40px;">
            <div>
              <h4 style="font-size:12px; text-transform:uppercase; color:var(--muted); margin-bottom:12px;">Materials Used</h4>
              <table style="width:100%; border-collapse:collapse;">
                <thead>
                  <tr style="text-align:left; border-bottom:1px solid var(--border);">
                    <th style="padding-bottom:8px; font-size:11px; color:var(--muted);">Type/color</th>
                    <th style="padding-bottom:8px; font-size:11px; color:var(--muted);">Quantity</th>
                    ${isAdmin ? `
                      <th style="padding-bottom:8px; font-size:11px; color:var(--muted);">Unit Cost</th>
                      <th style="padding-bottom:8px; font-size:11px; color:var(--muted);">Total</th>
                    ` : ''}
                  </tr>
                </thead>
                <tbody>${materialHtml}</tbody>
              </table>
            </div>
            <div>
              <h4 style="font-size:12px; text-transform:uppercase; color:var(--muted); margin-bottom:12px;">Production Timeline</h4>
              ${stageHtml}
              ${isAdmin ? `<button class="btn btn-danger btn-sm" style="margin-top:24px; width:100%;" onclick="deleteBatch('${b.id}')">Delete Record</button>` : ''}
            </div>
          </div>
        </div>
      </div>
    `;
  }).join('');
};

window.deleteBatch = async function(id) {
  if (!confirm('Are you sure you want to delete this production record? Inventory will NOT be restored automatically.')) return;
  try {
    const res = await fetch('/api/batches/' + id, { method: 'DELETE', headers: apiHeaders() });
    if (!res.ok) throw new Error('Failed to delete batch');
    showToast('Record deleted', 'success');
    await fetchAllData();
    renderBatches();
  } catch(e) { showToast(e.message, 'error'); }
};


// ================================================================
// STOCK MOVEMENTS
// ================================================================
window.renderMovements = function renderMovements() {
  const tbody = document.getElementById('movementsTbody');
  if (!tbody) return;
  if (_stockMovements.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4"><div class="empty-state"><p>No stock movement logs found</p></div></td></tr>`;
    return;
  }
  
  tbody.innerHTML = _stockMovements.map(log => {
      const date = new Date(log.ts).toLocaleString('en-GB');
      
      // Parse details from: "[SKU] Name Qt: Old → New (+/-Amt). Note: reason"
      let typeBadge = 'other';
      if (log.detail.includes('(+)')) typeBadge = 'in'; 
      if (log.detail.includes('(-)')) typeBadge = 'out';
      
      let detailHtml = esc(log.detail);
      const noteSplit = detailHtml.split('. Note: ');
      if (noteSplit.length > 1) {
          detailHtml = `${noteSplit[0]}
          <div style="margin-top:6px; padding:6px 10px; background:var(--bg); border:1px solid var(--border); border-left:3px solid var(--accent); border-radius:4px;">
              <strong style="color:var(--text); font-size:0.95em;">Note: </strong>
              <span style="color:var(--text); font-weight:600; font-size:0.95em;">${noteSplit[1]}</span>
          </div>`;
      }
      
      return `<tr>
          <td style="white-space:nowrap;color:var(--muted);">${date}</td>
          <td><span class="badge badge-${typeBadge}">${log.detail.includes('(+)') ? 'IN' : 'OUT'}</span></td>
          <td>${esc(log.user)}</td>
          <td>${detailHtml}</td>
      </tr>`;
  }).join('');
};

window.initTheme = function() {
  const savedTheme = localStorage.getItem('nia_theme') || 'light';
  document.documentElement.setAttribute('data-theme', savedTheme);
  
  const updateLogos = (theme) => {
    const isDark = theme === 'dark';
    document.querySelectorAll('.sidebar-brand img').forEach(img => {
      img.src = isDark ? "/Images/NIA%20Dark%20mode.png" : "/Images/NIA%20Light%20mode.png";
    });
  };
  
  updateLogos(savedTheme);
  
  const themeBtn = document.getElementById('themeToggleBtn');
  if (themeBtn && !themeBtn.dataset.listenerAdded) {
    themeBtn.dataset.listenerAdded = 'true';
    themeBtn.addEventListener('click', (e) => {
      e.preventDefault();
      const current = document.documentElement.getAttribute('data-theme');
      const next = current === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      localStorage.setItem('nia_theme', next);
      updateLogos(next);
      
      // Re-render charts if on reports page
      const reportsPage = document.getElementById('page-reports');
      if (reportsPage && reportsPage.classList.contains('active')) {
        setTimeout(renderReports, 50);
      }
    });
  }
};

// Password visibility toggle function
window.togglePw = function(inputId, button) {
  const input = document.getElementById(inputId);
  if (!input) return;
  
  if (input.type === 'password') {
    input.type = 'text';
    button.innerHTML = '<svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21"/></svg>';
  } else {
    input.type = 'password';
    button.innerHTML = '<svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/></svg>';
  }
};

window.addEventListener('DOMContentLoaded', () => {
  // Global DOM init if needed
});
// ================================================================
// SALE MODAL LOGIC
// ================================================================
let saleSelectedItems = new Set();

window.openSaleModal = function() {
  const modal = document.getElementById('saleModal');
  const grid = document.getElementById('saleProductGrid');
  const buyerIn = document.getElementById('sale-buyer');
  
  if (buyerIn) buyerIn.value = '';
  saleSelectedItems.clear();
  
  const products = _items.filter(i => i.category === 'Products');
  if (products.length === 0) {
    grid.innerHTML = '<div class="empty-state" style="grid-column:1/-1;"><p>No products available to sell.</p></div>';
  } else {
    grid.innerHTML = products.map(p => {
      const imgHtml = p.image_url ? `<img src="${esc(p.image_url)}" alt="${esc(p.name)}"/>` : `<div class="no-img">📦</div>`;
      const stockColor = p.qty <= 0 ? 'var(--danger)' : p.qty <= p.threshold ? 'var(--warning)' : 'var(--success)';
      return `
        <div class="product-card" id="sale-card-${p.id}" onclick="toggleSaleProduct('${p.id}')">
          <div class="product-card-img">
            ${imgHtml}
          </div>
          <div class="product-card-check">
            <svg width="12" height="12" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 13l4 4L19 7"/></svg>
          </div>
          <div class="product-card-body">
            <div class="product-card-name">${esc(p.name)}</div>
            <div class="product-card-qty" style="color:${stockColor}">${p.qty} Available</div>
          </div>
        </div>
      `;
    }).join('');
  }
  
  renderSaleSelectedItems();
  modal.classList.add('open');
};

window.closeSaleModal = function() {
  document.getElementById('saleModal').classList.remove('open');
};

window.toggleSaleProduct = function(id) {
  const card = document.getElementById(`sale-card-${id}`);
  if (saleSelectedItems.has(id)) {
    saleSelectedItems.delete(id);
    card.classList.remove('selected');
  } else {
    saleSelectedItems.add(id);
    card.classList.add('selected');
  }
  renderSaleSelectedItems();
};

window.renderSaleSelectedItems = function() {
  const container = document.getElementById('saleSelectedItems');
  const rows = document.getElementById('saleQtyRows');
  
  if (saleSelectedItems.size === 0) {
    container.style.display = 'none';
    rows.innerHTML = '';
    return;
  }
  
  container.style.display = 'block';
  
  // Keep existing values if already rendered
  const existingValues = {};
  document.querySelectorAll('.sale-qty-input').forEach(input => {
    existingValues[input.dataset.id] = input.value;
  });

  let html = '';
  saleSelectedItems.forEach(id => {
    const p = _items.find(i => i.id === id);
    if (!p) return;
    const val = existingValues[id] || '1';
    html += `
      <div style="display:flex; justify-content:space-between; align-items:center; padding:8px; border:1px solid var(--border); border-radius:6px; margin-bottom:8px; background:var(--bg);">
        <div style="font-size:13px; font-weight:600;">${esc(p.name)} <span style="color:var(--muted); font-size:11px;">(${esc(p.sku)})</span></div>
        <div style="display:flex; align-items:center; gap:8px;">
          <span style="font-size:11px; color:var(--muted);">Max: ${p.qty}</span>
          <input type="number" class="sale-qty-input" data-id="${p.id}" value="${val}" min="1" max="${p.qty}" style="width:70px; padding:6px; border:1px solid var(--border); border-radius:4px; font-family:inherit;">
          <input type="number" class="sale-price-input" data-id="${p.id}" value="${p.unit_cost || 0}" step="0.01" style="width:80px; padding:6px; border:1px solid var(--border); border-radius:4px; font-family:inherit;" placeholder="Price">
          <button class="btn btn-secondary btn-sm" onclick="toggleSaleProduct('${p.id}')" style="padding:4px 8px; color:var(--danger); border:none;">×</button>
        </div>
      </div>
    `;
  });
  rows.innerHTML = html;
};

window.saveSale = async function() {
  const buyer = document.getElementById('sale-buyer').value.trim();
  if (!buyer) {
    return showToast('Please enter a buyer name.', 'error');
  }
  if (saleSelectedItems.size === 0) {
    return showToast('Please select at least one product.', 'error');
  }

  const items = [];
  let valid = true;
  document.querySelectorAll('.sale-qty-input').forEach(input => {
    const id = input.dataset.id;
    const qty = parseFloat(input.value);
    const p = _items.find(i => i.id === id);
    const priceInput = document.querySelector(`.sale-price-input[data-id="${id}"]`);
    const price = priceInput ? parseFloat(priceInput.value) : (p.unit_cost || 0);
    if (!qty || qty <= 0) {
      showToast(`Invalid quantity for ${p.name}`, 'error');
      valid = false;
    }
    if (qty > p.qty) {
      showToast(`Not enough stock for ${p.name}. Only ${p.qty} available.`, 'error');
      valid = false;
    }
    items.push({ item_id: id, qty, price });
  });

  if (!valid) return;

  try {
    const res = await fetch('/api/sales', {
      method: 'POST',
      headers: apiHeaders(),
      body: JSON.stringify({ buyer, items })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to log sale');
    
    showToast(`Sale logged for ${buyer}!`, 'success');
    closeSaleModal();
    await fetchAllData();
    renderProductStock();
    renderOverview();
    if(typeof renderSales === 'function') renderSales();
  } catch(e) {
    showToast(e.message, 'error');
  }
};

window.renderSales = function() {
  const tbody = document.getElementById('salesTbody');
  if (!tbody) return;
  if (_sales.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6"><div class="empty-state"><p>No sales history found</p></div></td></tr>';
    return;
  }

  const fmtN = (n) => typeof n === 'number' ? n.toLocaleString() : n;
  const fmtP = (n) => typeof n === 'number' ? n.toLocaleString(undefined, {minimumFractionDigits:2, maximumFractionDigits:2}) : n;

  // Group by exact timestamp + buyer
  const groups = {};
  _sales.forEach(s => {
      const key = s.ts + '|' + s.buyer;
      if(!groups[key]) groups[key] = { ts: s.ts, buyer: s.buyer, items: [], totalQty: 0, totalPrice: 0 };
      groups[key].items.push(s);
      groups[key].totalQty += s.qty;
      groups[key].totalPrice += (s.total_price || 0);
  });

  tbody.innerHTML = Object.values(groups).map((g, idx) => {
      const date = new Date(g.ts).toLocaleString('en-GB');
      const gId = 'sg-' + idx;
      
      let html = `<tr style="cursor:pointer;" onclick="const e = document.getElementById('${gId}'); const b = this.querySelector('.sg-btn'); if(e.style.display==='none'){e.style.display='table-row';b.textContent='▲';this.style.background='var(--hover)';}else{e.style.display='none';b.textContent='▼';this.style.background='';}">
        <td>${date}</td>
        <td style="font-weight:600;">${esc(g.buyer)}</td>
        <td>${g.items.length} Product(s) <span class="sg-btn" style="font-size:10px; color:var(--muted); margin-left:4px;">▼</span></td>
        <td style="font-weight:600;">${fmtN(g.totalQty)}</td>
        <td style="color:var(--muted)">—</td>
        <td style="font-weight:600; color:var(--success);">$${fmtP(g.totalPrice)}</td>
      </tr>`;
      
      html += `<tr id="${gId}" style="display:none; background:#fafafa;">
        <td colspan="6" style="padding:0;">
          <table style="width:100%; margin:0; background:transparent; border-top:1px solid var(--border);">
            <tbody>
              ${g.items.map(s => {
                  const item = _items.find(i => i.id === s.item_id);
                  const name = item ? item.name : s.item_id;
                  return `<tr>
                    <td style="width:16%;"></td>
                    <td style="width:16%;"></td>
                    <td style="color:var(--text); font-size:13px;">↳ ${esc(name)}</td>
                    <td style="width:16%;">${fmtN(s.qty)}</td>
                    <td style="width:16%;">$${fmtP(s.unit_price || 0)}</td>
                    <td style="width:16%; color:var(--success);">$${fmtP(s.total_price || 0)}</td>
                  </tr>`;
              }).join('')}
            </tbody>
          </table>
        </td>
      </tr>`;
      return html;
  }).join('');
};

// ================================================================
// RESTOCK MODAL LOGIC (Trim & Fabric)
// ================================================================
let restockSelectedItems = new Set();

window.openRestockModal = function() {
  const modal = document.getElementById('restockModal');
  const grid = document.getElementById('restockMaterialGrid');
  
  restockSelectedItems.clear();
  
  const materials = _items.filter(i => i.category === 'Trim' || i.category === 'Fabric');
  if (materials.length === 0) {
    grid.innerHTML = '<div class="empty-state" style="grid-column:1/-1;"><p>No materials available to restock.</p></div>';
  } else {
    grid.innerHTML = materials.map(m => {
      const imgHtml = m.image_url ? `<img src="${esc(m.image_url)}" alt="${esc(m.name)}"/>` : `<div class="no-img">🧵</div>`;
      return `
        <div class="product-card" id="restock-card-${m.id}" onclick="toggleRestockMaterial('${m.id}')">
          <div class="product-card-img">
            ${imgHtml}
          </div>
          <div class="product-card-check">
            <svg width="12" height="12" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 13l4 4L19 7"/></svg>
          </div>
          <div class="product-card-body">
            <div class="product-card-name">${esc(m.name)}</div>
            <div class="product-card-qty" style="color:var(--muted)">${m.qty} in stock</div>
          </div>
        </div>
      `;
    }).join('');
  }
  
  renderRestockSelectedItems();
  modal.classList.add('open');
};

window.closeRestockModal = function() {
  document.getElementById('restockModal').classList.remove('open');
};

window.toggleRestockMaterial = function(id) {
  const card = document.getElementById(`restock-card-${id}`);
  if (restockSelectedItems.has(id)) {
    restockSelectedItems.delete(id);
    card.classList.remove('selected');
  } else {
    restockSelectedItems.add(id);
    card.classList.add('selected');
  }
  renderRestockSelectedItems();
};

window.renderRestockSelectedItems = function() {
  const container = document.getElementById('restockSelectedItems');
  const rows = document.getElementById('restockQtyRows');
  
  if (restockSelectedItems.size === 0) {
    container.style.display = 'none';
    rows.innerHTML = '';
    return;
  }
  
  container.style.display = 'block';
  
  const existingValues = {};
  document.querySelectorAll('.restock-qty-input').forEach(input => {
    existingValues[input.dataset.id] = input.value;
  });

  let html = '';
  restockSelectedItems.forEach(id => {
    const m = _items.find(i => i.id === id);
    if (!m) return;
    const val = existingValues[id] || '';
    const unit = m.category === 'Fabric' ? 'meters' : 'units';
    html += `
      <div style="display:flex; justify-content:space-between; align-items:center; padding:8px; border:1px solid var(--border); border-radius:6px; margin-bottom:8px; background:var(--bg);">
        <div style="font-size:13px; font-weight:600;">${esc(m.name)} <span style="color:var(--muted); font-size:11px;">(${m.category})</span></div>
        <div style="display:flex; align-items:center; gap:8px;">
          <input type="number" class="restock-qty-input" data-id="${m.id}" value="${val}" min="0.01" step="any" placeholder="+ Qty (${unit})" style="width:100px; padding:6px; border:1px solid var(--border); border-radius:4px; font-family:inherit;">
          <button class="btn btn-secondary btn-sm" onclick="toggleRestockMaterial('${m.id}')" style="padding:4px 8px; color:var(--danger); border:none;">×</button>
        </div>
      </div>
    `;
  });
  rows.innerHTML = html;
};

window.saveRestock = async function() {
  if (restockSelectedItems.size === 0) {
    return showToast('Please select at least one material.', 'error');
  }

  const inputs = Array.from(document.querySelectorAll('.restock-qty-input'));
  
  // Validate all inputs first
  for (const input of inputs) {
    const qty = parseFloat(input.value);
    if (!qty || qty <= 0) {
      const p = _items.find(i => i.id === input.dataset.id);
      return showToast(`Invalid restock quantity for ${p.name}`, 'error');
    }
  }

  try {
    for (const input of inputs) {
      const id = input.dataset.id;
      const amount = parseFloat(input.value);
      
      const res = await fetch('/api/items/stock', {
        method: 'POST',
        headers: apiHeaders(),
        body: JSON.stringify({ item_id: id, type: 'in', amount: amount, notes: 'Restock materials' })
      });
      if (!res.ok) throw new Error('Failed to log restock for some items');
    }
    
    showToast(`Materials restocked successfully!`, 'success');
    closeRestockModal();
    await fetchAllData();
    renderInventory();
    renderOverview();
  } catch(e) {
    showToast(e.message, 'error');
  }
};
