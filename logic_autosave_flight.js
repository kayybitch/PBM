// ==UserScript==
// @name         PBWEB - VANGUARD ELITE
// @namespace    vanguardelite.local
// @version      2.4.0
// @description  VANGUARD ELITE (NOVA core: aimbot + ESP + full features + anti-kick + performance mode + key gate, keyless)
// @match        *://pbmobile.app/*
// @match        *://*.pbmobile.app/*
// @run-at       document-start
// @grant        none
// ==/UserScript==

(function (winArg) {
  'use strict';

  var W = (typeof unsafeWindow !== 'undefined' && unsafeWindow)
    ? unsafeWindow
    : ((typeof winArg !== 'undefined' && winArg) ? winArg : ((typeof globalThis !== 'undefined') ? globalThis : this));

  if (!W) return;
  if (W.__pb) return;

  /* ============================================================================
     0. AUTH GATE (FAIL-CLOSED) - KEY SERVER via Google Apps Script
     ============================================================================ */
  var AUTH_URL = 'https://script.google.com/macros/s/AKfycbwYaNeiyTo4DC0DFq1f9Mrepev_F-hP0GV4PB770fbgI_vpxU3btftf_6DVMdai6yik4g/exec';

  var AUTH_KEY = 'vanguard_auth_v1';
  var AUTH_DEVICE_KEY = 'vanguard_device_uuid_v1';
  var AUTH_TOKEN_TTL_MS = 24 * 60 * 60 * 1000;     // 24 jam offline tolerance
  var AUTH_STATE = { status: 'pending', reason: '', key: '', deviceId: '', token: '', tokenExp: 0, bound: '' };

  function authLog() {
    try { console.log.apply(console, ['[VANGUARD AUTH]'].concat([].slice.call(arguments))); } catch (e) {}
  }

  function sha256Hex(str) {
    var h1 = 0x811c9dc5, h2 = 0x01000193;
    for (var i = 0; i < str.length; i++) {
      var c = str.charCodeAt(i);
      h1 ^= c; h1 = (h1 * 16777619) >>> 0;
      h2 = ((h2 << 5) - h2 + c) >>> 0;
    }
    return ('00000000' + h1.toString(16)).slice(-8) + ('00000000' + h2.toString(16)).slice(-8);
  }

  function authDeviceUuid() {
    try {
      var existing = localStorage.getItem(AUTH_DEVICE_KEY);
      if (existing && /^[a-f0-9]{32}$/.test(existing)) return existing;
      var buf = new Uint8Array(16);
      try { (W.crypto || W.msCrypto).getRandomValues(buf); } catch (e) {
        for (var i = 0; i < 16; i++) buf[i] = Math.floor(Math.random() * 256);
      }
      var hex = '';
      for (var j = 0; j < 16; j++) hex += ('0' + buf[j].toString(16)).slice(-2);
      localStorage.setItem(AUTH_DEVICE_KEY, hex);
      return hex;
    } catch (e) { return 'nouuid'; }
  }

  function authFingerprint() {
    var parts = [];
    try { parts.push(navigator.userAgent || ''); } catch (e) {}
    try { parts.push(String(screen.width) + 'x' + String(screen.height) + 'x' + String(screen.colorDepth || 0)); } catch (e) {}
    try { parts.push(String(devicePixelRatio || 1)); } catch (e) {}
    try { parts.push(String(Intl.DateTimeFormat().resolvedOptions().timeZone || '')); } catch (e) {}
    try { parts.push(String(navigator.language || '')); } catch (e) {}
    try { parts.push(String(navigator.hardwareConcurrency || 0)); } catch (e) {}
    try { parts.push(String(navigator.platform || '')); } catch (e) {}
    return sha256Hex(parts.join('|'));
  }

  function authComputeDeviceId() {
    var uuid = authDeviceUuid();
    var fp = authFingerprint();
    return 'fp_' + uuid + '_' + fp;
  }

  function authLoadCache() {
    try {
      var raw = localStorage.getItem(AUTH_KEY);
      if (!raw) return null;
      var d = JSON.parse(raw);
      if (!d || typeof d !== 'object') return null;
      return d;
    } catch (e) { return null; }
  }

  function authSaveCache(obj) {
    try { localStorage.setItem(AUTH_KEY, JSON.stringify(obj)); } catch (e) {}
  }

  function authClearCache() {
    try { localStorage.removeItem(AUTH_KEY); } catch (e) {}
  }

  function authReasonText(reason) {
    var m = {
      invalid: 'Key tidak ditemukan / salah.',
      revoked: 'Key sudah dinonaktifkan.',
      used_on_other_device: 'Key sudah dipakai di HP lain. Hubungi admin.',
      rate_limited: 'Terlalu banyak percobaan. Tunggu beberapa menit.',
      missing_params: 'Key kosong.',
      server_error: 'Server error. Coba lagi.',
      sheet_not_found: 'Sheet tidak ditemukan (Hubungi admin).',
      no_keys: 'Belum ada key di database (Hubungi admin).',
      network: 'Server tidak terjangkau. Cek koneksi internet.'
    };
    return m[reason] || ('Gagal: ' + reason);
  }

  function authVerify(key, interactive) {
    var deviceId = authComputeDeviceId();
    AUTH_STATE.key = key;
    AUTH_STATE.deviceId = deviceId;

    if (!AUTH_URL || AUTH_URL.indexOf('script.google.com') < 0) {
      AUTH_STATE.status = 'fail';
      AUTH_STATE.reason = 'no_url';
      return Promise.resolve({ ok: false, reason: 'no_url' });
    }

    var body = { key: key, deviceId: deviceId };
    var url = AUTH_URL;

    return new Promise(function (resolve) {
      var done = false;
      var timer = setTimeout(function () {
        if (done) return; done = true;
        AUTH_STATE.status = 'fail';
        AUTH_STATE.reason = 'network';
        resolve({ ok: false, reason: 'network' });
      }, 8000);

      try {
        fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'text/plain;charset=utf-8' },
          body: JSON.stringify(body)
        }).then(function (r) { return r.text(); })
          .then(function (txt) {
            if (done) return; done = true;
            clearTimeout(timer);
            var obj;
            try { obj = JSON.parse(txt); } catch (e) { obj = null; }
            if (!obj || typeof obj !== 'object') {
              AUTH_STATE.status = 'fail';
              AUTH_STATE.reason = 'bad_response';
              resolve({ ok: false, reason: 'bad_response' });
              return;
            }
            if (obj.ok) {
              AUTH_STATE.status = 'ok';
              AUTH_STATE.reason = '';
              AUTH_STATE.token = String(obj.token || '');
              AUTH_STATE.tokenExp = Date.now() + AUTH_TOKEN_TTL_MS;
              AUTH_STATE.bound = String(obj.bound || '');
              authSaveCache({
                key: key, deviceId: deviceId, token: AUTH_STATE.token,
                tokenExp: AUTH_STATE.tokenExp, bound: AUTH_STATE.bound, savedAt: Date.now()
              });
              resolve({ ok: true, token: AUTH_STATE.token, bound: AUTH_STATE.bound });
            } else {
              AUTH_STATE.status = 'fail';
              AUTH_STATE.reason = String(obj.reason || 'unknown');
              resolve({ ok: false, reason: AUTH_STATE.reason });
            }
          })
          .catch(function () {
            if (done) return; done = true;
            clearTimeout(timer);
            AUTH_STATE.status = 'fail';
            AUTH_STATE.reason = 'network';
            resolve({ ok: false, reason: 'network' });
          });
      } catch (e) {
        if (done) return; done = true;
        clearTimeout(timer);
        AUTH_STATE.status = 'fail';
        AUTH_STATE.reason = 'network';
        resolve({ ok: false, reason: 'network' });
      }
    });
  }

  // Overlay Login Fullscreen
  function authShowGateOverlay(reason, keyDefault) {
    try {
      if (document.getElementById('vanguard-gate')) return;
      var wrap = document.createElement('div');
      wrap.id = 'vanguard-gate';
      wrap.style.cssText = [
        'position:fixed;inset:0;z-index:2147483647;display:flex;align-items:center;justify-content:center;',
        'background:#090e17; font-family:"Segoe UI",Tahoma,system-ui,sans-serif;color:#e2e8f0;'
      ].join('');
      wrap.innerHTML =
        '<div style="width:340px;max-width:92vw;background:rgba(15,23,42,0.98);border:1px solid rgba(6,182,212,0.6);border-radius:14px;padding:24px 20px;box-shadow:0 20px 60px rgba(0,0,0,0.9);">' +
          '<div style="font-size:16px;font-weight:900;color:#67e8f9;letter-spacing:0.6px;margin-bottom:6px;text-align:center;">VANGUARD ELITE</div>' +
          '<div style="font-size:11px;color:#94a3b8;margin-bottom:20px;text-align:center;">Sistem Terkunci. Masukkan key akses untuk melanjutkan.</div>' +
          '<div id="vanguard-gate-msg" style="font-size:11px;color:#fda4af;margin-bottom:10px;min-height:16px;text-align:center;font-weight:bold;">' + (reason || '') + '</div>' +
          '<input id="vanguard-gate-input" type="text" placeholder="VG-XXXX-XXXX" value="' + (keyDefault || '') + '" ' +
            'style="width:100%;box-sizing:border-box;padding:12px;border-radius:8px;border:1px solid rgba(6,182,212,0.6);background:#0f172a;color:#f1f5f9;font-size:14px;font-weight:800;letter-spacing:2px;outline:none;text-transform:uppercase;margin-bottom:16px;text-align:center;">' +
          '<button id="vanguard-gate-btn" style="width:100%;padding:12px 0;border-radius:8px;border:0;background:linear-gradient(135deg,#0891b2,#10b981);color:#fff;font-weight:900;font-size:14px;cursor:pointer;">MASUK</button>' +
          '<div style="font-size:9px;color:#64748b;margin-top:16px;text-align:center;">1 Key hanya untuk 1 Device. Pastikan koneksi internet lancar.</div>' +
        '</div>';
      (document.body || document.documentElement).appendChild(wrap);

      var input = wrap.querySelector('#vanguard-gate-input');
      var msg = wrap.querySelector('#vanguard-gate-msg');
      var btn = wrap.querySelector('#vanguard-gate-btn');

      function trySubmit() {
        var k = String(input.value || '').trim().toUpperCase();
        if (!/^VG-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(k)) {
          msg.textContent = 'Format key salah. (Contoh: VG-AB12-CD34)';
          return;
        }
        msg.textContent = 'Memverifikasi...';
        msg.style.color = '#67e8f9';
        btn.disabled = true;
        btn.textContent = 'MEMUAT...';

        authVerify(k, true).then(function (res) {
          btn.disabled = false;
          btn.textContent = 'MASUK';
          msg.style.color = '#fda4af';
          if (res.ok) {
            wrap.remove();
            window.location.reload(); // Reload halaman agar script berjalan bersih
          } else {
            msg.textContent = authReasonText(res.reason);
          }
        }).catch(function () {
          btn.disabled = false;
          btn.textContent = 'MASUK';
          msg.style.color = '#fda4af';
          msg.textContent = authReasonText('network');
        });
      }

      btn.addEventListener('click', trySubmit);
      input.addEventListener('keydown', function (e) { if (e.key === 'Enter') trySubmit(); });
      setTimeout(function () { try { input.focus(); } catch (e) {} }, 100);
    } catch (e) {}
  }

  // Cek Login Sebelum Boot
  (function authBoot() {
    var cached = authLoadCache();
    var now = Date.now();
    var deviceId = authComputeDeviceId();

    if (cached && cached.token && cached.tokenExp > now && cached.deviceId === deviceId) {
      // Cache valid -> langsung izinkan boot, lalu verifikasi ulang di background
      AUTH_STATE.status = 'ok';
      AUTH_STATE.key = cached.key;
      AUTH_STATE.deviceId = deviceId;
      AUTH_STATE.token = cached.token;
      AUTH_STATE.tokenExp = cached.tokenExp;
      AUTH_STATE.bound = cached.bound || deviceId;

      authVerify(cached.key, false).then(function (res) {
        if (!res.ok && (res.reason === 'used_on_other_device' || res.reason === 'revoked' || res.reason === 'invalid')) {
          authClearCache();
          location.reload();
        }
      });
      return;
    }

    // Tidak ada cache / expired -> Tampilkan layar kunci
    var lastKey = (cached && cached.key) ? cached.key : '';
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', function () { authShowGateOverlay('', lastKey); });
    } else {
      authShowGateOverlay('', lastKey);
    }
  })();

  /* ============================================================================
     1. TIKTOK BADGE
     ============================================================================ */
  function ensureLobbyBadge() {
    try {
      if (document.getElementById('vanguard-lobby-badge')) return;
      var badge = document.createElement('div');
      badge.id = 'vanguard-lobby-badge';
      badge.style.cssText = [
        'position:fixed;top:10px;left:12px;z-index:999999;pointer-events:none;user-select:none;',
        'display:inline-flex;align-items:center;gap:7px;',
        'font-family:"Segoe UI",Tahoma,system-ui,sans-serif;line-height:1.2;',
        'background:rgba(9,14,23,0.90);backdrop-filter:blur(10px);',
        'border:1px solid rgba(34,211,238,0.45);padding:6px 11px;border-radius:9px;',
        'box-shadow:0 4px 18px rgba(0,0,0,0.7),0 0 12px rgba(6,182,212,0.25);'
      ].join('');
      badge.innerHTML =
        '<span style="width:20px;height:20px;border-radius:6px;display:inline-flex;align-items:center;justify-content:center;' +
          'background:linear-gradient(135deg,#06b6d4,#10b981);color:#fff;font-size:11px;font-weight:900;' +
          'box-shadow:0 0 8px rgba(6,182,212,0.5);">♪</span>' +
        '<span style="font-size:11px;font-weight:800;color:#67e8f9;letter-spacing:0.35px;' +
          'text-shadow:0 0 8px rgba(103,232,249,0.4);">TikTok : @pbmobile_id</span>';
      (document.body || document.documentElement).appendChild(badge);
    } catch (e) {}
  }
  
  // Hanya tampilkan badge jika sudah login (Auth OK)
  if (AUTH_STATE.status === 'ok') {
     ensureLobbyBadge();
  }

  /* ============================================================================
     2. CORE ENGINE
     ============================================================================ */
  function bootCore() {
    var V = '2.4.0';
    var BRAND = 'VANGUARD ELITE';

    function log() {
      try { console.log.apply(console, ['[VANGUARD]'].concat([].slice.call(arguments))); } catch (e) {}
    }

    /* --------------------------------------------------------------------------
       2.1 PREBOOT & BUNDLE PATCHER (ADAPTIVE)
       -------------------------------------------------------------------------- */
    (function preboot() {
      try {
        if (!/\/jogo|game\.html/.test(location.pathname)) return;
        if (W.G || W.HUDO || W.GAME_READY || W.__pbBoot) return;
        W.__pbBoot = 1;

        try {
          var nb = +sessionStorage.getItem('pb_noboot') || 0;
          if (nb && Date.now() - nb < 120000) return;
        } catch (e0) {}

        if (document.readyState === 'complete') return;

        function xget(url, accept) {
          var x = new XMLHttpRequest();
          x.open('GET', url, false);
          try { x.setRequestHeader('Accept', accept); } catch (e) {}
          x.send(null);
          if (x.status !== 200 || !x.responseText) throw new Error('xhr ' + x.status);
          return x.responseText;
        }

        var html = xget(location.href, 'text/html,*/*');
        var bm = /src="([^"]*\/static\/game\/bundle\.js[^"]*)"/.exec(html);
        if (!bm) return;

        var bsrc = xget(new URL(bm[1], location.href).href, '*/*');

        var integrityRe = /if\(!\(\(\)=>\{try\{const e=document\.currentScript,t=e&&e\.src&&new URL\(e\.src\);return!!t&&t\.origin===location\.origin&&"\/static\/game\/bundle\.js"===t\.pathname\}catch\(e\)\{return!1\}\}\)\(\)\)\{try\{location\.replace\("\/"\)\}catch\(t\)\{\}throw new Error\("pb"\)\}/;
        bsrc = bsrc.replace(/function kc\(\)\s*\{/, 'function kc(){return;');
        bsrc = bsrc.replace(/function R\(t\)\s*\{/, 'function R(t){if(t&&"acflag"===t.t)return;');

        if (integrityRe.test(bsrc)) {
          bsrc = bsrc.replace(integrityRe, 'if(0){}');
          log('integrity check disabled');
        } else {
          bsrc = bsrc.replace(/throw new Error\("pb"\)/g, 'void 0');
          log('integrity check fallback applied');
        }

        var gFlex = /!1&&\(window\.G=\{P:([A-Za-z_$][\w$]*),bots:([A-Za-z_$][\w$]*),CFG:([A-Za-z_$][\w$]*),camera:([A-Za-z_$][\w$]*),scene:([A-Za-z_$][\w$]*),cast:([A-Za-z_$][\w$]*),update:([A-Za-z_$][\w$]*),nades:([A-Za-z_$][\w$]*)/;
        if (gFlex.test(bsrc)) {
          bsrc = bsrc.replace(gFlex, '!0&&(window.G={P:$1,bots:$2,CFG:$3,camera:$4,scene:$5,cast:$6,update:$7,nades:$8');
          log('window.G expose re-enabled');
        }

        var gateFlex = /([A-Za-z_$][\w$]*)="localhost"===location\.hostname\|\|"127\.0\.0\.1"===location\.hostname\|\|"\[::1\]"===location\.hostname/g;
        var patched = false;
        var foundIds = [];
        bsrc = bsrc.replace(gateFlex, function (full, ident) {
          foundIds.push(ident);
          patched = true;
          return ident + '=!0';
        });

        if (!patched) {
          var gateUi = /const\s+([A-Za-z_$][\w$]*)="localhost"===location\.hostname\|\|"127\.0\.0\.1"===location\.hostname\|\|"\[::1\]"===location\.hostname,/;
          var mUi = gateUi.exec(bsrc);
          if (mUi) {
            bsrc = bsrc.replace(mUi[0], 'const ' + mUi[1] + '=!0,');
            foundIds.push(mUi[1] + '(legacy-comma)');
            patched = true;
          }
        }
        if (!patched) {
          log('gate tidak ditemukan, lanjut tanpa patch dokumen');
          return;
        }
        log('gate patched:', foundIds.join(', '));

        var parsed = new DOMParser().parseFromString(html, 'text/html');
        var scripts = [].slice.call(parsed.querySelectorAll('script')).map(function (s) {
          return { src: s.getAttribute('src'), text: s.textContent, type: s.getAttribute('type') || '' };
        });
        if (!scripts.length) return;

        [].slice.call(parsed.querySelectorAll('script')).forEach(function (s) {
          if (s.parentNode) s.parentNode.removeChild(s);
        });

        var dt = parsed.doctype ? '<!doctype ' + parsed.doctype.name + '>' : '<!doctype html>';
        var clean = dt + parsed.documentElement.outerHTML;
        var burl = '';
        try { burl = URL.createObjectURL(new Blob([bsrc], { type: 'text/javascript' })); } catch (e1) {}

        try {
          if (document.referrer.indexOf('android-app://') === 0 ||
              matchMedia('(display-mode: standalone), (display-mode: fullscreen)').matches) {
            document.cookie = 'pbapp=1; max-age=31536000; path=/; secure; samesite=lax';
          }
        } catch (e4) {}

        try {
          document.open();
          document.write(clean);
          document.close();
        } catch (e2) {
          try { sessionStorage.setItem('pb_noboot', String(Date.now())); } catch (e3) {}
          location.reload();
          return;
        }

        var i = 0;
        function next() {
          while (i < scripts.length) {
            var s = scripts[i++];
            try {
              var t = (s.type || '').toLowerCase();
              if (t && t.indexOf('javascript') < 0 && t.indexOf('ecmascript') < 0) continue;
              var el = document.createElement('script');
              var head = document.head || document.documentElement;
              if (s.src) {
                var abs;
                try { abs = new URL(s.src, location.href).href; } catch (eU) { abs = s.src; }
                if (/\/static\/game\/bundle\.js(\?|$)/.test(abs)) abs = burl || '';
                if (abs) {
                  el.src = abs;
                  el.async = false;
                  var done = false;
                  var fin = function () { if (done) return; done = true; clearTimeout(to); next(); };
                  var to = setTimeout(fin, 20000);
                  el.onload = el.onerror = fin;
                  head.appendChild(el);
                  return;
                }
                el.textContent = bsrc;
                head.appendChild(el);
                continue;
              }
              el.textContent = s.text;
              head.appendChild(el);
            } catch (eL) {}
          }
        }
        next();

        setTimeout(function () {
          try {
            if (W.HUDO || W.GAME_READY || document.querySelector('canvas')) return;
            try { sessionStorage.setItem('pb_noboot', String(Date.now())); } catch (e) {}
            location.reload();
          } catch (e) {}
        }, 20000);
      } catch (e) {}
    })();

    /* --------------------------------------------------------------------------
       2.2 STATE & KONFIGURASI GLOBAL
       -------------------------------------------------------------------------- */
    var HIDDEN = { pb: null, pbvis: null, pbnade: null, pbqc: null, pbx: null };

    var P = {
      cone: 0.65,
      reach: 200,
      autoFire: 0,
      gain: 0.9,
      mode: 'near',
      bias: 0.35,
      aimMode: 'pov',
      povCircleR: 220,
      hitbox: 'head',
      aimbotOn: 0,
      aimbotGain: 1.1,
      aimbotHoldMs: 250,
      bulletSpeed: 350,
      leadFactor: 1.0,
      lockMode: 'pov'
    };

    var O = { sens: 0.5, fov: 70, invert: false };

    var FL = {
      wallbang: 1,
      infAmmo: 1,
      noRecoil: 1,
      godmode: 0,
      noclip: 0,
      antiKick: 1,
      noFall: 1,
      infNade: 1,
      infNadeMax: 99
    };

    var G = null;
    var aimOn = false;
    var fireHeld = 0;
    var nextTap = 0;
    var holding = false;
    var silentHolding = false;
    var lastPick = null;

    var st = {
      v: V, aim: false, G: false, bots: 0, enemies: 0,
      lock: 0, err: 0, fire: 0, dist: 0, hitbox: P.hitbox,
      aimbot: 0, lead: 0, lockMode: P.lockMode
    };

    var AB = { lockUntil: 0, target: null, lastShot: 0, freshFire: 0 };
    var SF = { on: 1 };
    var AIM = { dx: 0, dy: 0, queued: false };
    var AIMLOCK = { on: false, targetYaw: 0, targetPitch: 0, locked: false };

    function readOpts() {
      try {
        var s = localStorage.getItem('pbweb_opts');
        if (!s) return;
        var o = JSON.parse(s);
        if (typeof o.sens === 'number' && o.sens > 0) O.sens = o.sens;
        if (typeof o.fov === 'number' && o.fov > 0) O.fov = o.fov;
        O.invert = !!o.invert;
      } catch (e) {}
    }
    readOpts();
    try { addEventListener('pbopts', readOpts); } catch (e) {}

    try {
      var _pr = parseFloat(localStorage.getItem('ir_povcirc'));
      if (isFinite(_pr) && _pr >= 1) P.povCircleR = _pr;
      var _hb = localStorage.getItem('ir_hitbox');
      if (_hb === 'head' || _hb === 'body' || _hb === 'nearest') P.hitbox = _hb;
      var _ab = localStorage.getItem('ir_aimbot');
      if (_ab === '1' || _ab === '0') P.aimbotOn = +_ab;
      var _abg = parseFloat(localStorage.getItem('ir_aimbot_gain'));
      if (isFinite(_abg) && _abg > 0) P.aimbotGain = _abg;
      var _abh = parseFloat(localStorage.getItem('ir_aimbot_hold'));
      if (isFinite(_abh) && _abh >= 50) P.aimbotHoldMs = _abh;
      var _bs = parseFloat(localStorage.getItem('ir_bullet_speed'));
      if (isFinite(_bs) && _bs > 0) P.bulletSpeed = _bs;
      var _lf = parseFloat(localStorage.getItem('ir_lead'));
      if (isFinite(_lf) && _lf >= 0) P.leadFactor = _lf;
      var _lm = localStorage.getItem('ir_lockmode');
      if (_lm === 'legacy' || _lm === 'pov') P.lockMode = _lm;
    } catch (e) {}

    /* --------------------------------------------------------------------------
       2.3 UTILITAS UMUM
       -------------------------------------------------------------------------- */
    function game() {
      try {
        var g = W.G;
        if (g && g.P && g.P.s && g.camera && g.bots) return g;
      } catch (e) {}
      return null;
    }

    var _canvasCache = { el: null, at: 0 };
    function getGameCanvas() {
      var now = performance.now();
      if (_canvasCache.el && _canvasCache.el.parentNode && now - _canvasCache.at < 2500) {
        return _canvasCache.el;
      }
      _canvasCache.at = now;
      var best = null;
      var maxArea = 0;
      var cs = document.getElementsByTagName('canvas');
      for (var i = 0; i < cs.length; i++) {
        var c = cs[i];
        if (c.getAttribute('data-pb') || c.id === 'crossCv') continue;
        var area = c.offsetWidth * c.offsetHeight;
        if (area > maxArea) {
          maxArea = area;
          best = c;
        }
      }
      _canvasCache.el = best || null;
      return _canvasCache.el;
    }

    function clamp(v, min, max) { return v < min ? min : v > max ? max : v; }
    function wrap(a) {
      while (a > Math.PI) a -= 2 * Math.PI;
      while (a < -Math.PI) a += 2 * Math.PI;
      return a;
    }
    function wpos(bone, out) {
      if (!bone || !bone.matrixWorld || !bone.matrixWorld.elements) return false;
      var e = bone.matrixWorld.elements;
      out.x = e[12]; out.y = e[13]; out.z = e[14];
      return true;
    }
    function ms(text) {
      try {
        var c = document.getElementById('center');
        if (c) {
          c.textContent = text;
          c.style.display = '';
          setTimeout(function () { if (c.textContent === text) c.textContent = ''; }, 1500);
        } else {
          log(text);
        }
      } catch (e) { log(text); }
    }
    function buzz(pattern) {
      try { if (navigator.vibrate) navigator.vibrate(pattern); } catch (e) {}
    }

    /* --------------------------------------------------------------------------
       2.4 KALKULASI TARGET
       -------------------------------------------------------------------------- */
    var _hpOut = { x: 0, y: 0, z: 0 };
    var _leadOut = { x: 0, y: 0, z: 0 };
    var _pv = null;
    var _pDir = { x: 0, y: 0, z: 0 };
    var F = { x: 0, y: 0, z: 0 };
    var C = { x: 0, y: 0, z: 0 };

    function headPoint(p) {
      var by = p && p.c && p.c.byName;
      if (!by) return null;
      var h = by.Head || by.head;
      var g = by.Bone_HeadGearAttach;
      if (g && wpos(g, _hpOut)) { _hpOut.y -= 0.05; return _hpOut; }
      if (h && wpos(h, _hpOut)) { _hpOut.y += 0.11; return _hpOut; }
      var base = (p.obj && p.obj.position) ? p.obj.position : (p.mover && p.mover.pos);
      if (!base) return null;
      _hpOut.x = base.x;
      _hpOut.y = base.y + (p.mover && p.mover.crouch ? 1.18 : 1.68);
      _hpOut.z = base.z;
      return _hpOut;
    }

    function bodyPoint(p) {
      var by = p && p.c && p.c.byName;
      if (!by) return null;
      var h = by.Spine2 || by.Spine1 || by.Spine3 || by.Neck || by.Pelvis;
      if (h && wpos(h, _hpOut)) return _hpOut;
      var base = (p.obj && p.obj.position) ? p.obj.position : (p.mover && p.mover.pos);
      if (!base) return null;
      _hpOut.x = base.x;
      _hpOut.y = base.y + (p.mover && p.mover.crouch ? 0.82 : 1.15);
      _hpOut.z = base.z;
      return _hpOut;
    }

    function nearestPoint(p) {
      var hp = headPoint(p);
      if (!hp) return bodyPoint(p);
      var hx = hp.x, hy = hp.y, hz = hp.z;
      var bp = bodyPoint(p);
      if (!bp) return hp;
      var bx = bp.x, by = bp.y, bz = bp.z;
      var dh = (hx - C.x) * (hx - C.x) + (hy - C.y) * (hy - C.y) + (hz - C.z) * (hz - C.z);
      var db = (bx - C.x) * (bx - C.x) + (by - C.y) * (by - C.y) + (bz - C.z) * (bz - C.z);
      if (dh <= db) { _hpOut.x = hx; _hpOut.y = hy; _hpOut.z = hz; }
      else { _hpOut.x = bx; _hpOut.y = by; _hpOut.z = bz; }
      return _hpOut;
    }

    function getTargetPointLogical(p) {
      if (P.hitbox === 'head') return headPoint(p);
      if (P.hitbox === 'body') return bodyPoint(p);
      return nearestPoint(p);
    }

    function predictPoint(p, basePt, fromPt) {
      var dx = basePt.x - fromPt.x;
      var dy = basePt.y - fromPt.y;
      var dz = basePt.z - fromPt.z;
      var dist = Math.sqrt(dx * dx + dy * dy + dz * dz);
      if (dist < 1 || P.bulletSpeed <= 0) {
        _leadOut.x = basePt.x; _leadOut.y = basePt.y; _leadOut.z = basePt.z;
        return _leadOut;
      }
      var t = (dist / P.bulletSpeed) * P.leadFactor;
      var vx = 0, vy = 0, vz = 0;
      try {
        if (p.mover && p.mover.vel) {
          vx = +p.mover.vel.x || 0;
          vy = +p.mover.vel.y || 0;
          vz = +p.mover.vel.z || 0;
        }
      } catch (e) {}
      _leadOut.x = basePt.x + vx * t;
      _leadOut.y = basePt.y + vy * t * 0.5;
      _leadOut.z = basePt.z + vz * t;
      return _leadOut;
    }

    function getTargetPointLead(p, fromPt) {
      var base = getTargetPointLogical(p);
      if (!base) return null;
      return predictPoint(p, { x: base.x, y: base.y, z: base.z }, fromPt || C);
    }

    var _povCache = new WeakMap();
    function isInsidePOVCircle(cam, hp, p) {
      try {
        var now = performance.now();
        if (p) {
          var c = _povCache.get(p);
          if (c && now - c.t < 200) return c.v;
        }
        if (!_pv) _pv = cam.position.clone();
        var ndc = _pv.set(hp.x, hp.y, hp.z).project(cam);
        if (!(ndc.z > -1 && ndc.z < 1)) {
          if (p) _povCache.set(p, { t: now, v: false });
          return false;
        }
        var px = ndc.x * (innerWidth / 2);
        var py = -ndc.y * (innerHeight / 2);
        var v = Math.sqrt(px * px + py * py) <= P.povCircleR;
        if (p) _povCache.set(p, { t: now, v: v });
        return v;
      } catch (e) { return false; }
    }

    function hasLineOfSight(g, cam, hp) {
      try {
        if (typeof g.cast !== 'function') return true;
        var eye = cam.position;
        var dx = hp.x - eye.x, dy = hp.y - eye.y, dz = hp.z - eye.z;
        var dist = Math.sqrt(dx * dx + dy * dy + dz * dz);
        if (!(dist > 0.5)) return false;
        _pDir.x = dx / dist; _pDir.y = dy / dist; _pDir.z = dz / dist;
        return !g.cast(eye, _pDir, dist - 0.35);
      } catch (e) { return true; }
    }

    var _losCache = new WeakMap();
    function hasLineOfSightThrottled(g, cam, p, point) {
      if (!p) return hasLineOfSight(g, cam, point);
      var now = performance.now();
      var c = _losCache.get(p);
      if (c && now - c.t < perfLosMs()) return c.v;
      var v = hasLineOfSight(g, cam, point);
      _losCache.set(p, { t: now, v: v });
      return v;
    }

    function canLockTarget(g, cam, p, point) {
      if (P.lockMode !== 'pov') return true;
      if (!point) return false;
      if (!isInsidePOVCircle(cam, point, p)) return false;
      return hasLineOfSightThrottled(g, cam, p, point);
    }

    var _aimbotLosCache = new WeakMap();
    function canAimbotTarget(g, cam, p, point) {
      if (!point || !isInsidePOVCircle(cam, point, p)) return false;
      var now = performance.now();
      var c = _aimbotLosCache.get(p);
      if (c && now - c.t < perfAimbotLosMs()) return c.v;
      var v = hasLineOfSight(g, cam, point);
      _aimbotLosCache.set(p, { t: now, v: v });
      return v;
    }

    function isBotReal(p) {
      if (!p || !p.obj || !p.c) return false;
      if (p.dead || !(p.hp > 0)) return false;
      if (!p.obj.parent || p.obj.visible === false) return false;
      return true;
    }

    function isInvulnerable(p) {
      if (!p) return true;
      try {
        if (p.god || p.godmode || p.invulnerable || p.immortal || p.shield) return true;
        if ((+p.flicker || 0) > 0 || (+p.spawnProtect || 0) > 0 || (+p.protect || 0) > 0) return true;
        if ((+p.invuln || 0) > 0 || (+p.invulnT || 0) > 0 || (+p.spawnT || 0) > 0) return true;
        if (p.mover && ((+p.mover.spawnT || 0) > 0 || (+p.mover.invulnT || 0) > 0)) return true;
      } catch (e) {}
      return false;
    }

    function isHumanEnemy(p, self) {
      if (!isBotReal(p) || !self || p === self) return false;
      if (p.team === self.team || p.isBot || p.bot) return false;
      var nm = String((p.name || p.nick || p.id || '')).trim().toLowerCase();
      if (/^(bot|ai)[_\-\s]?\d*$/i.test(nm)) return false;
      return !isInvulnerable(p);
    }

    function hitTestSafe(p, o, d, m) {
      if (!p || p.dead) return null;
      if (p.remote && !p.net && p.isBot) {
        var old = p.remote;
        p.remote = false;
        try { return p.hitTest(o, d, m); } finally { p.remote = old; }
      }
      return p.hitTest(o, d, m);
    }

    /* --------------------------------------------------------------------------
       2.5 INPUT MOUSE & YAW/PITCH
       -------------------------------------------------------------------------- */
    function aimWrite(dx, dy) {
      AIM.dx += dx;
      AIM.dy += dy;
      AIM.queued = true;
    }

    function aimFlush(g) {
      if (!AIM.queued) return;
      AIM.queued = false;
      var s = g && g.P && g.P.s;
      if (!s || s.dead) { AIM.dx = AIM.dy = 0; return; }
      if (AIMLOCK.locked && P.lockMode !== 'pov') { AIM.dx = AIM.dy = 0; return; }

      var sens = O.sens * ((g.camera && g.camera.fov || 70) / O.fov) * 0.005;
      var dyaw = -AIM.dx * sens;
      var dpitch = (O.invert ? 1 : -1) * AIM.dy * sens;
      var curY = (s.__pbYawRaw != null) ? s.__pbYawRaw : (+s.yaw || 0);
      var curP = (s.__pbPitchRaw != null) ? s.__pbPitchRaw : (+s.pitch || 0);
      var ny = wrap(curY + dyaw);
      var np = clamp(curP + dpitch, -1.4, 1.4);

      if (s.__pbYawLocked) {
        s.__pbYawRaw = ny;
        s.__pbPitchRaw = np;
      } else {
        s.yaw = ny;
        s.pitch = np;
      }
      AIM.dx = AIM.dy = 0;
    }

    function lockYawPitch(s) {
      if (!s || s.__pbYawLocked) return;
      s.__pbYawRaw = +s.yaw || 0;
      s.__pbPitchRaw = +s.pitch || 0;
      try {
        Object.defineProperty(s, 'yaw', {
          configurable: true,
          get: function () { return AIMLOCK.locked ? AIMLOCK.targetYaw : this.__pbYawRaw; },
          set: function (v) { this.__pbYawRaw = +v || 0; }
        });
        Object.defineProperty(s, 'pitch', {
          configurable: true,
          get: function () { return AIMLOCK.locked ? AIMLOCK.targetPitch : this.__pbPitchRaw; },
          set: function (v) { this.__pbPitchRaw = +v || 0; }
        });
        s.__pbYawLocked = true;
        log('yaw/pitch locked');
      } catch (e) { log('lockYawPitch fail', e); }
    }

    function down() {
      try {
        var g = G || game();
        if (g && g.P && g.P.s && !g.P.s.dead && typeof g.fire === 'function') {
          g.fire();
        }
      } catch (e) {}
      AB.freshFire = 1;
    }

    function up() {
      try {
        var g = G || game();
        if (g && typeof g.release === 'function') g.release();
      } catch (e) {}
      holding = false;
      silentHolding = false;
    }

    addEventListener('mousemove', function (e) {
      if (e.movementX || e.movementY) aimWrite(e.movementX, e.movementY);
    }, true);
    addEventListener('mousedown', function (e) {
      if (e.button === 0) { fireHeld = 1; AB.freshFire = 1; st.fire = 1; }
    }, true);
    addEventListener('mouseup', function (e) {
      if (e.button === 0) { fireHeld = 0; st.fire = 0; }
    }, true);
    document.addEventListener('visibilitychange', function () {
      if (document.hidden) {
        fireHeld = 0; st.fire = 0; AB.freshFire = 0;
        if (typeof FLY !== 'undefined') { FLY.jumpHeld = 0; FLY.crouchHeld = 0; }
        if (silentHolding) up();
      }
    });

    var fireIds = new Set();
    function inZone(t) { return t.clientX > innerWidth * 0.50 && t.clientY > innerHeight * 0.45; }
    function syncFire() { fireHeld = fireIds.size; st.fire = fireHeld; }

    addEventListener('touchstart', function (e) {
      for (var i = 0; i < e.changedTouches.length; i++) {
        var t = e.changedTouches[i];
        if (inZone(t)) { fireIds.add(t.identifier); AB.freshFire = 1; }
      }
      syncFire();
    }, true);
    addEventListener('touchmove', function (e) {
      for (var i = 0; i < e.changedTouches.length; i++) {
        var t = e.changedTouches[i];
        if (inZone(t)) fireIds.add(t.identifier);
        else fireIds.delete(t.identifier);
      }
      syncFire();
    }, true);
    function touchEnd(e) {
      for (var i = 0; i < e.changedTouches.length; i++) fireIds.delete(e.changedTouches[i].identifier);
      syncFire();
    }
    addEventListener('touchend', touchEnd, true);
    addEventListener('touchcancel', touchEnd, true);

    /* --------------------------------------------------------------------------
       2.6 MOVEMENT & SURVIVAL
       -------------------------------------------------------------------------- */
    var FLY = { on: 0, mode: 'hover', jumpHeld: 0, crouchHeld: 0, riseSpeed: 7, maxHeight: 35, groundY: null, hoverY: null };
    var FLYB = { on: 1, last: 0, interval: 16, smooth: 1.0 };

    addEventListener('blur', function () {
      fireHeld = 0; st.fire = 0; AB.freshFire = 0;
      FLY.jumpHeld = 0; FLY.crouchHeld = 0;
      if (silentHolding) up();
    });

    function flyPosObj(s) {
      if (!s) return null;
      if (s.mover && s.mover.pos && typeof s.mover.pos.y === 'number') return s.mover.pos;
      if (s.obj && s.obj.position && typeof s.obj.position.y === 'number') return s.obj.position;
      return null;
    }

    function flySyncBody(s, y) {
      try { if (s.mover && s.mover.pos && typeof s.mover.pos.y === 'number') s.mover.pos.y = y; } catch (e) {}
      try { if (s.obj && s.obj.position && typeof s.obj.position.y === 'number') s.obj.position.y = y; } catch (e) {}
    }

    function flyTick(dt) {
      if (!FLY.on) return false;
      var g = G || game();
      if (!g || !g.P || !g.P.s || g.P.s.dead) return false;
      var s = g.P.s, m = s.mover;
      var pos = flyPosObj(s);
      if (!pos || !isFinite(pos.y)) return false;

      var now = performance.now();
      var stepDt = (typeof dt === 'number' && isFinite(dt) && dt > 0) ? Math.min(0.05, dt) : 0.016;
      if (FLYB.on && FLYB.last > 0) {
        var elapsed = (now - FLYB.last) / 1000;
        if (elapsed > 0 && elapsed < 0.25) stepDt = Math.min(0.05, elapsed);
      }
      FLYB.last = now;

      if (FLY.groundY == null || !isFinite(FLY.groundY)) FLY.groundY = pos.y;
      if (FLY.hoverY == null || !isFinite(FLY.hoverY)) FLY.hoverY = pos.y;

      var verticalInput = (FLY.jumpHeld ? 1 : 0) - (FLY.crouchHeld ? 1 : 0);
      if (verticalInput !== 0) {
        var delta = verticalInput * FLY.riseSpeed * stepDt;
        if (FLYB.on) delta *= FLYB.smooth;
        FLY.hoverY += delta;
      }

      FLY.hoverY = clamp(FLY.hoverY, FLY.groundY, FLY.groundY + FLY.maxHeight);

      if (m) {
        try {
          m.noGrav = true; m.vy = 0; m.jt = -1; m.ft = 0; m.airT = 0; m.onGround = false;
          if (FL.noFall) { m.fallDmg = 0; m.fallT = 0; m.landT = 0; }
        } catch (e) {}
      }

      flySyncBody(s, FLY.hoverY);
      return true;
    }

    function flyToggle(on) {
      var g = G || game();
      var val = (on === undefined) ? (FLY.on ? 0 : 1) : (on ? 1 : 0);
      if (!val) {
        FLY.on = 0; FLY.jumpHeld = 0; FLY.crouchHeld = 0; FLY.groundY = null; FLY.hoverY = null;
        if (g && g.P && g.P.s && g.P.s.mover) {
          var m = g.P.s.mover;
          try { m.noGrav = false; m.vy = 0; m.jt = -1; m.ft = 0; m.onGround = false; } catch (e) {}
        }
        buzz(30);
        return 0;
      }

      var s = g && g.P && g.P.s;
      var pos = flyPosObj(s);
      if (!s || s.dead || !pos || !isFinite(pos.y)) {
        FLY.on = 0;
        return 0;
      }

      FLY.on = 1; FLY.groundY = pos.y; FLY.hoverY = pos.y;
      FLY.jumpHeld = 0; FLY.crouchHeld = 0; FLYB.last = performance.now();
      if (s.mover) {
        try { s.mover.noGrav = true; s.mover.jt = -1; s.mover.ft = 0; s.mover.vy = 0; } catch (e) {}
      }
      ms('Fly ON');
      buzz(30);
      return 1;
    }

    (function flyControls() {
      function isInputFocused() {
        var el = document.activeElement;
        return el && (/^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName) || el.isContentEditable);
      }
      function setVertical(code, isDown) {
        if (code === 'Space') FLY.jumpHeld = isDown ? 1 : 0;
        if (code === 'ControlLeft' || code === 'ControlRight' || code === 'KeyC') FLY.crouchHeld = isDown ? 1 : 0;
      }
      addEventListener('keydown', function (e) {
        if (!FLY.on || isInputFocused()) return;
        if (e.code === 'Space' || e.code === 'ControlLeft' || e.code === 'ControlRight' || e.code === 'KeyC') {
          setVertical(e.code, true);
          e.preventDefault(); e.stopPropagation();
        }
        if (e.code === 'F9') { e.preventDefault(); flyToggle(); }
      }, true);
      addEventListener('keyup', function (e) { setVertical(e.code, false); }, true);

      setInterval(function bindMobileControls() {
        var jump = document.querySelectorAll('[data-action="jump"], .btn-jump, #btn-jump, #jump, [class*="jump"], [id*="jump"]');
        var crouch = document.querySelectorAll('[data-action="crouch"], .btn-crouch, #btn-crouch, #crouch, [class*="crouch"], [id*="crouch"], [data-action="duck"]');
        function bind(nodes, key) {
          for (var i = 0; i < nodes.length; i++) {
            var el = nodes[i], marker = key === 'jump' ? '__pbFlyJumpBound' : '__pbFlyCrouchBound';
            if (el[marker]) continue;
            el[marker] = 1;
            (function (node) {
              node.addEventListener('touchstart', function (e) {
                if (!FLY.on) return;
                if (key === 'jump') FLY.jumpHeld = 1; else FLY.crouchHeld = 1;
                e.preventDefault(); e.stopPropagation();
              }, { passive: false });
              function release(e) {
                if (key === 'jump') FLY.jumpHeld = 0; else FLY.crouchHeld = 0;
                if (FLY.on && e && e.cancelable) { e.preventDefault(); e.stopPropagation(); }
              }
              node.addEventListener('touchend', release, { passive: false });
              node.addEventListener('touchcancel', release, { passive: false });
            })(el);
          }
        }
        bind(jump, 'jump');
        bind(crouch, 'crouch');
      }, 1500);
    })();

    var NC = { active: 0, mover: null, origBlocked: null, origCrosses: null, origDepen: null };
    function ncInstall() {
      var g = G || game();
      var m = g && g.P && g.P.s && g.P.s.mover;
      if (!m) return false;
      if (NC.active && NC.mover === m) return true;
      ncUninstall();
      NC.mover = m;
      NC.origBlocked = m.blocked;
      NC.origCrosses = m.crosses;
      NC.origDepen = m.depenetrate;
      try { m.blocked = function () { return false; }; } catch (e) {}
      try { m.crosses = function () { return false; }; } catch (e) {}
      try { m.depenetrate = function () { return false; }; } catch (e) {}
      NC.active = 1;
      return true;
    }
    function ncUninstall() {
      if (!NC.active || !NC.mover) { NC.active = 0; return; }
      var m = NC.mover;
      try { m.blocked = NC.origBlocked; } catch (e) {}
      try { m.crosses = NC.origCrosses; } catch (e) {}
      try { m.depenetrate = NC.origDepen; } catch (e) {}
      NC.active = 0;
      NC.mover = null;
    }

    var GB = { s: null, field: null, patched: 0, origHT: null, lastApply: 0 };
    function gbBind(s) {
      if (!s || GB.s === s) return;
      GB.s = s; GB.field = null;
      var fields = ['flicker', 'spawnProtect', 'protect', 'invuln', 'invulnT', 'spawnT'];
      for (var i = 0; i < fields.length; i++) {
        if (typeof s[fields[i]] === 'number') { GB.field = fields[i]; break; }
      }
    }
    function gbTick(now) {
      if (!FL.godmode) {
        if (GB.patched && GB.s && GB.origHT) {
          try { GB.s.hitTest = GB.origHT; } catch (e) {}
          GB.patched = 0;
        }
        return;
      }
      var g = G || game();
      var s = g && g.P && g.P.s;
      if (!s || s.dead) return;
      if (s !== GB.s) gbBind(s);
      if (now - GB.lastApply < 150) return;
      GB.lastApply = now;

      if (GB.field) {
        try { s[GB.field] = 9e9; } catch (e) {}
      } else {
        ['flicker', 'spawnProtect', 'protect', 'invuln', 'invulnT', 'spawnT'].forEach(function (f) {
          try { if (typeof s[f] === 'number') s[f] = 9e9; } catch (e) {}
        });
      }
      if (!GB.patched && typeof s.hitTest === 'function') {
        GB.origHT = s.hitTest;
        s.hitTest = function () { return FL.godmode ? null : GB.origHT.apply(this, arguments); };
        GB.patched = 1;
      }
    }

    var IR = { on: 0, at: 0 };

    /* --------------------------------------------------------------------------
       2.7 SILENT NADE & UNLIMITED GRENADE
       -------------------------------------------------------------------------- */
    var SN = { on: 0, side: 'enemy', mode: 'aim', targetName: '', requireLOS: 0, homing: 1, lockedTarget: null, pinnedNameBot: null, nadeCount: 0, lastNadeAt: 0 };
    var SNB = { on: 1, last: 0, interval: 33 };
    var NG = { on: 1, max: 99, lastLog: 0, count: 0 };

    function snBotLabel(p, idxFallback) {
      var raw = (p && (p.name || p.nick)) ? String(p.name || p.nick).trim() : '';
      if (raw) return raw;
      if (p && p.id != null) return 'bot_' + String(p.id);
      return 'player_' + String(idxFallback || 0);
    }

    function snIsValidSide(p, self) {
      if (!p || p === self || p.dead || !(p.hp > 0) || !p.obj || !p.c || p.obj.visible === false) return false;
      var sameTeam = (p.team === self.team);
      return SN.side === 'ally' ? sameTeam : !sameTeam;
    }

    function snLock(g, from) {
      var list = g.bots || [];
      var self = g.P && g.P.s;
      var cam = g.camera;
      if (!self) return null;

      var candidates = [];
      for (var i = 0; i < list.length; i++) {
        var p = list[i];
        if (!snIsValidSide(p, self)) continue;
        var pt = getTargetPointLogical(p);
        if (!pt) continue;
        if (SN.requireLOS && cam && !hasLineOfSight(g, cam, pt)) continue;
        candidates.push({ bot: p, label: snBotLabel(p, i), pt: { x: pt.x, y: pt.y, z: pt.z } });
      }
      if (!candidates.length) return null;

      if (SN.mode === 'random') {
        return candidates[Math.floor(Math.random() * candidates.length)];
      }

      if (SN.mode === 'name_order') {
        if (SN.targetName) {
          var matched = candidates.find(function (c) { return c.label === SN.targetName; });
          if (matched) { SN.pinnedNameBot = matched.bot; return matched; }
          return null;
        }
        candidates.sort(function (a, b) {
          var cmp = a.label.localeCompare(b.label, undefined, { sensitivity: 'base' });
          return cmp !== 0 ? cmp : String(a.bot.id || '').localeCompare(String(b.bot.id || ''));
        });
        if (SN.pinnedNameBot && snIsValidSide(SN.pinnedNameBot, self)) {
          var pinnedPt = getTargetPointLogical(SN.pinnedNameBot);
          if (pinnedPt && (!SN.requireLOS || !cam || hasLineOfSight(g, cam, pinnedPt))) {
            return { bot: SN.pinnedNameBot, label: snBotLabel(SN.pinnedNameBot, 0), pt: { x: pinnedPt.x, y: pinnedPt.y, z: pinnedPt.z } };
          }
        }
        SN.pinnedNameBot = candidates[0].bot;
        return candidates[0];
      }

      var eye = (cam && cam.matrixWorld && cam.matrixWorld.elements)
        ? { x: cam.matrixWorld.elements[12], y: cam.matrixWorld.elements[13], z: cam.matrixWorld.elements[14] }
        : (from || { x: 0, y: 0, z: 0 });
      var yaw = +self.yaw || 0, pitch = +self.pitch || 0, cp = Math.cos(pitch);
      var fx = -Math.sin(yaw) * cp, fy = Math.sin(pitch), fz = -Math.cos(yaw) * cp;

      var best = null, bestScore = 1e9;
      for (var c = 0; c < candidates.length; c++) {
        var item = candidates[c];
        var dx = item.pt.x - eye.x, dy = item.pt.y - eye.y, dz = item.pt.z - eye.z;
        var dist = Math.sqrt(dx * dx + dy * dy + dz * dz);
        if (!(dist > 0.01)) continue;
        var ang = Math.acos(clamp((dx * fx + dy * fy + dz * fz) / dist, -1, 1));
        var score = ang + dist * 0.002;
        if (score < bestScore) { bestScore = score; best = item; }
      }
      return best || candidates[0];
    }

    function snChaseNade(n) {
      if (!n || !n.__sn || !n.pos) return;
      var tgt = n.__snTarget;
      var g = G || game();
      var self = g && g.P && g.P.s;

      if (!tgt || !tgt.bot || !self || !snIsValidSide(tgt.bot, self)) {
        if (!g) { n.__snTarget = null; return; }
        var nt = snLock(g, n.pos);
        if (!nt) { n.__snTarget = null; return; }
        n.__snTarget = nt;
        tgt = nt;
        SN.lockedTarget = nt;
      }

      var pt = getTargetPointLogical(tgt.bot);
      if (!pt) return;
      tgt.pt.x = pt.x; tgt.pt.y = pt.y; tgt.pt.z = pt.z;

      try { n.pos.x = pt.x; n.pos.y = pt.y; n.pos.z = pt.z; } catch (e) { return; }
      try { if (n.mesh && n.mesh.position) n.mesh.position.set(pt.x, pt.y, pt.z); } catch (e) {}
      try { if (n.obj && n.obj.position) n.obj.position.set(pt.x, pt.y, pt.z); } catch (e) {}
      try { if (n.start && n.start.copy) n.start.copy(n.pos); } catch (e) {}
    }

    function snScanAndHoming(g) {
      if (!SN.on || !g.nades || !g.nades.length) return;
      var self = g.P && g.P.s;
      if (!self) return;

      for (var i = 0; i < g.nades.length; i++) {
        var n = g.nades[i];
        if (!n) continue;
        if (n.__sn) {
          if (!n.__snPatched) {
            n.__snPatched = 1;
            ['update', 'step', 'tick', 'integrate', 'move'].forEach(function (key) {
              if (typeof n[key] !== 'function') return;
              var orig = n[key];
              n[key] = function () {
                var r = orig.apply(this, arguments);
                try { snChaseNade(this); } catch (e) {}
                return r;
              };
            });
          }
          snChaseNade(n);
          continue;
        }

        var isMine = (n.owner === self);
        if (!isMine && n.owner == null && n.pos && self.mover && self.mover.pos) {
          try {
            var dx0 = n.pos.x - self.mover.pos.x;
            var dy0 = n.pos.y - self.mover.pos.y;
            var dz0 = n.pos.z - self.mover.pos.z;
            if (dx0 * dx0 + dy0 * dy0 + dz0 * dz0 < 16) isMine = true;
          } catch (e) {}
        }
        if (!isMine) continue;

        if (!n.pos && self.mover && self.mover.pos) {
          try { n.pos = self.mover.pos.clone(); n.pos.y += 1.4; } catch (e) { continue; }
        }
        if (!n.pos) continue;

        var target = snLock(g, n.pos);
        if (!target) continue;
        n.__snTarget = target;
        n.__sn = 1;
        SN.nadeCount++;
        SN.lastNadeAt = performance.now();
        SN.lockedTarget = target;
      }
    }

    function nadeTick() {
      if (!FL.infNade) return;
      var g = G || game();
      var inv = g && g.P && !g.P.s.dead && g.P.inv;
      if (!inv) return;

      var changed = false;
      for (var k in inv) {
        var slot = inv[k];
        if (!slot || typeof slot !== 'object' || !slot.w || !slot.w.grenade) continue;
        var maxAmmo = FL.infNadeMax;
        try { if (slot.ammo !== maxAmmo) { slot.ammo = maxAmmo; changed = true; } } catch (e) {}
        try { if (typeof slot.reserve === 'number' && slot.reserve < maxAmmo) { slot.reserve = maxAmmo; changed = true; } } catch (e) {}
      }
      if (changed) NG.count++;
    }

    /* --------------------------------------------------------------------------
       2.8 WEAPON & SILENT AIM
       -------------------------------------------------------------------------- */
    var PR = { on: 0, ms: 120 };
    var RF = { on: 0, antiSpam: 1, lastFireAt: 0, minGapMs: 65 };
    var QC = { on: 1, fast: 0, slot: 0, ammo: -1, gate: {}, invRef: null, n: 0, sw: 0, dead: 0 };
    var IS = { on: 0 };
    var TB = { on: 0, at: 0 };
    var SL = { on: 0 };
    var DM = { at: 0, mult: 1.3 };
    var WB = 200;

    /* --------------------------------------------------------------------------
       2.8b PERFORMANCE MODE
       -------------------------------------------------------------------------- */
    var PERF = {
      on: 0,
      level: 2,
      lastApply: 0,
      refRenderer: null,
      refScene: null,
      refCamera: null,
      orig: { px: null, shadow: null, far: null, fogFar: null },
      applied: { px: null, shadow: null, far: null, fog: null, hidden: [] }
    };

    function perfVisualFps() {
      if (!PERF.on) return 33;
      if (PERF.level <= 1) return 66;
      if (PERF.level === 2) return 83;
      return 125;
    }
    function perfRadarFps() {
      if (!PERF.on) return 50;
      return PERF.level >= 3 ? 200 : 50;
    }
    function perfLosMs() {
      if (!PERF.on) return 300;
      return PERF.level >= 2 ? 600 : 450;
    }
    function perfAimbotLosMs() {
      if (!PERF.on) return 80;
      return PERF.level >= 2 ? 160 : 120;
    }

    function perfRestoreRefs() {
      var r = PERF.refRenderer;
      var cam = PERF.refCamera;
      var scene = PERF.refScene;
      if (r && PERF.orig.px != null && typeof r.setPixelRatio === 'function') {
        try { r.setPixelRatio(PERF.orig.px); } catch (e) {}
      }
      if (r && r.shadowMap && PERF.orig.shadow != null) {
        try { r.shadowMap.enabled = PERF.orig.shadow; } catch (e) {}
      }
      if (cam && PERF.orig.far != null) {
        try { cam.far = PERF.orig.far; cam.updateProjectionMatrix(); } catch (e) {}
      }
      if (scene && scene.fog && PERF.orig.fogFar != null) {
        try { scene.fog.far = PERF.orig.fogFar; } catch (e) {}
      }
      if (PERF.applied.hidden && PERF.applied.hidden.length) {
        for (var i = 0; i < PERF.applied.hidden.length; i++) {
          try { PERF.applied.hidden[i].visible = true; PERF.applied.hidden[i].__pbHidden = 0; } catch (e) {}
        }
      }
      PERF.refRenderer = null;
      PERF.refScene = null;
      PERF.refCamera = null;
      PERF.orig = { px: null, shadow: null, far: null, fogFar: null };
      PERF.applied = { px: null, shadow: null, far: null, fog: null, hidden: [] };
    }

    function perfApply(g) {
      if (!PERF.on) { perfRestoreRefs(); return; }
      var now = performance.now();
      if (now - PERF.lastApply < 1000) return;
      PERF.lastApply = now;

      var r = g && g.renderer;
      var cam = g && g.camera;
      var scene = g && g.scene;

      if (PERF.refRenderer && r && PERF.refRenderer !== r) perfRestoreRefs();
      if (PERF.refScene && scene && PERF.refScene !== scene) perfRestoreRefs();

      if (PERF.level <= 1) {
        if (PERF.refRenderer) perfRestoreRefs();
        return;
      }

      if (r && typeof r.getPixelRatio === 'function' && typeof r.setPixelRatio === 'function') {
        if (!PERF.refRenderer) { PERF.refRenderer = r; PERF.orig.px = r.getPixelRatio(); }
        var targetPx = PERF.level >= 3 ? 0.75 : Math.max(1.0, Math.min(PERF.orig.px || 1, 1.25));
        var curPx = r.getPixelRatio() || 1;
        if (Math.abs(curPx - targetPx) > 0.01) {
          try { r.setPixelRatio(targetPx); } catch (e) {}
        }
        PERF.applied.px = targetPx;
      }
      if (r && r.shadowMap) {
        if (!PERF.refRenderer) { PERF.refRenderer = r; PERF.orig.shadow = !!r.shadowMap.enabled; }
        if (r.shadowMap.enabled) { try { r.shadowMap.enabled = false; } catch (e) {} }
        PERF.applied.shadow = false;
      }
      if (cam && typeof cam.far === 'number') {
        if (!PERF.refCamera) { PERF.refCamera = cam; PERF.orig.far = cam.far; }
        var shrink = PERF.level >= 3 ? 0.6 : 0.8;
        var newFar = Math.max(60, (PERF.orig.far || cam.far) * shrink);
        if (Math.abs(cam.far - newFar) > 1) {
          try { cam.far = newFar; cam.updateProjectionMatrix(); } catch (e) {}
        }
        PERF.applied.far = newFar;
      }
      if (scene && scene.fog && typeof scene.fog.far === 'number') {
        if (!PERF.refScene) { PERF.refScene = scene; PERF.orig.fogFar = scene.fog.far; }
        var fogShrink = PERF.level >= 3 ? 0.55 : 0.75;
        var newFog = Math.max(40, (PERF.orig.fogFar || scene.fog.far) * fogShrink);
        if (Math.abs(scene.fog.far - newFog) > 1) {
          try { scene.fog.far = newFog; } catch (e) {}
        }
        PERF.applied.fog = newFog;
      }

      if (PERF.level >= 3 && scene && typeof scene.traverse === 'function') {
        if (PERF.applied.hidden && PERF.applied.hidden.length) return;
        var hidden = [];
        try {
          scene.traverse(function (o) {
            if (!o || o.__pbHidden) return;
            if (o.isPoints || (o.isSprite && !o.isMesh)) {
              if (o.visible) { o.visible = false; o.__pbHidden = 1; hidden.push(o); }
            }
          });
        } catch (e) {}
        PERF.applied.hidden = hidden;
      }
    }

    function rfCanFire(now) {
      return !RF.on || !RF.antiSpam || (now - RF.lastFireAt) >= RF.minGapMs;
    }

    function wbGun() {
      try {
        var g = G || game();
        var w = g && g.P && g.P.W;
        return !!(w && !w.melee && !w.grenade && !w.c4);
      } catch (e) { return false; }
    }

    function wbPatch() {
      if (!FL.wallbang) return;
      var g = G || game();
      var L = g && g.bots;
      if (!L || !L.length) return;
      for (var i = 0; i < L.length; i++) {
        var b = L[i];
        if (!b || b.__wbVer === 2 || typeof b.hitTest !== 'function') continue;
        b.__wbVer = 2;
        (function (bot, orig) {
          bot.hitTest = function (o, d, m) {
            var r = (FL.wallbang && wbGun() && typeof m === 'number') ? WB : m;
            try { return orig.call(this, o, d, r); } catch (e) { return null; }
          };
        })(b, b.hitTest);
      }
    }

    var SA = {
      on: 0,
      autoShoot: 0,
      tapShot: 0,
      fovDeg: 35,
      minDist: 1.5,
      target: 'head',
      lastShotAt: 0
    };
    var SA_HEAD = { x: 0, y: 0, z: 0, bot: null, validUntil: 0 };

    function saGetPoint(bot, fromPt) {
      if (!bot) return null;
      var base = (SA.target === 'body') ? bodyPoint(bot) : headPoint(bot);
      if (!base) base = headPoint(bot) || bodyPoint(bot);
      if (!base) return null;
      return predictPoint(bot, { x: base.x, y: base.y, z: base.z }, fromPt || C);
    }

    function getTHREE() {
      if (W.THREE && W.THREE.Vector3) return W.THREE;
      try {
        var g = G || game();
        var V3 = g && g.camera && g.camera.position && g.camera.position.constructor;
        if (V3 && V3.prototype && V3.prototype.project) return { Vector3: V3 };
      } catch (e) {}
      return null;
    }

    function saUpdateHead(g) {
      if (!SA.on || !g || !g.P || !g.P.s || g.P.s.dead) { SA_HEAD.bot = null; return; }
      var s = g.P.s, cam = g.camera, list = g.bots || [];
      if (!cam || !cam.matrixWorld) { SA_HEAD.bot = null; return; }

      var me = cam.matrixWorld.elements;
      var cx = me[12], cy = me[13], cz = me[14];
      var yaw = +s.yaw || 0, pitch = +s.pitch || 0, cp = Math.cos(pitch);
      var fx = -Math.sin(yaw) * cp, fy = Math.sin(pitch), fz = -Math.cos(yaw) * cp;
      var cosFov = Math.cos(clamp(SA.fovDeg, 1, 180) * Math.PI / 180);

      var best = null, bestScore = 1e9;

      for (var i = 0; i < list.length; i++) {
        var p = list[i];
        if (!isHumanEnemy(p, s)) continue;
        var hp = saGetPoint(p, C);
        if (!hp) continue;
        var dx = hp.x - cx, dy = hp.y - cy, dz = hp.z - cz;
        var d = Math.sqrt(dx * dx + dy * dy + dz * dz);
        if (!(d >= SA.minDist) || d > P.reach + 80) continue;
        var dot = (dx * fx + dy * fy + dz * fz) / d;
        if (dot < cosFov) continue;
        var ang = Math.acos(clamp(dot, -1, 1));
        var score = ang + d * 0.001;
        if (score < bestScore) { bestScore = score; best = p; }
      }

      if (!best) { SA_HEAD.bot = null; return; }
      var targetPt = saGetPoint(best, C);
      if (!targetPt) { SA_HEAD.bot = null; return; }
      SA_HEAD.x = targetPt.x; SA_HEAD.y = targetPt.y; SA_HEAD.z = targetPt.z;
      SA_HEAD.bot = best;
      SA_HEAD.validUntil = performance.now() + 250;
    }

    function forceResetCycleTimers(p) {
      if (!p) return;
      ['nextShot', 'chamberT', 'cockT', 'boltT', 'pumpT', 'cockingT', 'reloading', 'swapEnd'].forEach(function (k) {
        if (typeof p[k] === 'number' && p[k] > 0) p[k] = 0;
      });
      try {
        var w = p.W;
        if (w) {
          ['nextShot', 'chamberT', 'cockT', 'boltT', 'pumpT', 'cockingT', 'reloading', 'swapEnd'].forEach(function (k) {
            if (typeof w[k] === 'number' && w[k] > 0) w[k] = 0;
          });
        }
      } catch (e) {}
    }

    function releaseSilentFire(g) {
      if (!silentHolding) return;
      try {
        var curG = g || G || game();
        if (curG && typeof curG.release === 'function') curG.release();
      } catch (e) {}
      silentHolding = false;
      holding = false;
    }

    function saCanFire(g) {
      var s = g && g.P && g.P.s;
      if (!s || s.dead) return false;
      var p = g.P;
      var w = p && p.W;
      if (!w) return false;
      if (w.melee || w.c4 || w.grenade) return false;
      var now = performance.now();
      if (typeof p.nextShot === 'number' && p.nextShot > now + 500) return false;
      if (typeof p.reloading === 'number' && p.reloading > 0) return false;
      if (p.reloading === true) return false;
      if (typeof p.swapEnd === 'number' && p.swapEnd > now + 500) return false;
      return true;
    }

    function saFireStep(g) {
      var s = g && g.P && g.P.s;
      var now = performance.now();

      var hasValidTarget =
        SA.on &&
        SA_HEAD.bot &&
        s && !s.dead &&
        isHumanEnemy(SA_HEAD.bot, s) &&
        now <= SA_HEAD.validUntil &&
        saCanFire(g);

      if (!hasValidTarget) {
        releaseSilentFire(g);
        return;
      }

      if (SA.tapShot) {
        forceResetCycleTimers(g.P);
        if (now < SA.lastShotAt + 22) return;
        SA.lastShotAt = now;
        try { if (typeof g.fire === 'function') g.fire(); } catch (e) {}
        silentHolding = true;
        holding = true;
        setTimeout(function () {
          try { if (typeof g.release === 'function') g.release(); } catch (e) {}
          silentHolding = false;
          holding = false;
        }, 10);
        return;
      }

      if (SA.autoShoot) {
        if (!silentHolding) {
          try { if (typeof g.fire === 'function') g.fire(); } catch (e) {}
          silentHolding = true;
          holding = true;
        }
        SA.lastShotAt = now;
      } else {
        releaseSilentFire(g);
      }
    }

    function saPatch() {
      var g = G || game();
      var L = g && g.bots;
      if (!L || !L.length) return;
      for (var i = 0; i < L.length; i++) {
        var b = L[i];
        if (!b || typeof b.hitTest !== 'function') continue;
        if (b.__saVer === 3) continue;
        b.__saVer = 3;
        (function (bot, origHT) {
          bot.hitTest = function (o, d, m) {
            if (!SA.on) return origHT.call(this, o, d, m);
            try {
              var g2 = G || game();
              if (!g2 || !g2.P || !g2.P.s || !isHumanEnemy(this, g2.P.s) || SA_HEAD.bot !== this) {
                return origHT.call(this, o, d, m);
              }
              var curHp = saGetPoint(this, C);
              if (!curHp) return origHT.call(this, o, d, m);
              SA_HEAD.x = curHp.x; SA_HEAD.y = curHp.y; SA_HEAD.z = curHp.z;

              var cam = g2.camera;
              var me = cam && cam.matrixWorld && cam.matrixWorld.elements;
              if (!me) return origHT.call(this, o, d, m);
              var ox = me[12], oy = me[13], oz = me[14];
              var tdx = SA_HEAD.x - ox, tdy = SA_HEAD.y - oy, tdz = SA_HEAD.z - oz;
              var tlen = Math.hypot(tdx, tdy, tdz);
              if (tlen < 0.5) return origHT.call(this, o, d, m);

              var THREE = getTHREE();
              var no, nd;
              if (THREE && THREE.Vector3) {
                no = new THREE.Vector3(ox, oy, oz);
                nd = new THREE.Vector3(tdx / tlen, tdy / tlen, tdz / tlen);
              } else {
                no = cam.position.clone(); no.set(ox, oy, oz);
                nd = cam.position.clone(); nd.set(tdx / tlen, tdy / tlen, tdz / tlen);
              }
              return origHT.call(this, no, nd, Math.max(tlen + 3, typeof m === 'number' ? m : 200));
            } catch (e) { return origHT.call(this, o, d, m); }
          };
        })(b, b.hitTest);
      }
    }

    /* --------------------------------------------------------------------------
       2.9 WEBSOCKET FILTER & ANTI-KICK
       -------------------------------------------------------------------------- */
    function pbOut(d) {
      if (typeof d === 'string' && (d.indexOf('acflag') >= 0 || d.indexOf('ac\\u0066lag') >= 0)) return null;
      return d;
    }

    var KG = { on: 0, drop: 0 };
    function kgDrop(d) {
      if (!FL.antiKick) return false;
      if (typeof d !== 'string' || d.length < 8 || d.length > 900) return false;
      if (d.indexOf('"t"') < 0) return false;
      var low = d.toLowerCase();
      var m = low.match(/"t"\s*:\s*"([a-z_]+)"/);
      if (!m) return false;
      var t = m[1];
      if (t === 'kick' || t === 'kicked' || t === 'kickout' || t === 'ban' || t === 'banned' ||
          t === 'expel' || t === 'expulso' || t === 'removed' || t === 'removido') { KG.drop++; return true; }
      if ((t === 'error' || t === 'err') && /(kick|expuls|banid|banned|removid|removido)/.test(low)) { KG.drop++; return true; }
      return false;
    }
    (function kgInstall() {
      try {
        var OW = W.WebSocket;
        if (!OW || OW.__pbKG) return;
        var Pp = OW.prototype;
        var sendN = Pp.send, closeN = Pp.close;
        var rsGet = Object.getOwnPropertyDescriptor(Pp, 'readyState').get;
        function revive(rec, wait) {
          if (!FL.antiKick || rec.dead) return;
          clearTimeout(rec.timer);
          rec.timer = setTimeout(function () {
            if (!FL.antiKick || rec.dead) return;
            try { if (rec.live && rsGet.call(rec.live) === 1) return; } catch (e) {}
            var ns;
            try { ns = new OW(rec.url); } catch (e) { revive(rec, 1500); return; }
            rec.live = ns;
            try { ns.binaryType = rec.sock.binaryType || 'arraybuffer'; } catch (e) {}
            ns.onopen = function (ev) { rec.tries = 0; try { if (rec.onopen) rec.onopen.call(rec.sock, ev); } catch (e) {} };
            ns.onmessage = function (ev) { if (kgDrop(ev.data)) return; try { if (rec.onmessage) rec.onmessage.call(rec.sock, ev); } catch (e) {} };
            ns.onerror = function (ev) { try { if (rec.onerror) rec.onerror.call(rec.sock, ev); } catch (e) {} };
            ns.onclose = function (ev) {
              var code = ev ? ev.code : 0; rec.tries++;
              if (code === 1008) {
                if (rec.tries > 6) { rec.dead = 1; return; }
                revive(rec, Math.min(4000, 400 * rec.tries));
                return;
              }
              if (rec.tries > 40) { rec.dead = 1; return; }
              revive(rec, Math.min(8000, 200 * Math.pow(1.3, Math.min(rec.tries, 12))));
            };
          }, wait == null ? 200 : wait);
        }
        function wrap(sock) {
          if (!sock || sock.__pbKG) return sock;
          var rec = { sock: sock, url: sock.url, bin: 'arraybuffer', live: null, tries: 0, dead: 0, timer: 0, onopen: null, onmessage: null, onerror: null, onclose: null };
          sock.__pbKG = rec;
          ['onopen', 'onmessage', 'onerror', 'onclose'].forEach(function (p) {
            try {
              Object.defineProperty(sock, p, {
                configurable: true,
                get: function () { return rec[p]; },
                set: function (fn) {
                  if (p === 'onmessage' && typeof fn === 'function') {
                    rec.onmessage = function (ev) { if (kgDrop(ev.data)) return; return fn.call(rec.sock, ev); };
                  } else rec[p] = fn;
                  try {
                    var d = Object.getOwnPropertyDescriptor(Pp, p);
                    if (rec.live && rsGet.call(rec.live) === 1) d.set.call(rec.live, rec[p]);
                    else d.set.call(sock, rec[p]);
                  } catch (e) {}
                }
              });
            } catch (e) {}
          });
          try { sock.send = function (d) { d = pbOut(d); if (d === null) return; try { if (rec.live && rsGet.call(rec.live) === 1) return sendN.call(rec.live, d); } catch (e) {} return sendN.call(sock, d); }; } catch (e) {}
          try { sock.close = function (c, r) { try { if (rec.live) closeN.call(rec.live, c, r); } catch (e) {} try { return closeN.call(sock, c, r); } catch (e) {} }; } catch (e) {}
          try { Object.defineProperty(sock, 'readyState', { configurable: true, get: function () { try { if (rec.live) return rsGet.call(rec.live); } catch (e) {} try { return rsGet.call(sock); } catch (e) { return 3; } } }); } catch (e) {}
          return sock;
        }
        function WSW(url, prot) {
          var s = arguments.length > 1 ? new OW(url, prot) : new OW(url);
          try { if (/[?&]k=|\/ws(\?|$)/.test(String(url))) return wrap(s); } catch (e) {}
          return s;
        }
        WSW.prototype = Pp;
        try { WSW.CONNECTING = 0; WSW.OPEN = 1; WSW.CLOSING = 2; WSW.CLOSED = 3; } catch (e) {}
        WSW.__pbKG = 1; W.WebSocket = WSW; KG.on = 1;
      } catch (e) {}
    })();

    /* --------------------------------------------------------------------------
       2.10 ESP & VISUAL OVERLAYS
       -------------------------------------------------------------------------- */
    var E = { on: 1, nameOn: 0, wrap: null, slots: [], last: 0, n: 0, v: null };
    var HPO = { on: 0 };

    function eInit() {
      if (E.wrap && E.wrap.parentNode) return true;
      var host = document.body || document.documentElement;
      if (!host) return false;
      var w = document.createElement('div');
      w.setAttribute('data-pb', '1');
      w.style.cssText = 'position:fixed;left:0;top:0;width:100%;height:100%;overflow:hidden;pointer-events:none;z-index:2147483000';
      host.appendChild(w);
      E.wrap = w;
      E.slots = [];
      return true;
    }

    function eSlot(i) {
      var s = E.slots[i];
      if (s) return s;
      var box = document.createElement('div');
      box.style.cssText = 'position:absolute;left:0;top:0;box-sizing:border-box;border:1px solid rgba(6,182,212,.92);border-radius:2px;display:none;will-change:transform;box-shadow:0 0 6px rgba(6,182,212,0.25)';

      var hb = document.createElement('div');
      hb.style.cssText = 'position:absolute;left:-1px;top:-5px;width:calc(100% + 2px);height:3px;background:rgba(0,0,0,.45)';
      var hf = document.createElement('div');
      hf.style.cssText = 'position:absolute;left:0;top:0;height:100%;width:100%;background:#10b981';
      hb.appendChild(hf);

      var dot = document.createElement('div');
      dot.style.cssText = 'position:absolute;left:50%;top:-4px;width:3px;height:3px;margin-left:-2px;background:#f43f5e;border-radius:50%';

      var tx = document.createElement('div');
      tx.style.cssText = 'position:absolute;right:0;top:-15px;font:10px/12px Tahoma,sans-serif;color:#67e8f9;text-shadow:0 1px 2px #000;white-space:nowrap;font-weight:700';

      var tx2 = document.createElement('div');
      tx2.style.cssText = 'position:absolute;left:0;top:-15px;font:10px/12px Tahoma,sans-serif;color:#fb7185;text-shadow:0 1px 2px #000;white-space:nowrap;font-weight:700;display:none';

      var nameEl = document.createElement('div');
      nameEl.style.cssText = 'position:absolute;left:50%;top:-26px;transform:translateX(-50%);font:10px/12px Tahoma,sans-serif;color:#38bdf8;text-shadow:0 1px 2px #000;white-space:nowrap;font-weight:800;display:none';

      box.appendChild(hb); box.appendChild(dot); box.appendChild(tx); box.appendChild(tx2); box.appendChild(nameEl);
      E.wrap.appendChild(box);
      s = { box: box, hp: hf, tx: tx, tx2: tx2, name: nameEl };
      E.slots[i] = s;
      return s;
    }

    function eClear() {
      for (var i = 0; i < E.slots.length; i++) E.slots[i].box.style.display = 'none';
      E.n = 0;
    }

    function eProj(cam, r, x, y, z) {
      if (!E.v) { try { E.v = cam.position.clone(); } catch (e) { return null; } }
      var d = E.v.set(x, y, z).project(cam);
      if (!(d.z > -1 && d.z < 1)) return null;
      return { x: r.left + (d.x * 0.5 + 0.5) * r.width, y: r.top + (-d.y * 0.5 + 0.5) * r.height };
    }

    function eDraw(g) {
      var cam = g.camera, list = g.bots, self = g.P && g.P.s;
      if (!list || !cam || !self || self.dead) { eClear(); return; }
      var host = getGameCanvas();
      if (!host) { eClear(); return; }
      var r = host.getBoundingClientRect();
      if (!(r.width > 0)) { eClear(); return; }

      var me = cam.matrixWorld && cam.matrixWorld.elements;
      var cx = me ? me[12] : 0, cy = me ? me[13] : 0, cz = me ? me[14] : 0;
      var my = self.team, idx = 0;

      for (var i = 0; i < list.length; i++) {
        var p = list[i];
        if (!p || !p.obj || !p.c || p === self || p.team === my || p.dead || !(p.hp > 0)) continue;
        var hp = headPoint(p);
        if (!hp) continue;
        var mm = p.obj.matrixWorld && p.obj.matrixWorld.elements;
        if (!mm) continue;

        var a = eProj(cam, r, hp.x, hp.y, hp.z);
        var b = eProj(cam, r, mm[12], mm[13], mm[14]);
        if (!a || !b) continue;

        var bh = b.y - a.y;
        if (!(bh > 6)) continue;
        if (a.x < r.left - 60 || a.x > r.left + r.width + 60 || b.y < r.top - 60 || a.y > r.top + r.height + 60) continue;

        var bw = Math.min(400, bh * 0.42);
        var s = eSlot(idx++);
        s.box.style.display = 'block';
        s.box.style.transform = 'translate3d(' + (a.x - bw / 2).toFixed(1) + 'px,' + a.y.toFixed(1) + 'px,0)';
        s.box.style.width = bw.toFixed(1) + 'px';
        s.box.style.height = bh.toFixed(1) + 'px';

        var mxh = p.maxHp > 0 ? p.maxHp : 100;
        var f = clamp((p.hp || 0) / mxh, 0, 1);
        s.hp.style.width = (f * 100).toFixed(0) + '%';
        s.hp.style.background = f > 0.5 ? '#10b981' : (f > 0.25 ? '#f59e0b' : '#f43f5e');

        var dist = Math.hypot(hp.x - cx, hp.y - cy, hp.z - cz);
        s.tx.textContent = Math.round(dist) + 'm';

        if (HPO.on) {
          s.tx2.textContent = Math.round(p.hp) + ' HP';
          s.tx2.style.display = 'block';
        } else {
          s.tx2.style.display = 'none';
        }

        if (E.nameOn) {
          var nm = p.name || p.nick || ('bot' + (p.id != null ? p.id : ''));
          s.name.textContent = String(nm).slice(0, 20);
          s.name.style.display = 'block';
        } else {
          s.name.style.display = 'none';
        }
      }

      for (; idx < E.slots.length; idx++) {
        E.slots[idx].box.style.display = 'none';
      }
      E.n = idx;
    }

    var BE = { on: 0, wrap: null, ctx: null, range: 60, _v: null, _camRef: null };
    var BONE_PAIRS = [
      ['Head', 'Neck'], ['Neck', 'Spine3'], ['Spine3', 'Spine2'], ['Spine2', 'Spine1'], ['Spine1', 'Pelvis'],
      ['Spine3', 'L_Clavicle'], ['L_Clavicle', 'L_UpperArm'], ['L_UpperArm', 'L_Forearm'], ['L_Forearm', 'L_Hand'],
      ['Spine3', 'R_Clavicle'], ['R_Clavicle', 'R_UpperArm'], ['R_UpperArm', 'R_Forearm'], ['R_Forearm', 'R_Hand'],
      ['Pelvis', 'L_Thigh'], ['L_Thigh', 'L_Calf'], ['L_Calf', 'L_Foot'],
      ['Pelvis', 'R_Thigh'], ['R_Thigh', 'R_Calf'], ['R_Calf', 'R_Foot']
    ];

    function beInit() {
      if (BE.wrap && BE.wrap.parentNode) return true;
      var host = document.body || document.documentElement;
      if (!host) return false;
      var w = document.createElement('canvas');
      w.setAttribute('data-pb', '1');
      w.style.cssText = 'position:fixed;left:0;top:0;width:100%;height:100%;pointer-events:none;z-index:2147482999';
      host.appendChild(w);
      BE.wrap = w;
      BE.ctx = w.getContext('2d');
      return true;
    }

    function beClear() {
      if (BE.ctx && BE.wrap) BE.ctx.clearRect(0, 0, BE.wrap.width, BE.wrap.height);
    }

    function beProject(cam, r, b, out) {
      if (!BE._v || BE._camRef !== cam) { try { BE._v = cam.position.clone(); BE._camRef = cam; } catch (e) { return false; } }
      var e = b.matrixWorld.elements;
      var d = BE._v.set(e[12], e[13], e[14]).project(cam);
      if (!(d.z > -1 && d.z < 1)) return false;
      out.x = r.left + (d.x * 0.5 + 0.5) * r.width;
      out.y = r.top + (-d.y * 0.5 + 0.5) * r.height;
      return true;
    }

    function beDraw(g) {
      if (!BE.on) { beClear(); return; }
      var cam = g.camera, list = g.bots, self = g.P && g.P.s;
      if (!list || !cam || !self || self.dead || !beInit()) { beClear(); return; }
      var host = getGameCanvas();
      if (!host) { beClear(); return; }
      var r = host.getBoundingClientRect();
      if (!(r.width > 0)) { beClear(); return; }

      var dpr = Math.min(2, devicePixelRatio || 1);
      var w = Math.round(innerWidth * dpr), h = Math.round(innerHeight * dpr);
      if (BE.wrap.width !== w || BE.wrap.height !== h) { BE.wrap.width = w; BE.wrap.height = h; }

      var ctx = BE.ctx;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, innerWidth, innerHeight);
      ctx.lineWidth = 1.2;
      ctx.strokeStyle = 'rgba(56,189,248,0.75)';

      var my = self.team, me = cam.matrixWorld.elements;
      var cx = me[12], cy = me[13], cz = me[14];
      var pa = { x: 0, y: 0 }, pb = { x: 0, y: 0 };

      for (var i = 0; i < list.length; i++) {
        var p = list[i];
        if (!p || !p.obj || !p.c || p === self || p.team === my || p.dead || !(p.hp > 0)) continue;
        var mm = p.obj.matrixWorld && p.obj.matrixWorld.elements;
        if (!mm || Math.hypot(mm[12] - cx, mm[13] - cy, mm[14] - cz) > BE.range) continue;
        var by = p.c.byName;
        if (!by) continue;

        for (var j = 0; j < BONE_PAIRS.length; j++) {
          var ba = by[BONE_PAIRS[j][0]], bb = by[BONE_PAIRS[j][1]];
          if (!ba || !bb || !beProject(cam, r, ba, pa) || !beProject(cam, r, bb, pb)) continue;
          if (pa.x < r.left - 200 || pa.x > r.left + r.width + 200 || pa.y < r.top - 200 || pa.y > r.top + r.height + 200) continue;
          ctx.beginPath();
          ctx.moveTo(pa.x, pa.y);
          ctx.lineTo(pb.x, pb.y);
          ctx.stroke();
        }
      }
    }

    var RD = { on: 0, el: null, dots: [], last: 0 };
    function rdInit() {
      if (RD.el && RD.el.parentNode) return true;
      var host = document.body || document.documentElement;
      if (!host) return false;
      var w = document.createElement('div');
      w.setAttribute('data-pb', '1');
      w.style.cssText = 'position:fixed;right:12px;bottom:12px;width:120px;height:120px;border-radius:50%;background:rgba(9,14,23,.82);backdrop-filter:blur(8px);border:1.5px solid rgba(6,182,212,.65);box-shadow:0 4px 16px rgba(0,0,0,0.6);z-index:2147483000;pointer-events:none;display:none';
      host.appendChild(w);
      RD.el = w;
      RD.dots = [];
      return true;
    }

    function rdDraw(g) {
      if (!RD.on) { if (RD.el) RD.el.style.display = 'none'; return; }
      if (!rdInit()) return;
      RD.el.style.display = 'block';
      var now = performance.now();
      if (now - RD.last < perfRadarFps()) return;
      RD.last = now;

      var s = g.P && g.P.s;
      if (!s || !s.mover || !s.mover.pos) return;
      var sx = s.mover.pos.x, sz = s.mover.pos.z, yaw = +s.yaw || 0, range = 60;
      var list = g.bots || [], idx = 0;

      for (var i = 0; i < list.length; i++) {
        var p = list[i];
        if (!p || p === s || p.dead || !(p.hp > 0) || p.team === s.team) continue;
        var e = p.obj && p.obj.matrixWorld && p.obj.matrixWorld.elements;
        if (!e) continue;
        var dx = e[12] - sx, dz = e[14] - sz;
        if (Math.hypot(dx, dz) > range) continue;

        var ca = Math.cos(-yaw), sa = Math.sin(-yaw);
        var rx = dx * ca - dz * sa, rz = dx * sa + dz * ca;
        var cx = 60 + (rx / range) * 55, cz = 60 + (rz / range) * 55;

        var dot = RD.dots[idx];
        if (!dot) {
          dot = document.createElement('div');
          dot.style.cssText = 'position:absolute;width:5px;height:5px;margin:-2.5px 0 0 -2.5px;border-radius:50%;background:#f43f5e;box-shadow:0 0 5px #f43f5e';
          RD.el.appendChild(dot);
          RD.dots[idx] = dot;
        }
        dot.style.display = 'block';
        dot.style.left = cx.toFixed(1) + 'px';
        dot.style.top = cz.toFixed(1) + 'px';
        idx++;
      }
      for (; idx < RD.dots.length; idx++) RD.dots[idx].style.display = 'none';
    }

    var FC = { on: 0, el: null };
    function fcTick() {
      if (!FC.on) { if (FC.el) FC.el.style.display = 'none'; return; }
      if (!FC.el || !FC.el.parentNode) {
        var host = document.body || document.documentElement;
        if (!host) return;
        var w = document.createElement('div');
        w.setAttribute('data-pb', '1');
        w.style.cssText = 'position:fixed;left:50%;top:50%;transform:translate(-50%,-50%);border:1.5px dashed rgba(6,182,212,.85);border-radius:50%;z-index:2147482999;pointer-events:none;box-shadow:0 0 12px rgba(6,182,212,0.18)';
        host.appendChild(w);
        FC.el = w;
      }
      FC.el.style.display = 'block';
      var r = P.povCircleR;
      FC.el.style.width = (r * 2).toFixed(0) + 'px';
      FC.el.style.height = (r * 2).toFixed(0) + 'px';
    }

    var TR = { on: 0, wrap: null, slots: [], _v: null, _camRef: null };
    function trClear() { for (var i = 0; i < TR.slots.length; i++) TR.slots[i].style.display = 'none'; }
    function trDraw(g) {
      if (!TR.on) { if (TR.wrap) trClear(); return; }
      var cam = g.camera, list = g.bots, self = g.P && g.P.s;
      if (!list || !cam || !self || self.dead) { trClear(); return; }

      if (!TR.wrap || !TR.wrap.parentNode) {
        var host = document.body || document.documentElement;
        if (!host) return;
        var w = document.createElement('div');
        w.setAttribute('data-pb', '1');
        w.style.cssText = 'position:fixed;left:0;top:0;width:100%;height:100%;overflow:hidden;pointer-events:none;z-index:2147482999';
        host.appendChild(w);
        TR.wrap = w;
        TR.slots = [];
      }

      var canvas = getGameCanvas();
      if (!canvas) { trClear(); return; }
      var r = canvas.getBoundingClientRect();
      if (!(r.width > 0)) { trClear(); return; }

      var ox = r.left + r.width / 2, oy = r.top;
      var my = self.team, idx = 0;

      for (var i = 0; i < list.length; i++) {
        var p = list[i];
        if (!p || !p.obj || !p.c || p === self || p.team === my || p.dead || !(p.hp > 0)) continue;
        var hp = headPoint(p);
        if (!hp) continue;

        if (!TR._v || TR._camRef !== cam) { try { TR._v = cam.position.clone(); TR._camRef = cam; } catch (e) { continue; } }
        var d = TR._v.set(hp.x, hp.y, hp.z).project(cam);
        if (!(d.z > -1 && d.z < 1)) continue;

        var tx = r.left + (d.x * 0.5 + 0.5) * r.width;
        var ty = r.top + (-d.y * 0.5 + 0.5) * r.height;
        if (tx < r.left - 40 || tx > r.left + r.width + 40 || ty < r.top - 40 || ty > r.top + r.height + 40) continue;

        var dx = tx - ox, dy = ty - oy, len = Math.hypot(dx, dy);
        if (len < 20) continue;

        var line = TR.slots[idx];
        if (!line) {
          line = document.createElement('div');
          line.style.cssText = 'position:absolute;left:0;top:0;height:1.5px;background:linear-gradient(90deg,rgba(6,182,212,.95),rgba(16,185,129,.35));transform-origin:0 50%;display:none;box-shadow:0 0 4px rgba(6,182,212,.6);border-radius:1px';
          TR.wrap.appendChild(line);
          TR.slots[idx] = line;
        }
        line.style.display = 'block';
        line.style.left = ox.toFixed(1) + 'px';
        line.style.top = oy.toFixed(1) + 'px';
        line.style.width = len.toFixed(1) + 'px';
        line.style.transform = 'rotate(' + (Math.atan2(dy, dx) * 180 / Math.PI).toFixed(2) + 'deg)';
        idx++;
      }
      for (; idx < TR.slots.length; idx++) TR.slots[idx].style.display = 'none';
    }

    /* --------------------------------------------------------------------------
       2.11 UNIFIED MAIN LOOP (rAF SCHEDULER)
       -------------------------------------------------------------------------- */
    var _timers = {
      wb: 0, esp: 0, bone: 0, tracer: 0, silentScan: 0, silentFire: 0,
      respawn: 0, trigger: 0, ammo: 0, dmg: 0, snade: 0
    };

    function revalidateG() {
      if (G && (!G.P || !G.P.s)) {
        G = null; st.G = false;
      }
      if (!G) {
        G = game();
        if (G) { st.G = true; log('G unlocked', V); buzz(30); }
      }
    }

    function mainLoop() {
      requestAnimationFrame(mainLoop);
      var now = performance.now();

      revalidateG();
      if (!G) return;

      var g = G;
      var p = g.P;
      var self = p && p.s;
      var cam = g.camera;
      if (!p || !self) return;

      try { perfApply(g); } catch (e) {}

      if (FLY.on) { try { flyTick(0.016); } catch (e) {} }
      if (FL.noclip) {
        try {
          ncInstall();
          if (self && self.mover && self.mover.pos && self.mover.pos.y < -50) {
            self.mover.pos.y = 5;
            self.mover.vy = 0;
          }
        } catch (e) {}
      } else if (NC.active) {
        ncUninstall();
      }
      try { gbTick(now); } catch (e) {}

      if (IR.on && now >= IR.at) {
        IR.at = now + 200;
        try { if (self && self.dead) self.dead = false; } catch (e) {}
      }

      if (FL.noRecoil) {
        try {
          var r = p.rec;
          if (r) { r.v = 0; r.A = 0; r.t = 0; r.T = 0; r.hPend = 0; r.hRate = 0; r.hState = 0; }
          if (p.kick) p.kick = 0;
        } catch (e) {}
      }

      if (RF.on) {
        try {
          var w = p.W;
          if (w && !w.melee && !w.c4 && !w.grenade && (!RF.antiSpam || now - RF.lastFireAt >= RF.minGapMs)) {
            if (typeof p.nextShot === 'number' && p.nextShot > 0) p.nextShot = 0;
            if (typeof p.swapEnd === 'number' && p.swapEnd > 0) p.swapEnd = 0;
          }
        } catch (e) {}
      }

      if (IS.on) {
        try {
          if (p.fpActs && p.fpActs.zoom) p.fpActs.zoom.timeScale = 20;
          if (p.fpActs && p.fpActs.scope) p.fpActs.scope.timeScale = 20;
          if (typeof p.scopeT === 'number' && p.scopeT > 0 && p.scopeT < 0.2) p.scopeT = 0.05;
        } catch (e) {}
      }

      if (p.inv) {
        try {
          if (QC.invRef !== p.inv) { QC.invRef = p.inv; QC.gate = {}; QC.slot = p.slot; QC.ammo = p.ammo; }
          if (self.dead) {
            if (!QC.dead) { QC.dead = 1; QC.gate = {}; }
            QC.slot = p.slot; QC.ammo = p.ammo;
          } else {
            if (QC.dead) { QC.dead = 0; QC.gate = {}; QC.slot = p.slot; QC.ammo = p.ammo; }
            if (p.slot === QC.slot && typeof p.ammo === 'number' && QC.ammo >= 0 && p.ammo < QC.ammo) {
              QC.gate[p.slot] = +p.nextShot || 0;
              QC.n++;
            }
            if (p.slot !== QC.slot) {
              if (QC.on) {
                p.swapEnd = 0;
                p.nextShot = QC.fast ? 0 : (QC.gate[p.slot] || 0);
                if (p.fpActs && p.fpActs.change) p.fpActs.change.timeScale = 8;
                QC.sw++;
              }
              QC.slot = p.slot;
            }
            QC.ammo = p.ammo;
          }
        } catch (e) {}
      }

      if (now - _timers.ammo >= 180) {
        _timers.ammo = now;
        try { nadeTick(); } catch (e) {}
        if (FL.infAmmo) {
          try {
            if (p.inv) {
              for (var k in p.inv) {
                var sInv = p.inv[k];
                if (sInv && typeof sInv === 'object' && (!sInv.w || !sInv.w.grenade) && typeof sInv.reserve === 'number') {
                  sInv.reserve = 999;
                }
              }
            }
            if (typeof p.extReserve === 'number') p.extReserve = 99;
            var wInf = p.W;
            if (wInf && !wInf.melee && !wInf.c4 && !wInf.grenade) {
              if (typeof p.ammo === 'number' && p.ammo !== 999) p.ammo = 999;
              if (typeof p.reserve === 'number' && p.reserve !== 999) p.reserve = 999;
            }
          } catch (e) {}
        }
      }

      if (now - _timers.dmg >= 500) {
        _timers.dmg = now;
        try {
          var wDmg = p.W;
          if (wDmg && !wDmg.melee && !wDmg.c4 && !wDmg.grenade && !wDmg.dmg && wDmg.damage > 0 && !wDmg.__pbD) {
            wDmg.damage = Math.round(wDmg.damage * DM.mult);
            wDmg.__pbD = 1;
          }
        } catch (e) {}
      }

      if (now - _timers.wb >= 1000) {
        _timers.wb = now;
        try { wbPatch(); } catch (e) {}
      }

      if (SN.on && now - _timers.snade >= SNB.interval) {
        _timers.snade = now;
        try { snScanAndHoming(g); } catch (e) {}
      }

      fcTick();
      if (RD.on) { try { rdDraw(g); } catch (e) {} } else if (RD.el) { RD.el.style.display = 'none'; }

      var vFps = perfVisualFps();
      if (!E.on) {
        eClear();
      } else if (now - _timers.esp >= vFps) {
        _timers.esp = now;
        if (eInit()) { try { eDraw(g); } catch (err) { eClear(); } }
      }

      if (now - _timers.bone >= vFps) {
        _timers.bone = now;
        try { beDraw(g); } catch (e) { beClear(); }
      }

      if (TR.on && now - _timers.tracer >= vFps) {
        _timers.tracer = now;
        try { trDraw(g); } catch (e) {}
      } else if (!TR.on && TR.wrap) {
        trClear();
      }

      if (SA.on && (SA.autoShoot || SA.tapShot)) {
        if (now - _timers.silentScan >= 33) {
          _timers.silentScan = now;
          try {
            saUpdateHead(g);
            saPatch();
          } catch (e) {}
        }
        try { saFireStep(g); } catch (e) {}
      } else if (silentHolding) {
        releaseSilentFire(g);
      }

      if (!self || self.dead) {
        if (holding || silentHolding) up();
        lastPick = null;
        st.lock = 0;
        AB.target = null;
        AB.freshFire = 0;
        AIMLOCK.locked = false;
        return;
      }

      if (!self.__pbYawLocked) lockYawPitch(self);

      var m = cam.matrixWorld.elements;
      C.x = m[12]; C.y = m[13]; C.z = m[14];

      var yaw = +self.yaw || 0, pitch = +self.pitch || 0;
      var cp = Math.cos(pitch);
      F.x = -Math.sin(yaw) * cp;
      F.y = Math.sin(pitch);
      F.z = -Math.cos(yaw) * cp;

      if (TB.on && now >= _timers.trigger) {
        _timers.trigger = now + 40;
        try {
          var wTb = p.W;
          if (wTb && !wTb.melee && !wTb.grenade && !wTb.c4) {
            var origTb = { x: C.x, y: C.y, z: C.z };
            var dirTb = { x: F.x, y: F.y, z: F.z };
            var botsTb = g.bots || [];
            for (var ti = 0; ti < botsTb.length; ti++) {
              var bt = botsTb[ti];
              if (!isHumanEnemy(bt, self) || typeof bt.hitTest !== 'function') continue;
              var ht = hitTestSafe(bt, origTb, dirTb, 200);
              if (ht && ht.head && now >= nextTap && !holding) {
                down();
                holding = true;
                var hMs = 40 + Math.random() * 25;
                setTimeout(function () { if (holding) up(); }, hMs);
                nextTap = now + hMs + 80 + Math.random() * 60;
                break;
              }
            }
          }
        } catch (e) {}
      }

      var list = g.bots;
      var best = null, bestPt = null, bestA = 1e9, bestD = 1e9;
      var myTeam = self.team, n = 0, en = 0;

      for (var i = 0; i < list.length; i++) {
        var bot = list[i];
        if (!isBotReal(bot)) continue;
        n++;
        if (bot.team === myTeam || bot === self) continue;
        var hp = getTargetPointLead(bot, C);
        if (!hp) continue;
        var dx = hp.x - C.x, dy = hp.y - C.y, dz = hp.z - C.z;
        var d = Math.hypot(dx, dy, dz);
        if (d < 2 || d > P.reach) continue;
        en++;

        var ey = wrap(Math.atan2(-dx, -dz) - yaw);
        var ep = Math.asin(clamp(dy / d, -1, 1)) - pitch;
        var a = Math.hypot(ey, ep);
        if (a > P.cone || !canLockTarget(g, cam, bot, hp)) continue;

        var better = (P.mode === 'angle')
          ? (a < bestA)
          : (d < bestD - P.bias || (d <= bestD + P.bias && a < bestA));
        if (better) {
          bestA = a; bestD = d; best = bot;
          bestPt = { x: hp.x, y: hp.y, z: hp.z };
        }
      }
      st.bots = n;
      st.enemies = en;

      var wantAcquire = P.aimbotOn && (AB.freshFire || (fireHeld > 0 && now >= AB.lockUntil));
      if (!wantAcquire && !P.autoFire && !fireHeld) {
        st.bots = n;
        aimFlush(g);
        return;
      }

      var doAimbot = false;
      if (wantAcquire) {
        AB.freshFire = 0;
        var bestAb = null, bestAbD = 1e9;
        for (var j = 0; j < list.length; j++) {
          var q = list[j];
          if (!isBotReal(q) || q === self || q.team === myTeam) continue;
          var qp = getTargetPointLead(q, C);
          if (!qp) continue;
          var qd = Math.hypot(qp.x - C.x, qp.y - C.y, qp.z - C.z);
          if (qd >= 2 && qd <= P.reach && canAimbotTarget(g, cam, q, qp) && qd < bestAbD) {
            bestAbD = qd;
            bestAb = { bot: q, p: { x: qp.x, y: qp.y, z: qp.z } };
          }
        }
        if (bestAb) {
          AB.target = bestAb;
          AB.lockUntil = now + P.aimbotHoldMs;
          AB.lastShot = now;
        }
      }

      if (AB.target && now < AB.lockUntil) doAimbot = true;
      else AB.target = null;

      if (doAimbot && AB.target) {
        var curAp = getTargetPointLead(AB.target.bot, C) || AB.target.p;
        if (!canAimbotTarget(g, cam, AB.target.bot, curAp)) {
          AB.target = null; AB.lockUntil = 0; AIMLOCK.locked = false; st.aimbot = 0;
          aimFlush(g);
          return;
        }
        AB.target.p = { x: curAp.x, y: curAp.y, z: curAp.z };
        var ap = AB.target.p;
        var tYawAb = wrap(Math.atan2(-(ap.x - C.x), -(ap.z - C.z)));
        var tPitchAb = Math.asin(clamp((ap.y - C.y) / Math.max(0.001, Math.hypot(ap.x - C.x, ap.y - C.y, ap.z - C.z)), -1, 1));
        var rawY = self.__pbYawRaw != null ? self.__pbYawRaw : (+self.yaw || 0);
        var rawP = self.__pbPitchRaw != null ? self.__pbPitchRaw : (+self.pitch || 0);
        var k = clamp(P.aimbotGain * 0.7, 0.35, 1);

        AIMLOCK.on = true;
        AIMLOCK.locked = true;
        AIMLOCK.targetYaw = rawY + wrap(tYawAb - rawY) * k;
        AIMLOCK.targetPitch = rawP + (tPitchAb - rawP) * k;
        st.aimbot = 1;
      } else {
        st.aimbot = 0;
        if (!best || !aimOn) {
          AIMLOCK.locked = false; lastPick = null; st.lock = 0;
          if (holding && !silentHolding) up();
          aimFlush(g);
          return;
        }
        var tYaw = wrap(Math.atan2(-(bestPt.x - C.x), -(bestPt.z - C.z)));
        var tPitch = Math.asin(clamp((bestPt.y - C.y) / Math.max(0.001, bestD), -1, 1));
        var rawY2 = self.__pbYawRaw != null ? self.__pbYawRaw : (+self.yaw || 0);
        var rawP2 = self.__pbPitchRaw != null ? self.__pbPitchRaw : (+self.pitch || 0);
        var gainBase = (P.lockMode === 'pov') ? clamp(P.gain, 0.85, 1) : clamp(P.gain, 0.5, 1);

        AIMLOCK.on = true;
        AIMLOCK.locked = true;
        AIMLOCK.targetYaw = rawY2 + wrap(tYaw - rawY2) * gainBase;
        AIMLOCK.targetPitch = rawP2 + (tPitch - rawP2) * gainBase;
        st.err = bestA; st.dist = bestD; st.lock = 1; lastPick = best;
      }

      if (!(P.autoFire || fireHeld) || now < nextTap || holding) {
        if (P.aimbotOn && fireHeld > 0) AB.lastShot = now;
        aimFlush(g);
        return;
      }

      var fireTarget = (doAimbot && AB.target) ? AB.target.bot : best;
      var firePoint = (doAimbot && AB.target) ? AB.target.p : bestPt;
      if (!fireTarget || !firePoint) { aimFlush(g); return; }
      if (!doAimbot && !FL.wallbang && !hasLineOfSightThrottled(g, cam, fireTarget, firePoint)) { aimFlush(g); return; }

      var hit = null;
      try { hit = hitTestSafe(fireTarget, C, F, P.reach); } catch (e) {}
      if (!hit || (RF.on && !rfCanFire(now))) { aimFlush(g); return; }

      down();
      holding = true;
      RF.lastFireAt = now;

      var holdMs, gapMs;
      if (RF.on) {
        holdMs = 18 + Math.random() * 12;
        gapMs = RF.antiSpam ? (RF.minGapMs + Math.random() * 25) : (10 + Math.random() * 10);
      } else if (SF.on) {
        holdMs = 20 + Math.random() * 15;
        gapMs = 25 + Math.random() * 20;
      } else {
        holdMs = 45 + Math.random() * 30;
        gapMs = 90 + Math.random() * 70;
      }

      setTimeout(function () { if (holding && !silentHolding) up(); }, holdMs);
      nextTap = now + holdMs + gapMs;
      if (P.aimbotOn) AB.lastShot = now;
      aimFlush(g);
    }

    setInterval(function () {
      try { var g = G || game(); if (g) aimFlush(g); } catch (e) {}
    }, 8);

    setInterval(function () {
      try {
        var Bx = W.PBAndroid;
        var v = Bx && Bx.poll ? Bx.poll() : 0;
        if (v === 1) { aimOn = true; st.aim = true; buzz([20, 40, 20]); }
        else if (v === -1) { aimOn = false; st.aim = false; up(); buzz(60); }
      } catch (e) {}
    }, 120);

    /* --------------------------------------------------------------------------
       2.12 PUBLIC INTERNAL APIS
       -------------------------------------------------------------------------- */
    var PB_API = {
      state: function () {
        return {
          v: V, aim: aimOn, G: !!G, bots: st.bots, enemies: st.enemies, lock: st.lock,
          dist: +st.dist.toFixed(2), mode: P.mode, aimMode: P.aimMode,
          povCircleR: P.povCircleR, hitbox: P.hitbox,
          err: +(st.err * 57.2958).toFixed(2), fire: fireHeld, autoFire: P.autoFire,
          sens: O.sens, fov: O.fov, aimbot: P.aimbotOn, aimbotActive: st.aimbot,
          bulletSpeed: P.bulletSpeed, leadFactor: P.leadFactor, lockMode: P.lockMode
        };
      },
      cfg: function (o) { if (o) for (var k in o) if (k in P) P[k] = o[k]; return P; },
      on: function () { aimOn = true; st.aim = true; return 'on'; },
      off: function () { aimOn = false; st.aim = false; AIMLOCK.locked = false; up(); return 'off'; },
      aimMode: function () { P.aimMode = 'pov'; try { localStorage.setItem('ir_aimmode', 'pov'); } catch (e) {} return P.aimMode; },
      povCircle: function (v) { if (typeof v === 'number' && v >= 1) { P.povCircleR = v; try { localStorage.setItem('ir_povcirc', String(v)); } catch (e) {} } return P.povCircleR; },
      hitbox: function (v) { if (v === 'head' || v === 'body' || v === 'nearest') { P.hitbox = v; st.hitbox = v; try { localStorage.setItem('ir_hitbox', v); } catch (e) {} } return P.hitbox; },
      lockMode: function (m) {
        if (m === 'legacy' || m === 'pov') {
          P.lockMode = m; st.lockMode = m;
          try { localStorage.setItem('ir_lockmode', m); } catch (e) {}
          AIMLOCK.locked = false;
          _losCache = new WeakMap(); _povCache = new WeakMap(); _aimbotLosCache = new WeakMap();
        }
        return P.lockMode;
      },
      aimbot: function (on) {
        P.aimbotOn = on ? 1 : 0;
        if (!P.aimbotOn) { AB.target = null; AIMLOCK.locked = false; }
        _aimbotLosCache = new WeakMap();
        try { localStorage.setItem('ir_aimbot', P.aimbotOn ? '1' : '0'); } catch (e) {}
        return P.aimbotOn;
      },
      aimbotGain: function (v) { if (typeof v === 'number' && v > 0) { P.aimbotGain = v; try { localStorage.setItem('ir_aimbot_gain', String(v)); } catch (e) {} } return P.aimbotGain; },
      aimbotHold: function (v) { if (typeof v === 'number' && v >= 50) { P.aimbotHoldMs = v; try { localStorage.setItem('ir_aimbot_hold', String(v)); } catch (e) {} } return P.aimbotHoldMs; },
      bulletSpeed: function (v) { if (typeof v === 'number' && v > 0) { P.bulletSpeed = v; try { localStorage.setItem('ir_bullet_speed', String(v)); } catch (e) {} } return P.bulletSpeed; },
      leadFactor: function (v) { if (typeof v === 'number' && v >= 0) { P.leadFactor = v; try { localStorage.setItem('ir_lead', String(v)); } catch (e) {} } return P.leadFactor; },
      autoFire: function (on) { P.autoFire = on ? 1 : 0; return P.autoFire; },
      sens: function (v) { if (typeof v === 'number' && v > 0) { O.sens = v; try { var o = JSON.parse(localStorage.getItem('pbweb_opts') || '{}'); o.sens = v; localStorage.setItem('pbweb_opts', JSON.stringify(o)); } catch (e) {} } return O.sens; },
      fov: function (v) { if (typeof v === 'number' && v > 0) { O.fov = v; try { var o = JSON.parse(localStorage.getItem('pbweb_opts') || '{}'); o.fov = v; localStorage.setItem('pbweb_opts', JSON.stringify(o)); } catch (e) {} } return O.fov; },
      invert: function (on) { O.invert = !!on; try { var o = JSON.parse(localStorage.getItem('pbweb_opts') || '{}'); o.invert = O.invert; localStorage.setItem('pbweb_opts', JSON.stringify(o)); } catch (e) {} return O.invert; },
      unlock: function () { AIMLOCK.locked = false; return 'unlocked'; }
    };

    var VIS_API = {
      on: function () { E.on = 1; return 'on'; },
      off: function () { E.on = 0; eClear(); return 'off'; },
      is: function () { return E.on; },
      name: function (on) { E.nameOn = on ? 1 : 0; return E.nameOn; },
      nameOn: function () { return E.nameOn; },
      dmg: function (m) { if (typeof m === 'number' && m >= 1 && m <= 3) DM.mult = m; return DM.mult; },
      bone: function (on, range) { BE.on = on ? 1 : 0; if (typeof range === 'number') BE.range = range; if (!on) beClear(); return { on: BE.on, range: BE.range }; }
    };

    var QC_API = {
      cfg: function (o) { if (o) for (var k in o) if (k === 'on' || k === 'fast') QC[k] = o[k]; return { on: QC.on, fast: QC.fast }; },
      on: function () { QC.on = 1; return 'on'; },
      off: function () { QC.on = 0; return 'off'; },
      swap: function () {
        try {
          var o = { code: 'KeyQ', key: 'KeyQ', bubbles: true, cancelable: true };
          W.dispatchEvent(new KeyboardEvent('keydown', o));
          W.dispatchEvent(new KeyboardEvent('keyup', o));
        } catch (e) {}
        return 'swap';
      },
      st: function () { return { v: V, on: QC.on, shots: QC.n, swaps: QC.sw, fast: QC.fast }; }
    };

    var PBX_API = {
      pred: function (on, ms) { PR.on = on ? 1 : 0; if (typeof ms === 'number') PR.ms = ms; return { on: PR.on, ms: PR.ms }; },
      rapid: function (on) { RF.on = on ? 1 : 0; return RF.on; },
      rapidAntiSpam: function (on) { RF.antiSpam = on ? 1 : 0; return RF.antiSpam; },
      instScope: function (on) { IS.on = on ? 1 : 0; return IS.on; },
      trig: function (on) { TB.on = on ? 1 : 0; return TB.on; },
      silent: function (on) {
        SA.on = on ? 1 : 0;
        if (!SA.on) { SA_HEAD.bot = null; releaseSilentFire(); }
        saPatch();
        return SA.on;
      },
      silentAutoShoot: function (on) {
        SA.autoShoot = on ? 1 : 0;
        if (!SA.autoShoot && !SA.tapShot) releaseSilentFire();
        return SA.autoShoot;
      },
      silentTapShot: function (on) {
        SA.tapShot = on ? 1 : 0;
        if (!SA.tapShot && !SA.autoShoot) releaseSilentFire();
        return SA.tapShot;
      },
      silentTarget: function (t) { if (t === 'head' || t === 'body') SA.target = t; return SA.target; },
      silentFov: function (deg) { if (typeof deg === 'number' && deg > 0 && deg <= 180) SA.fovDeg = deg; return SA.fovDeg; },
      silentMinDist: function (m) { if (typeof m === 'number' && m >= 0) SA.minDist = m; return SA.minDist; },
      lob: function (on) { SL.on = on ? 1 : 0; return SL.on; },
      respawn: function (on) { IR.on = on ? 1 : 0; return IR.on; },
      radar: function (on) { RD.on = on ? 1 : 0; if (!on && RD.el) RD.el.style.display = 'none'; return RD.on; },
      hpo: function (on) { HPO.on = on ? 1 : 0; return HPO.on; },
      fovc: function (on) { FC.on = on ? 1 : 0; return FC.on; },
      tracer: function (on) { TR.on = on ? 1 : 0; if (!on) trClear(); return TR.on; },
      wallbang: function (on) { FL.wallbang = on ? 1 : 0; return FL.wallbang; },
      infAmmo: function (on) { FL.infAmmo = on ? 1 : 0; return FL.infAmmo; },
      noRecoil: function (on) { FL.noRecoil = on ? 1 : 0; return FL.noRecoil; },
      godmode: function (on) { FL.godmode = on ? 1 : 0; return FL.godmode; },
      noclip: function (on) { FL.noclip = on ? 1 : 0; if (!FL.noclip) ncUninstall(); else ncInstall(); return FL.noclip; },
      antiKick: function (on) { FL.antiKick = on ? 1 : 0; return FL.antiKick; },
      smoothFire: function (on) { SF.on = on ? 1 : 0; return SF.on; },
      fly: function (on) { return flyToggle(on); },
      flyMode: function (m) { if (m === 'jump' || m === 'hover') FLY.mode = m; return FLY.mode; },
      flyBypass: function (on) { FLYB.on = on ? 1 : 0; return FLYB.on; },
      noFall: function (on) { FL.noFall = on ? 1 : 0; return FL.noFall; },
      infNade: function (on) { FL.infNade = on ? 1 : 0; return FL.infNade; },
      infNadeMax: function (n) { if (typeof n === 'number' && n >= 1 && n <= 999) FL.infNadeMax = n | 0; return FL.infNadeMax; },
      infNadeSt: function () {
        var g = G || game();
        var out = { on: FL.infNade, max: FL.infNadeMax, count: NG.count, grenades: [] };
        try {
          var inv = g && g.P && g.P.inv;
          if (inv) for (var k in inv) {
            var s = inv[k];
            if (s && s.w && s.w.grenade) {
              out.grenades.push({ slot: +k, name: s.w.name || s.w.id, kind: s.w.kind, ammo: s.ammo, reserve: s.reserve });
            }
          }
        } catch (e) {}
        return out;
      },
      silentNade: function (on) { SN.on = on ? 1 : 0; return SN.on; },
      silentNadeSide: function (s) {
        if (s === 'enemy' || s === 'ally') { if (SN.side !== s) SN.pinnedNameBot = null; SN.side = s; }
        return SN.side;
      },
      silentNadeMode: function (m) {
        if (m === 'aim' || m === 'random' || m === 'name_order') { if (SN.mode !== m || m !== 'name_order') SN.pinnedNameBot = null; SN.mode = m; }
        return SN.mode;
      },
      silentNadeTarget: function (name) { SN.targetName = name ? String(name) : ''; SN.pinnedNameBot = null; return SN.targetName; },
      silentNadeTargets: function () {
        var g = G || game();
        if (!g || !g.bots || !g.P || !g.P.s) return [];
        var self = g.P.s, out = [], seen = {};
        for (var i = 0; i < g.bots.length; i++) {
          var p = g.bots[i];
          if (!snIsValidSide(p, self)) continue;
          var lbl = snBotLabel(p, i);
          if (!seen[lbl]) { seen[lbl] = 1; out.push(lbl); }
        }
        return out.sort(function (a, b) { return a.localeCompare(b, undefined, { sensitivity: 'base' }); });
      },
      silentNadeHoming: function (on) { SN.homing = on ? 1 : 0; return SN.homing; },
      silentNadeLOS: function (on) { SN.requireLOS = on ? 1 : 0; return SN.requireLOS; },
      silentNadeBypass: function (on) { SNB.on = on ? 1 : 0; return SNB.on; },
      silentNadeSt: function () {
        return {
          on: SN.on, side: SN.side, mode: SN.mode, targetName: SN.targetName,
          homing: SN.homing, nadeCount: SN.nadeCount, hasTarget: !!SN.lockedTarget,
          targetBotName: (SN.lockedTarget && SN.lockedTarget.bot && (SN.lockedTarget.bot.name || SN.lockedTarget.label)) || null,
          bypass: SNB.on
        };
      },
      perf: function (on) {
        PERF.on = on ? 1 : 0;
        if (!PERF.on) perfRestoreRefs();
        else PERF.lastApply = 0;
        return PERF.on;
      },
      perfLevel: function (lvl) {
        if (typeof lvl === 'number' && lvl >= 1 && lvl <= 3) {
          PERF.level = lvl | 0;
          PERF.lastApply = 0;
        }
        return PERF.level;
      },
      perfSt: function () {
        return {
          on: PERF.on, level: PERF.level,
          applied: {
            px: PERF.applied.px, shadow: PERF.applied.shadow,
            far: PERF.applied.far, fog: PERF.applied.fog,
            hidden: PERF.applied.hidden ? PERF.applied.hidden.length : 0
          },
          refs: { renderer: !!PERF.refRenderer, scene: !!PERF.refScene, camera: !!PERF.refCamera }
        };
      },
      authSt: function () {
        return {
          status: AUTH_STATE.status, reason: AUTH_STATE.reason,
          key: AUTH_STATE.key, deviceId: AUTH_STATE.deviceId,
          hasToken: !!AUTH_STATE.token, tokenExp: AUTH_STATE.tokenExp,
          bound: AUTH_STATE.bound, url: AUTH_URL
        };
      },
      authReset: function () {
        try { authClearCache(); } catch (e) {}
        try { localStorage.removeItem(AUTH_DEVICE_KEY); } catch (e) {}
        AUTH_STATE = { status: 'pending', reason: '', key: '', deviceId: '', token: '', tokenExp: 0, bound: '' };
        authShowGateOverlay('', '');
        return 'reset';
      },
      authSet: function (key) {
        return authVerify(String(key || '').trim().toUpperCase(), true);
      },
      panic: function () {
        try {
          PERF.on = 0; perfRestoreRefs();
          SA.on = 0; SA.autoShoot = 0; SA.tapShot = 0; releaseSilentFire();
          FL.godmode = 0; FL.noclip = 0; FLY.on = 0; ncUninstall();
          try { saveSettings(); } catch (e) {}
        } catch (e) {}
        try { location.reload(); } catch (e) {}
        return 'panic';
      },
      st: function () {
        return {
          pred: PR.on, rapid: RF.on, rapidAntiSpam: RF.antiSpam,
          instScope: IS.on, trig: TB.on, silent: SA.on, silentAutoShoot: SA.autoShoot,
          silentTapShot: SA.tapShot, silentTarget: SA.target, silentFov: SA.fovDeg,
          silentMinDist: SA.minDist,
          lob: SL.on, respawn: IR.on, radar: RD.on, hpo: HPO.on, fovc: FC.on, tracer: TR.on,
          wallbang: FL.wallbang, infAmmo: FL.infAmmo, noRecoil: FL.noRecoil,
          godmode: FL.godmode, noclip: FL.noclip, antiKick: FL.antiKick,
          aimbot: P.aimbotOn, smoothFire: SF.on, bulletSpeed: P.bulletSpeed, leadFactor: P.leadFactor,
          lockMode: P.lockMode, flyOn: FLY.on, flyMode: FLY.mode, flyBypass: FLYB.on,
          noFall: FL.noFall, infNade: FL.infNade, infNadeMax: FL.infNadeMax,
          silentNade: SN.on, silentNadeSide: SN.side, silentNadeMode: SN.mode,
          silentNadeTarget: SN.targetName, silentNadeBypass: SNB.on, espName: E.nameOn,
          perf: PERF.on, perfLevel: PERF.level,
          saHead: SA_HEAD.bot ? { x: +SA_HEAD.x.toFixed(2), y: +SA_HEAD.y.toFixed(2), z: +SA_HEAD.z.toFixed(2), name: SA_HEAD.bot.name, hp: SA_HEAD.bot.hp } : null
        };
      }
    };

    W.__pb = PB_API; HIDDEN.pb = PB_API;
    W.__pbvis = VIS_API; HIDDEN.pbvis = VIS_API;
    W.__pbqc = QC_API; HIDDEN.pbqc = QC_API;
    W.__pbx = PBX_API; HIDDEN.pbx = PBX_API;

    ['__pb', '__pbvis', '__pbnade', '__pbqc', '__pbx'].forEach(function (k) {
      try {
        var v = W[k];
        if (v) Object.defineProperty(W, k, { configurable: false, enumerable: false, get: function () { return v; } });
      } catch (e) {}
    });

    /* --------------------------------------------------------------------------
       2.13 SETTINGS PERSISTENCE
       -------------------------------------------------------------------------- */
    var SETTINGS_KEY = 'vanguard_settings_v4';
    var _saveTimer = 0;

    function saveSettings() {
      try {
        var ps = PB_API.state();
        var xs = PBX_API.st();
        var data = {
          version: 4,
          aim: ps.aim, povCircleR: ps.povCircleR, hitbox: ps.hitbox,
          aimbot: ps.aimbot, aimbotGain: P.aimbotGain, aimbotHoldMs: P.aimbotHoldMs,
          bulletSpeed: ps.bulletSpeed, leadFactor: ps.leadFactor, lockMode: ps.lockMode,
          autoFire: P.autoFire, sens: O.sens, fov: O.fov, invert: O.invert,
          cone: P.cone, reach: P.reach, gain: P.gain, mode: P.mode, bias: P.bias,
          flyOn: FLY.on, flyMode: FLY.mode, flyBypass: FLYB.on, noFall: FL.noFall,
          pred: xs.pred, predMs: PR.ms,
          rapid: xs.rapid, rapidAntiSpam: xs.rapidAntiSpam, instScope: xs.instScope,
          trig: xs.trig, silent: xs.silent,
          silentAutoShoot: xs.silentAutoShoot, silentTapShot: xs.silentTapShot,
          silentTarget: xs.silentTarget, silentFov: xs.silentFov, silentMinDist: xs.silentMinDist,
          respawn: xs.respawn, radar: xs.radar, hpo: xs.hpo, fovc: xs.fovc, tracer: xs.tracer,
          wallbang: xs.wallbang, infAmmo: xs.infAmmo, noRecoil: xs.noRecoil,
          godmode: xs.godmode, noclip: xs.noclip, antiKick: xs.antiKick,
          smoothFire: xs.smoothFire, infNade: xs.infNade, infNadeMax: xs.infNadeMax,
          silentNade: SN.on, silentNadeSide: SN.side, silentNadeMode: SN.mode,
          silentNadeTarget: SN.targetName, silentNadeBypass: xs.silentNadeBypass,
          silentNadeHoming: SN.homing, silentNadeLOS: SN.requireLOS,
          esp: E.on, espName: xs.espName,
          perf: PERF.on, perfLevel: PERF.level
        };
        localStorage.setItem(SETTINGS_KEY, JSON.stringify(data));
      } catch (e) {}
    }

    function scheduleSave() {
      clearTimeout(_saveTimer);
      _saveTimer = setTimeout(saveSettings, 400);
    }

    function restoreSettings() {
      var d;
      try { d = JSON.parse(localStorage.getItem(SETTINGS_KEY) || 'null'); } catch (e) { d = null; }
      if (!d || d.version !== 4) return;
      try {
        if (d.aim != null) d.aim ? PB_API.on() : PB_API.off();
        if (d.povCircleR > 0) PB_API.povCircle(d.povCircleR);
        if (d.hitbox) PB_API.hitbox(d.hitbox);
        if (d.aimbot != null) PB_API.aimbot(d.aimbot);
        if (d.aimbotGain > 0) PB_API.aimbotGain(d.aimbotGain);
        if (d.aimbotHoldMs >= 50) PB_API.aimbotHold(d.aimbotHoldMs);
        if (d.bulletSpeed > 0) PB_API.bulletSpeed(d.bulletSpeed);
        if (d.leadFactor >= 0) PB_API.leadFactor(d.leadFactor);
        if (d.lockMode) PB_API.lockMode(d.lockMode);
        if (d.autoFire != null) PB_API.autoFire(d.autoFire);
        if (d.sens > 0) PB_API.sens(d.sens);
        if (d.fov > 0) PB_API.fov(d.fov);
        if (d.invert != null) PB_API.invert(d.invert);
        if (d.cone > 0) P.cone = d.cone;
        if (d.reach > 0) P.reach = d.reach;
        if (d.gain > 0) P.gain = d.gain;
        if (d.mode) P.mode = d.mode;
        if (d.bias >= 0) P.bias = d.bias;

        if (d.flyMode) PBX_API.flyMode(d.flyMode);
        if (d.flyBypass != null) PBX_API.flyBypass(d.flyBypass);
        if (d.noFall != null) PBX_API.noFall(d.noFall);

        if (d.pred != null) PBX_API.pred(!!d.pred, d.predMs);
        if (d.rapid != null) PBX_API.rapid(d.rapid);
        if (d.rapidAntiSpam != null) PBX_API.rapidAntiSpam(d.rapidAntiSpam);
        if (d.instScope != null) PBX_API.instScope(d.instScope);
        if (d.trig != null) PBX_API.trig(d.trig);
        if (d.silent != null) PBX_API.silent(d.silent);
        if (d.silentAutoShoot != null) PBX_API.silentAutoShoot(d.silentAutoShoot);
        if (d.silentTapShot != null) PBX_API.silentTapShot(d.silentTapShot);
        if (d.silentTarget) PBX_API.silentTarget(d.silentTarget);
        if (d.silentFov > 0) PBX_API.silentFov(d.silentFov);
        if (d.silentMinDist >= 0) PBX_API.silentMinDist(d.silentMinDist);
        if (d.respawn != null) PBX_API.respawn(d.respawn);
        if (d.radar != null) PBX_API.radar(d.radar);
        if (d.hpo != null) PBX_API.hpo(d.hpo);
        if (d.fovc != null) PBX_API.fovc(d.fovc);
        if (d.tracer != null) PBX_API.tracer(d.tracer);
        if (d.wallbang != null) PBX_API.wallbang(d.wallbang);
        if (d.infAmmo != null) PBX_API.infAmmo(d.infAmmo);
        if (d.noRecoil != null) PBX_API.noRecoil(d.noRecoil);
        if (d.godmode != null) PBX_API.godmode(d.godmode);
        if (d.noclip != null) PBX_API.noclip(d.noclip);
        if (d.antiKick != null) PBX_API.antiKick(d.antiKick);
        if (d.smoothFire != null) PBX_API.smoothFire(d.smoothFire);
        if (d.infNade != null) PBX_API.infNade(d.infNade);
        if (d.infNadeMax > 0) PBX_API.infNadeMax(d.infNadeMax);

        if (d.silentNade != null) PBX_API.silentNade(d.silentNade);
        if (d.silentNadeSide) PBX_API.silentNadeSide(d.silentNadeSide);
        if (d.silentNadeMode) PBX_API.silentNadeMode(d.silentNadeMode);
        if (d.silentNadeTarget != null) PBX_API.silentNadeTarget(d.silentNadeTarget);
        if (d.silentNadeBypass != null) PBX_API.silentNadeBypass(d.silentNadeBypass);
        if (d.silentNadeHoming != null) PBX_API.silentNadeHoming(d.silentNadeHoming);
        if (d.silentNadeLOS != null) PBX_API.silentNadeLOS(d.silentNadeLOS);

        if (d.esp != null) d.esp ? VIS_API.on() : VIS_API.off();
        if (d.espName != null) VIS_API.name(d.espName);

        if (d.perf != null) PBX_API.perf(d.perf);
        if (d.perfLevel >= 1 && d.perfLevel <= 3) PBX_API.perfLevel(d.perfLevel);

        if (d.flyOn != null) PBX_API.fly(d.flyOn);
      } catch (e) { log('restoreSettings err', e); }
    }

    restoreSettings();

    addEventListener('pagehide', saveSettings);
    addEventListener('beforeunload', saveSettings);
    document.addEventListener('visibilitychange', function () { if (document.hidden) saveSettings(); });
    setInterval(saveSettings, 5000);

    /* ============================================================================
       3. UI SYSTEM
       ============================================================================ */
    (function pbUI() {
      if (W.__pbUI) return;
      W.__pbUI = 1;

      if (!document.querySelector('link[data-fa]')) {
        var fa = document.createElement('link');
        fa.rel = 'stylesheet';
        fa.setAttribute('data-fa', '1');
        fa.href = 'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css';
        (document.head || document.documentElement).appendChild(fa);
      }

      var css = [
        '.fk{position:fixed;top:12px;right:14px;z-index:2147483600;font:11px/1.35 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:#e2e8f0;',
        '  background:rgba(9,14,23,0.90);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);border:1px solid rgba(6,182,212,0.38);border-radius:12px;',
        '  box-shadow:0 12px 36px rgba(0,0,0,0.75),0 0 18px rgba(6,182,212,0.20),inset 0 1px 0 rgba(255,255,255,0.06);pointer-events:auto;user-select:none;touch-action:none;overflow:hidden}',
        '.fk:hover{border-color:rgba(34,211,238,0.6);box-shadow:0 16px 42px rgba(0,0,0,0.85),0 0 24px rgba(6,182,212,0.3)}',
        '.fk.expanded{display:flex;flex-direction:row}',
        '.fk.expanded .fk-rail{display:flex;flex-direction:column;background:rgba(5,9,16,0.82);border-right:1px solid rgba(6,182,212,0.2);width:44px;padding:6px 0;gap:3px;flex:0 0 44px;overflow-y:auto;max-height:86vh}',
        '.fk-rail::-webkit-scrollbar{width:2px}',
        '.fk-rail::-webkit-scrollbar-thumb{background:rgba(6,182,212,0.35);border-radius:2px}',
        '.fk.expanded .fk-body-col{width:262px;display:flex;flex-direction:column;min-width:0}',
        '.fk.expanded .fk-tabbar{display:none}',
        '.fk.collapsed{width:auto;border-radius:10px}',
        '.fk.collapsed .fk-rail,.fk.collapsed .fk-body-col{display:none}',
        '.fk.collapsed .fk-tabbar{display:flex;align-items:center;gap:8px;padding:6px 11px;cursor:grab;background:rgba(9,14,23,0.94)}',
        '.fk.collapsed .fk-tabbar:active{cursor:grabbing}',
        '.fk.collapsed .fk-tb-title{font:800 11px/1 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:#67e8f9;text-shadow:0 0 8px rgba(103,232,249,0.5);letter-spacing:.6px;white-space:nowrap}',
        '.fk.collapsed .fk-tb-title .dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:#10b981;box-shadow:0 0 8px #10b981;margin-right:6px;vertical-align:middle}',
        '.fk-tb-open{width:22px;height:22px;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:12px;color:#fff;cursor:pointer;background:linear-gradient(135deg,#0891b2,#10b981);box-shadow:0 0 8px rgba(6,182,212,0.5);font-weight:900;flex:0 0 22px}',
        '.fk-tb-open:hover{transform:scale(1.08)}',
        '.fk-rail-btn{width:36px;height:34px;margin:0 auto;border-radius:7px;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:2px;color:#94a3b8;cursor:pointer;transition:all .15s;flex:0 0 34px}',
        '.fk-rail-btn i{font-size:11px}',
        '.fk-rail-btn span{font-size:6.5px;font-weight:800;letter-spacing:.3px}',
        '.fk-rail-btn:hover{background:rgba(6,182,212,0.18);color:#67e8f9}',
        '.fk-rail-btn.on{background:linear-gradient(135deg,#0891b2 0%,#10b981 100%);color:#fff;box-shadow:0 0 12px rgba(6,182,212,0.55)}',
        '.fk-h{display:flex;align-items:center;gap:6px;padding:7px 10px;border-bottom:1px solid rgba(6,182,212,0.2);background:rgba(12,19,31,0.9);font-weight:700;cursor:grab}',
        '.fk-h:active{cursor:grabbing}',
        '.fk-h .dot{width:7px;height:7px;border-radius:50%;background:#10b981;box-shadow:0 0 8px #10b981;flex:0 0 7px}',
        '.fk-h .title{font-size:11.5px;font-weight:800;color:#67e8f9;text-shadow:0 0 10px rgba(103,232,249,0.45);letter-spacing:.5px}',
        '.fk-h .v{font-weight:600;font-size:9px;margin-left:auto;color:#38bdf8;font-family:monospace}',
        '.fk-toggle{cursor:pointer;margin-left:4px;color:#fff;border-radius:5px;width:20px;height:20px;display:flex;align-items:center;justify-content:center;flex:0 0 20px;font-size:10px;background:rgba(6,182,212,0.25);border:1px solid rgba(6,182,212,0.4)}',
        '.fk-toggle:hover{background:#0891b2}',
        '.fk-body{padding:7px 10px 10px;max-height:56vh;overflow-y:auto}',
        '.fk-body::-webkit-scrollbar{width:3px}',
        '.fk-body::-webkit-scrollbar-thumb{background:rgba(6,182,212,0.4);border-radius:2px}',
        '.fk-page{display:none}.fk-page.on{display:block}',
        '.fk-sec{margin:8px 0 4px;font-size:9px;letter-spacing:1px;color:#38bdf8;text-transform:uppercase;font-weight:800;display:flex;align-items:center;gap:5px}',
        '.fk-sec:first-child{margin-top:0}.fk-sec i{color:#10b981}',
        '.fk-row{display:flex;align-items:center;justify-content:space-between;gap:6px;padding:3.5px 0;border-bottom:1px solid rgba(255,255,255,0.04)}',
        '.fk-row label{flex:1;color:#f1f5f9;font-size:11px;font-weight:500}',
        '.fk-row small{display:block;color:#94a3b8;font-size:8.5px;margin-top:1px}',
        '.risk-badge{display:inline-block;padding:0 4px;margin-left:4px;border-radius:3px;font-size:7px;background:linear-gradient(135deg,#f59e0b,#d97706);color:#fff;font-weight:900}',
        '.new-badge{display:inline-block;padding:0 4px;margin-left:4px;border-radius:3px;font-size:7px;background:linear-gradient(135deg,#10b981,#059669);color:#fff;font-weight:900}',
        '.fk-sw{position:relative;width:30px;height:16px;flex:0 0 30px;border-radius:9px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.1);transition:all .15s;cursor:pointer}',
        '.fk-sw::after{content:"";position:absolute;top:1px;left:1px;width:12px;height:12px;border-radius:50%;background:#94a3b8;transition:transform .15s,background .15s}',
        '.fk-sw.on{background:linear-gradient(135deg,#0891b2,#10b981);border-color:rgba(34,211,238,0.65);box-shadow:0 0 10px rgba(6,182,212,0.5)}',
        '.fk-sw.on::after{transform:translateX(14px);background:#fff}',
        '.fk-slider{display:flex;align-items:center;gap:6px;padding:3px 0}',
        '.fk-slider label{flex:0 0 76px;font-size:9.5px;color:#cbd5e1}',
        '.fk-slider input[type=range]{flex:1;height:3px;-webkit-appearance:none;background:rgba(255,255,255,0.16);border-radius:2px;outline:none}',
        '.fk-slider input[type=range]::-webkit-slider-thumb{-webkit-appearance:none;width:12px;height:12px;border-radius:50%;background:#22d3ee;box-shadow:0 0 8px #06b6d4;cursor:pointer}',
        '.fk-slider .n{flex:0 0 40px;text-align:right;font-size:9px;color:#67e8f9;font-weight:700}',
        '.fk-select{width:100%;box-sizing:border-box;padding:4px 7px;border:1px solid rgba(6,182,212,0.35);border-radius:6px;font:11px sans-serif;outline:none;background:rgba(15,23,42,0.9);color:#f1f5f9;cursor:pointer;margin-top:2px}',
        '.fk-select:focus{border-color:#22d3ee}',
        '.fk-btns{display:flex;gap:5px;margin-top:6px}',
        '.fk-btn{flex:1;padding:5px 0;text-align:center;border-radius:6px;background:rgba(15,23,42,0.85);border:1px solid rgba(6,182,212,0.35);color:#e2e8f0;cursor:pointer;font:700 9.5px sans-serif;transition:all .15s}',
        '.fk-btn:hover{background:rgba(6,182,212,0.25);border-color:#22d3ee;color:#fff}',
        '.fk-btn:active{transform:scale(0.97)}',
        '.fk-btn.save{background:linear-gradient(135deg,#0891b2,#10b981);border-color:transparent;color:#fff}',
        '.fk-btn.save:hover{filter:brightness(1.15)}',
        '.fk-tabbar{display:none}',
        '.fk-toast{position:fixed;left:50%;bottom:20px;transform:translateX(-50%);background:rgba(9,14,23,0.95);border:1px solid rgba(34,211,238,0.5);color:#67e8f9;padding:7px 14px;border-radius:8px;font:700 11px sans-serif;z-index:2147483601;box-shadow:0 6px 20px rgba(0,0,0,0.7);pointer-events:none;opacity:0;transition:opacity .2s}',
        '.fk-toast.show{opacity:1}'
      ].join('');

      var styleEl = document.createElement('style');
      styleEl.setAttribute('data-pb', '1');
      styleEl.textContent = css;
      (document.head || document.documentElement).appendChild(styleEl);

      function mk(tag, cls, html) {
        var el = document.createElement(tag);
        if (cls) el.className = cls;
        if (html != null) el.innerHTML = html;
        return el;
      }

      function toast(msg) {
        var t = document.querySelector('.fk-toast');
        if (!t) {
          t = mk('div', 'fk-toast');
          document.body.appendChild(t);
        }
        t.textContent = msg;
        t.classList.add('show');
        clearTimeout(t.__to);
        t.__to = setTimeout(function () { t.classList.remove('show'); }, 1400);
      }

      var TABS = [
        { id: 'aim', icon: 'fa-crosshairs', label: 'AIM' },
        { id: 'visual', icon: 'fa-eye', label: 'VIS' },
        { id: 'weapon', icon: 'fa-gun', label: 'WPN' },
        { id: 'silent', icon: 'fa-bolt', label: 'SLNT' },
        { id: 'nade', icon: 'fa-bomb', label: 'NADE' },
        { id: 'misc', icon: 'fa-cog', label: 'MISC' }
      ];

      var root = mk('div', 'fk expanded');
      root.id = 'vanguard-panel';

      var rail = mk('div', 'fk-rail');
      TABS.forEach(function (t, i) {
        var b = mk('div', 'fk-rail-btn' + (i === 0 ? ' on' : ''),
          '<i class="fa-solid ' + t.icon + '"></i><span>' + t.label + '</span>');
        b.dataset.tab = t.id;
        b.addEventListener('click', function () {
          [].forEach.call(rail.children, function (c) { c.classList.remove('on'); });
          b.classList.add('on');
          [].forEach.call(bodyCol.querySelectorAll('.fk-page'), function (pg) {
            pg.classList.toggle('on', pg.dataset.page === t.id);
          });
        });
        rail.appendChild(b);
      });

      var bodyCol = mk('div', 'fk-body-col');
      var header = mk('div', 'fk-h');
      header.innerHTML = '<span class="dot"></span><span class="title">VANGUARD ELITE</span><span class="v">v' + V + '</span>';
      var collapseBtn = mk('div', 'fk-toggle', '<i class="fa-solid fa-chevron-up"></i>');
      header.appendChild(collapseBtn);
      bodyCol.appendChild(header);

      var body = mk('div', 'fk-body');
      bodyCol.appendChild(body);

      var pages = {};
      TABS.forEach(function (t) {
        var pg = mk('div', 'fk-page' + (t.id === 'aim' ? ' on' : ''));
        pg.dataset.page = t.id;
        body.appendChild(pg);
        pages[t.id] = pg;
      });

      root.appendChild(rail);
      root.appendChild(bodyCol);

      var tabbar = mk('div', 'fk-tabbar',
        '<span class="fk-tb-title"><span class="dot"></span>VANGUARD ELITE</span>' +
        '<span class="fk-tb-open"><i class="fa-solid fa-chevron-down"></i></span>');
      root.appendChild(tabbar);

      document.body.appendChild(root);

      collapseBtn.addEventListener('click', function (e) {
        e.stopPropagation();
        root.classList.remove('expanded');
        root.classList.add('collapsed');
      });
      tabbar.querySelector('.fk-tb-open').addEventListener('click', function (e) {
        e.stopPropagation();
        root.classList.remove('collapsed');
        root.classList.add('expanded');
      });

      (function makeDraggable(handle) {
        var sx = 0, sy = 0, ox = 0, oy = 0, dragging = false;
        handle.addEventListener('pointerdown', function (e) {
          if (e.target.closest('.fk-toggle')) return;
          dragging = true;
          sx = e.clientX; sy = e.clientY;
          var r = root.getBoundingClientRect();
          ox = r.left; oy = r.top;
          handle.setPointerCapture(e.pointerId);
        });
        handle.addEventListener('pointermove', function (e) {
          if (!dragging) return;
          var nx = ox + (e.clientX - sx);
          var ny = oy + (e.clientY - sy);
          nx = Math.max(0, Math.min(innerWidth - root.offsetWidth, nx));
          ny = Math.max(0, Math.min(innerHeight - root.offsetHeight, ny));
          root.style.left = nx + 'px';
          root.style.top = ny + 'px';
          root.style.right = 'auto';
        });
        handle.addEventListener('pointerup', function () { dragging = false; });
      })(header);
      (function makeDraggableCollapsed(handle) {
        var sx = 0, sy = 0, ox = 0, oy = 0, dragging = false;
        handle.addEventListener('pointerdown', function (e) {
          if (e.target.closest('.fk-tb-open')) return;
          dragging = true;
          sx = e.clientX; sy = e.clientY;
          var r = root.getBoundingClientRect();
          ox = r.left; oy = r.top;
          handle.setPointerCapture(e.pointerId);
        });
        handle.addEventListener('pointermove', function (e) {
          if (!dragging) return;
          var nx = ox + (e.clientX - sx);
          var ny = oy + (e.clientY - sy);
          nx = Math.max(0, Math.min(innerWidth - root.offsetWidth, nx));
          ny = Math.max(0, Math.min(innerHeight - root.offsetHeight, ny));
          root.style.left = nx + 'px';
          root.style.top = ny + 'px';
          root.style.right = 'auto';
        });
        handle.addEventListener('pointerup', function () { dragging = false; });
      })(tabbar);

      function sec(title, icon) {
        return mk('div', 'fk-sec', '<i class="fa-solid ' + icon + '"></i>' + title);
      }
      function row(label, sub, badge, badgeCls) {
        var r = mk('div', 'fk-row');
        var l = mk('label', null, label + (badge ? '<span class="' + (badgeCls || 'new-badge') + '">' + badge + '</span>' : '') + (sub ? '<small>' + sub + '</small>' : ''));
        r.appendChild(l);
        return r;
      }
      function sw(getter, setter) {
        var el = mk('div', 'fk-sw' + (getter() ? ' on' : ''));
        el.addEventListener('click', function () {
          var v = !getter();
          setter(v);
          el.classList.toggle('on', v);
          scheduleSave();
        });
        return el;
      }
      function slider(label, min, max, step, getter, setter, fmt) {
        var wrap = mk('div', 'fk-slider');
        var l = mk('label', null, label);
        var inp = document.createElement('input');
        inp.type = 'range';
        inp.min = min; inp.max = max; inp.step = step;
        inp.value = getter();
        var n = mk('span', 'n', fmt ? fmt(getter()) : getter());
        inp.addEventListener('input', function () {
          var v = parseFloat(inp.value);
          setter(v);
          n.textContent = fmt ? fmt(v) : v;
          scheduleSave();
        });
        wrap.appendChild(l); wrap.appendChild(inp); wrap.appendChild(n);
        return wrap;
      }
      function select(label, opts, getter, setter) {
        var wrap = mk('div');
        wrap.appendChild(mk('label', null, '<span style="font-size:9.5px;color:#cbd5e1">' + label + '</span>'));
        var sel = document.createElement('select');
        sel.className = 'fk-select';
        opts.forEach(function (o) {
          var op = document.createElement('option');
          op.value = o.v; op.textContent = o.t;
          if (getter() === o.v) op.selected = true;
          sel.appendChild(op);
        });
        sel.addEventListener('change', function () { setter(sel.value); scheduleSave(); });
        wrap.appendChild(sel);
        return wrap;
      }
      function btn(label, fn, cls) {
        var b = mk('div', 'fk-btn' + (cls ? ' ' + cls : ''), label);
        b.addEventListener('click', function () { fn(); scheduleSave(); });
        return b;
      }

      (function () {
        var pg = pages.aim;
        pg.appendChild(sec('Aim Assist', 'fa-crosshairs'));
        var r1 = row('Aim Assist', 'Aktifkan lock on target');
        r1.appendChild(sw(function () { return aimOn; }, function (v) { v ? PB_API.on() : PB_API.off(); }));
        pg.appendChild(r1);

        var r2 = row('Aimbot', 'Auto-lock + auto fire saat tembak');
        r2.appendChild(sw(function () { return P.aimbotOn; }, function (v) { PB_API.aimbot(v); }));
        pg.appendChild(r2);

        var r3 = row('Auto Fire', 'Tembak otomatis tanpa tap');
        r3.appendChild(sw(function () { return P.autoFire; }, function (v) { PB_API.autoFire(v); }));
        pg.appendChild(r3);

        pg.appendChild(sec('Target', 'fa-bullseye'));
        pg.appendChild(select('Hitbox',
          [{ v: 'head', t: 'Head' }, { v: 'body', t: 'Body' }, { v: 'nearest', t: 'Nearest' }],
          function () { return P.hitbox; },
          function (v) { PB_API.hitbox(v); }));

        pg.appendChild(select('Lock Mode',
          [{ v: 'pov', t: 'POV Circle' }, { v: 'legacy', t: 'Legacy' }],
          function () { return P.lockMode; },
          function (v) { PB_API.lockMode(v); }));

        pg.appendChild(slider('POV Circle', 40, 600, 10,
          function () { return P.povCircleR; },
          function (v) { PB_API.povCircle(v); },
          function (v) { return v + 'px'; }));

        pg.appendChild(slider('Aimbot Gain', 0.2, 2, 0.05,
          function () { return P.aimbotGain; },
          function (v) { PB_API.aimbotGain(v); },
          function (v) { return v.toFixed(2); }));

        pg.appendChild(slider('Aimbot Hold', 50, 1000, 25,
          function () { return P.aimbotHoldMs; },
          function (v) { PB_API.aimbotHold(v); },
          function (v) { return v + 'ms'; }));

        pg.appendChild(slider('Bullet Speed', 50, 1500, 25,
          function () { return P.bulletSpeed; },
          function (v) { PB_API.bulletSpeed(v); },
          function (v) { return v; }));

        pg.appendChild(slider('Lead Factor', 0, 3, 0.1,
          function () { return P.leadFactor; },
          function (v) { PB_API.leadFactor(v); },
          function (v) { return v.toFixed(1); }));

        pg.appendChild(sec('Sensitivitas', 'fa-sliders'));
        pg.appendChild(slider('Sens', 0.05, 3, 0.05,
          function () { return O.sens; },
          function (v) { PB_API.sens(v); },
          function (v) { return v.toFixed(2); }));
        pg.appendChild(slider('FOV', 40, 120, 1,
          function () { return O.fov; },
          function (v) { PB_API.fov(v); },
          function (v) { return v + '°'; }));
        var rInv = row('Invert Y', 'Balik pitch');
        rInv.appendChild(sw(function () { return O.invert; }, function (v) { PB_API.invert(v); }));
        pg.appendChild(rInv);
      })();

      (function () {
        var pg = pages.visual;
        pg.appendChild(sec('ESP', 'fa-eye'));
        var r1 = row('ESP Box', 'Kotak + HP bar');
        r1.appendChild(sw(function () { return E.on; }, function (v) { v ? VIS_API.on() : VIS_API.off(); }));
        pg.appendChild(r1);

        var r2 = row('ESP Name', 'Tampilkan nama');
        r2.appendChild(sw(function () { return E.nameOn; }, function (v) { VIS_API.name(v); }));
        pg.appendChild(r2);

        var r3 = row('HP Overlay', 'Angka HP');
        r3.appendChild(sw(function () { return HPO.on; }, function (v) { PBX_API.hpo(v); }));
        pg.appendChild(r3);

        var r4 = row('Bone ESP', 'Skeleton');
        r4.appendChild(sw(function () { return BE.on; }, function (v) { VIS_API.bone(v); }));
        pg.appendChild(r4);

        var r5 = row('Tracer', 'Garis ke target');
        r5.appendChild(sw(function () { return TR.on; }, function (v) { PBX_API.tracer(v); }));
        pg.appendChild(r5);

        var r6 = row('Radar', 'Mini map musuh');
        r6.appendChild(sw(function () { return RD.on; }, function (v) { PBX_API.radar(v); }));
        pg.appendChild(r6);

        var r7 = row('FOV Circle', 'Ring POV');
        r7.appendChild(sw(function () { return FC.on; }, function (v) { PBX_API.fovc(v); }));
        pg.appendChild(r7);

        pg.appendChild(sec('Damage', 'fa-explosion'));
        pg.appendChild(slider('Dmg Multi', 1, 3, 0.1,
          function () { return DM.mult; },
          function (v) { VIS_API.dmg(v); },
          function (v) { return v.toFixed(1) + 'x'; }));
      })();

      (function () {
        var pg = pages.weapon;
        pg.appendChild(sec('Fire', 'fa-gun'));
        var r1 = row('Wallbang', 'Tembus dinding');
        r1.appendChild(sw(function () { return FL.wallbang; }, function (v) { PBX_API.wallbang(v); }));
        pg.appendChild(r1);

        var r2 = row('Infinite Ammo', 'Ammo tanpa batas');
        r2.appendChild(sw(function () { return FL.infAmmo; }, function (v) { PBX_API.infAmmo(v); }));
        pg.appendChild(r2);

        var r3 = row('No Recoil', 'Hilangkan recoil');
        r3.appendChild(sw(function () { return FL.noRecoil; }, function (v) { PBX_API.noRecoil(v); }));
        pg.appendChild(r3);

        var r4 = row('Rapid Fire', 'Tembak cepat');
        r4.appendChild(sw(function () { return RF.on; }, function (v) { PBX_API.rapid(v); }));
        pg.appendChild(r4);

        var r5 = row('Rapid Anti-Spam', 'Jeda minimal antar tembakan');
        r5.appendChild(sw(function () { return RF.antiSpam; }, function (v) { PBX_API.rapidAntiSpam(v); }));
        pg.appendChild(r5);

        var r6 = row('Instant Scope', 'Scope instan');
        r6.appendChild(sw(function () { return IS.on; }, function (v) { PBX_API.instScope(v); }));
        pg.appendChild(r6);

        var r7 = row('Trigger Bot', 'Auto tembak saat crosshair di musuh');
        r7.appendChild(sw(function () { return TB.on; }, function (v) { PBX_API.trig(v); }));
        pg.appendChild(r7);

        var r8 = row('Smooth Fire', 'Tembakan halus');
        r8.appendChild(sw(function () { return SF.on; }, function (v) { PBX_API.smoothFire(v); }));
        pg.appendChild(r8);
      })();

      (function () {
        var pg = pages.silent;
        pg.appendChild(sec('Silent Aim', 'fa-bolt'));
        var r1 = row('Silent Aim', 'HitTest spoof');
        r1.appendChild(sw(function () { return SA.on; }, function (v) { PBX_API.silent(v); }));
        pg.appendChild(r1);

        var r2 = row('Auto Shoot', 'Tembak otomatis saat target valid');
        r2.appendChild(sw(function () { return SA.autoShoot; }, function (v) { PBX_API.silentAutoShoot(v); }));
        pg.appendChild(r2);

        var r3 = row('Tap Shot', 'Tap cepat');
        r3.appendChild(sw(function () { return SA.tapShot; }, function (v) { PBX_API.silentTapShot(v); }));
        pg.appendChild(r3);

        pg.appendChild(select('Silent Target',
          [{ v: 'head', t: 'Head' }, { v: 'body', t: 'Body' }],
          function () { return SA.target; },
          function (v) { PBX_API.silentTarget(v); }));

        pg.appendChild(slider('Silent FOV', 5, 180, 5,
          function () { return SA.fovDeg; },
          function (v) { PBX_API.silentFov(v); },
          function (v) { return v + '°'; }));

        pg.appendChild(slider('Silent Min Dist', 0, 10, 0.5,
          function () { return SA.minDist; },
          function (v) { PBX_API.silentMinDist(v); },
          function (v) { return v.toFixed(1) + 'm'; }));

        pg.appendChild(sec('Prediction', 'fa-location-arrow'));
        var r4 = row('Prediction', 'Prediksi gerak target');
        r4.appendChild(sw(function () { return PR.on; }, function (v) { PBX_API.pred(v); }));
        pg.appendChild(r4);

        pg.appendChild(slider('Pred MS', 0, 500, 10,
          function () { return PR.ms; },
          function (v) { PBX_API.pred(PR.on, v); },
          function (v) { return v + 'ms'; }));
      })();

      (function () {
        var pg = pages.nade;
        pg.appendChild(sec('Grenade', 'fa-bomb'));
        var r1 = row('Infinite Nade', 'Nade tanpa batas');
        r1.appendChild(sw(function () { return FL.infNade; }, function (v) { PBX_API.infNade(v); }));
        pg.appendChild(r1);

        pg.appendChild(slider('Max Nade', 1, 200, 1,
          function () { return FL.infNadeMax; },
          function (v) { PBX_API.infNadeMax(v); },
          function (v) { return v; }));

        pg.appendChild(sec('Silent Nade', 'fa-crosshairs'));
        var r2 = row('Silent Nade', 'Nade homing ke target');
        r2.appendChild(sw(function () { return SN.on; }, function (v) { PBX_API.silentNade(v); }));
        pg.appendChild(r2);

        var r3 = row('Homing', 'Nade mengikuti target');
        r3.appendChild(sw(function () { return SN.homing; }, function (v) { PBX_API.silentNadeHoming(v); }));
        pg.appendChild(r3);

        var r4 = row('Require LOS', 'Butuh line of sight');
        r4.appendChild(sw(function () { return SN.requireLOS; }, function (v) { PBX_API.silentNadeLOS(v); }));
        pg.appendChild(r4);

        pg.appendChild(select('Side',
          [{ v: 'enemy', t: 'Enemy' }, { v: 'ally', t: 'Ally' }],
          function () { return SN.side; },
          function (v) { PBX_API.silentNadeSide(v); }));

        pg.appendChild(select('Mode',
          [{ v: 'aim', t: 'Aim (crosshair)' }, { v: 'random', t: 'Random' }, { v: 'name_order', t: 'Name Order' }],
          function () { return SN.mode; },
          function (v) { PBX_API.silentNadeMode(v); }));
      })();

      (function () {
        var pg = pages.misc;
        pg.appendChild(sec('Survival', 'fa-shield'));
        var r1 = row('Godmode', 'Kebal damage');
        r1.appendChild(sw(function () { return FL.godmode; }, function (v) { PBX_API.godmode(v); }));
        pg.appendChild(r1);

        var r2 = row('Noclip', 'Tembus dinding');
        r2.appendChild(sw(function () { return FL.noclip; }, function (v) { PBX_API.noclip(v); }));
        pg.appendChild(r2);

        var r3 = row('No Fall Damage', 'Tanpa damage jatuh');
        r3.appendChild(sw(function () { return FL.noFall; }, function (v) { PBX_API.noFall(v); }));
        pg.appendChild(r3);

        var r4 = row('Anti Kick', 'Cegah kick dari server');
        r4.appendChild(sw(function () { return FL.antiKick; }, function (v) { PBX_API.antiKick(v); }));
        pg.appendChild(r4);

        var r5 = row('Auto Respawn', 'Respawn otomatis');
        r5.appendChild(sw(function () { return IR.on; }, function (v) { PBX_API.respawn(v); }));
        pg.appendChild(r5);

        pg.appendChild(sec('Fly', 'fa-plane'));
        var r6 = row('Fly', 'Terbang');
        r6.appendChild(sw(function () { return FLY.on; }, function (v) { PBX_API.fly(v); }));
        pg.appendChild(r6);

        var r7 = row('Fly Bypass', 'Smooth movement');
        r7.appendChild(sw(function () { return FLYB.on; }, function (v) { PBX_API.flyBypass(v); }));
        pg.appendChild(r7);

        pg.appendChild(sec('Quick Change', 'fa-arrows-rotate'));
        var r8 = row('Quick Change', 'Fast swap');
        r8.appendChild(sw(function () { return QC.on; }, function (v) { v ? QC_API.on() : QC_API.off(); }));
        pg.appendChild(r8);

        var r9 = row('Fast Swap', 'Swap instan');
        r9.appendChild(sw(function () { return QC.fast; }, function (v) { QC_API.cfg({ fast: v ? 1 : 0 }); }));
        pg.appendChild(r9);

        pg.appendChild(sec('Performance', 'fa-gauge-high'));
        var rp1 = row('Performance Mode', 'Turunkan beban visual & render');
        rp1.appendChild(sw(function () { return PERF.on; }, function (v) { PBX_API.perf(v); }));
        pg.appendChild(rp1);

        pg.appendChild(slider('Perf Level', 1, 3, 1,
          function () { return PERF.level; },
          function (v) { PBX_API.perfLevel(v); },
          function (v) { return 'L' + v; }));

        var rp2 = row('Panic', 'Matikan semua & reload');
        var pb1 = btn('PANIC', function () { PBX_API.panic(); });
        pb1.style.background = 'linear-gradient(135deg,#dc2626,#b91c1c)';
        pb1.style.borderColor = 'transparent';
        rp2.appendChild(pb1);
        pg.appendChild(rp2);

        pg.appendChild(sec('Auth', 'fa-key'));
        var ra1 = row('Auth Status', 'Lihat status key');
        var raBtn = btn('STATUS', function () {
          var s = PBX_API.authSt();
          toast(s.status.toUpperCase() + (s.reason ? ' · ' + s.reason : '') + (s.hasToken ? ' · token' : ''));
        });
        ra1.appendChild(raBtn);
        pg.appendChild(ra1);

        var ra2 = row('Auth Reset', 'Ganti key / lepas device');
        var raBtn2 = btn('RESET KEY', function () {
          PBX_API.authReset();
          toast('Key direset, isi ulang');
        });
        raBtn2.style.background = 'linear-gradient(135deg,#f59e0b,#d97706)';
        raBtn2.style.borderColor = 'transparent';
        ra2.appendChild(raBtn2);
        pg.appendChild(ra2);

        pg.appendChild(sec('Lainnya', 'fa-wrench'));
        var r10 = row('Lob', 'Mode lempar');
        r10.appendChild(sw(function () { return SL.on; }, function (v) { PBX_API.lob(v); }));
        pg.appendChild(r10);

        var btns = mk('div', 'fk-btns');
        btns.appendChild(btn('Simpan', function () { saveSettings(); toast('Settings disimpan'); }, 'save'));
        btns.appendChild(btn('Reset', function () {
          try { localStorage.removeItem(SETTINGS_KEY); } catch (e) {}
          toast('Settings dihapus, reload halaman');
        }));
        pg.appendChild(btns);
      })();

      log(BRAND, V, 'UI ready');
    })();

    log(BRAND, V, 'up');
    requestAnimationFrame(mainLoop);
  }

  try {
    // HANYA JALANKAN CHEAT JIKA AUTH BERHASIL
    if (AUTH_STATE.status === 'ok') {
      bootCore();
    } else {
      console.log('[VANGUARD] Cheat diblokir. Menunggu key valid.');
    }
  } catch (e) { try { console.error('[VANGUARD] boot fail', e); } catch (_) {} }
})(typeof unsafeWindow !== 'undefined' ? unsafeWindow : window);
