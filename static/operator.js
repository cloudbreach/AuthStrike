(function () {
  const sidebar = document.getElementById('sidebar');
  const mobileMenu = document.getElementById('mobileMenu');
  if (mobileMenu && sidebar) {
    mobileMenu.addEventListener('click', () => sidebar.classList.toggle('open'));
  }

  async function copyText(text) {
    if (!text) throw new Error('Nothing to copy');
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return;
    }
    const area = document.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly', '');
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    area.setSelectionRange(0, area.value.length);
    const ok = document.execCommand('copy');
    area.remove();
    if (!ok) throw new Error('Copy command failed');
  }

  document.querySelectorAll('[data-copy]').forEach((button) => {
    button.addEventListener('click', async () => {
      const selector = button.getAttribute('data-copy');
      const source = document.querySelector(selector);
      if (!source) return;
      const old = button.textContent;
      try {
        await copyText(source.value || source.innerText || source.textContent || '');
        button.textContent = 'Copied';
      } catch (_) {
        button.textContent = 'Copy failed';
      }
      setTimeout(() => { button.textContent = old; }, 1400);
    });
  });

  // Operator alerts are enabled by default and persist across page navigation.
  // Browser-level Notification and audio have additional browser restrictions, so
  // an in-page alert is always used as the reliable fallback.
  const ALERTS_KEY = 'AuthStrike.alerts.enabled';
  const LAST_SEEN_KEY = 'AuthStrike.alerts.last_seen';
  const EVENT_KEYS_KEY = 'AuthStrike.alerts.seen_events';
  const DEFAULT_ENABLED = true;
  const alertButton = document.getElementById('alertSettings');
  const toastHost = document.getElementById('operatorAlertHost') || createToastHost();
  let alertsEnabled = getStoredBool(ALERTS_KEY, DEFAULT_ENABLED);
  let audioCtx = null;

  function getStoredBool(key, fallback) {
    try {
      const value = localStorage.getItem(key);
      return value === null ? fallback : value === 'true';
    } catch (_) {
      return fallback;
    }
  }

  function setStoredBool(key, value) {
    try { localStorage.setItem(key, String(value)); } catch (_) {}
  }

  function getSeenEvents() {
    try { return JSON.parse(localStorage.getItem(EVENT_KEYS_KEY) || '[]'); }
    catch (_) { return []; }
  }

  function rememberEvent(key) {
    try {
      const seen = getSeenEvents();
      seen.push(key);
      localStorage.setItem(EVENT_KEYS_KEY, JSON.stringify(seen.slice(-50)));
    } catch (_) {}
  }

  function createToastHost() {
    const host = document.createElement('div');
    host.id = 'operatorAlertHost';
    host.className = 'operator-alert-host';
    document.body.appendChild(host);
    return host;
  }

  function showToast(title, message) {
    const toast = document.createElement('div');
    toast.className = 'operator-alert-toast';
    toast.innerHTML = '<div class="operator-alert-title">' + escapeHtml(title) + '</div>' +
      '<div class="operator-alert-message">' + escapeHtml(message) + '</div>';
    toastHost.appendChild(toast);
    setTimeout(() => toast.classList.add('visible'), 20);
    setTimeout(() => {
      toast.classList.remove('visible');
      setTimeout(() => toast.remove(), 250);
    }, 8000);
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>'"]/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
  }

  function unlockAudio() {
    if (!alertsEnabled || audioCtx) return;
    try {
      const Ctx = window.AudioContext || window.webkitAudioContext;
      if (!Ctx) return;
      audioCtx = new Ctx();
      audioCtx.resume().catch(() => {});
    } catch (_) {}
  }

  // Any normal operator interaction can unlock audio for future capture alerts.
  window.addEventListener('pointerdown', unlockAudio, { once: true, passive: true });
  window.addEventListener('keydown', unlockAudio, { once: true, passive: true });

  function beep() {
    if (!alertsEnabled || !audioCtx) return;
    try {
      if (audioCtx.state === 'suspended') audioCtx.resume().catch(() => {});
      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      osc.type = 'sine';
      osc.frequency.value = 880;
      gain.gain.value = 0.09;
      osc.connect(gain);
      gain.connect(audioCtx.destination);
      osc.start();
      setTimeout(() => { try { osc.stop(); } catch (_) {} }, 180);
    } catch (_) {}
  }

  async function requestBrowserNotificationPermission() {
    if (!alertsEnabled || !('Notification' in window)) return;
    // Notification API is restricted to secure contexts (HTTPS/localhost).
    if (!window.isSecureContext) return;
    if (Notification.permission === 'default') {
      try { await Notification.requestPermission(); } catch (_) {}
    }
  }

  async function notifyCapture(event) {
    if (!alertsEnabled) return;
    const text = `Operation #${event.id} completed · ${event.username} · ${event.client_name}`;
    showToast('Token captured', text);
    beep();
    document.title = `✓ Token captured · Operation #${event.id}`;
    setTimeout(() => {
      if (document.title.startsWith('✓ Token captured')) document.title = 'AuthStrike';
    }, 10000);

    if ('Notification' in window && window.isSecureContext && Notification.permission === 'granted') {
      try {
        new Notification('AuthStrike · Token captured', { body: text, tag: `AuthStrike-${event.event_key}` });
      } catch (_) {}
    }
  }

  async function pollNotifications() {
    if (!alertsEnabled) return;
    let baseline = Number(localStorage.getItem(LAST_SEEN_KEY) || '0');
    if (!baseline) {
      baseline = Math.floor(Date.now() / 1000);
      try { localStorage.setItem(LAST_SEEN_KEY, String(baseline)); } catch (_) {}
    }
    try {
      const res = await fetch('/api/notifications?since=' + encodeURIComponent(baseline), {
        headers: {'Accept': 'application/json'},
        cache: 'no-store'
      });
      if (!res.ok) return;
      const data = await res.json();
      const events = Array.isArray(data.events) ? data.events : [];
      const seen = new Set(getSeenEvents());
      let maxEpoch = baseline;
      for (const event of events) {
        maxEpoch = Math.max(maxEpoch, Number(event.completed_at_epoch || 0));
        if (event.event_key && seen.has(event.event_key)) continue;
        rememberEvent(event.event_key);
        await notifyCapture(event);
      }
      try { localStorage.setItem(LAST_SEEN_KEY, String(maxEpoch)); } catch (_) {}
    } catch (_) {}
  }

  function updateAlertButton() {
    if (!alertButton) return;
    alertButton.textContent = alertsEnabled ? 'Alerts on' : 'Alerts off';
    alertButton.classList.toggle('button-success', alertsEnabled);
    alertButton.setAttribute('aria-pressed', String(alertsEnabled));
  }

  if (alertButton) {
    updateAlertButton();
    alertButton.addEventListener('click', async () => {
      alertsEnabled = !alertsEnabled;
      setStoredBool(ALERTS_KEY, alertsEnabled);
      if (alertsEnabled) {
        unlockAudio();
        await requestBrowserNotificationPermission();
      }
      updateAlertButton();
      if (alertsEnabled) showToast('Alerts enabled', 'In-app alerts are enabled for token captures.');
      else showToast('Alerts disabled', 'Token captures will still be recorded, but no operator alert will be shown.');
    });
  }

  // Request browser permission on a user interaction, while leaving in-app alerts
  // enabled by default. This is necessary because browsers block unsolicited prompts.
  document.addEventListener('click', () => {
    if (alertsEnabled) {
      unlockAudio();
      requestBrowserNotificationPermission();
    }
  }, { once: true });

  updateAlertButton();
  pollNotifications();
  setInterval(pollNotifications, 3000);
})();
