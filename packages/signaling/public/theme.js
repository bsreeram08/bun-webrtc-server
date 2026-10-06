'use strict';
// Cosmetic themes: preset palettes, a custom accent, and per-chat theme + wallpaper overrides.
// Preferences live in this browser only (localStorage, per account); they never reach the server.
(() => {
  const $ = id => document.getElementById(id);
  const PRESETS = {
    midnight: { name: 'Midnight', scheme: 'dark', bg: '#111820', surface: '#192733', 'surface-2': '#20303c', raised: '#263d4c', line: '#344755', 'line-strong': '#647987', text: '#eef4f9', muted: '#afbfcc', accent: '#a1efce', mine: '#244535', theirs: '#20303c', danger: '#e2606e', 'danger-bg': '#562d35', warn: '#f2c14e', 'warn-bg': '#3d321a', wallpaper: 'none' },
    fsociety: { name: 'fsociety', scheme: 'dark', mono: true, bg: '#040805', surface: '#09110b', 'surface-2': '#0e1a11', raised: '#142418', line: '#1c3322', 'line-strong': '#2f5a39', text: '#c9f7c8', muted: '#7cb487', accent: '#3dff73', mine: '#0f2b17', theirs: '#0c1810', danger: '#ff4d5e', 'danger-bg': '#3a1015', warn: '#e8d44d', 'warn-bg': '#2a260c', wallpaper: 'circuit' },
    light: { name: 'Daylight', scheme: 'light', bg: '#f4f6f8', surface: '#ffffff', 'surface-2': '#eaeff3', raised: '#dfe6ec', line: '#d3dce3', 'line-strong': '#a3b1bc', text: '#13202a', muted: '#52616c', accent: '#0a7a52', mine: '#d4f3e4', theirs: '#ffffff', danger: '#c2334a', 'danger-bg': '#fbe1e5', warn: '#7d5800', 'warn-bg': '#fff1c7', wallpaper: 'dots' },
    amoled: { name: 'AMOLED', scheme: 'dark', bg: '#000000', surface: '#0b0b0b', 'surface-2': '#141414', raised: '#1e1e1e', line: '#262626', 'line-strong': '#454545', text: '#f2f2f2', muted: '#a6a6a6', accent: '#8ab4ff', mine: '#15253f', theirs: '#161616', danger: '#ff6b78', 'danger-bg': '#3b141a', warn: '#ffd166', 'warn-bg': '#2e2510', wallpaper: 'none' },
    dusk: { name: 'Dusk', scheme: 'dark', bg: '#16111e', surface: '#1f1829', 'surface-2': '#292034', raised: '#342a42', line: '#3d3150', 'line-strong': '#6b5b82', text: '#f4eefb', muted: '#c4b7d8', accent: '#f6a8cb', mine: '#4a2944', theirs: '#292034', danger: '#ff6f86', 'danger-bg': '#4a1f2c', warn: '#f7c86b', 'warn-bg': '#3a2c18', wallpaper: 'gradient' },
    ocean: { name: 'Ocean', scheme: 'dark', bg: '#0a1520', surface: '#0f1f2e', 'surface-2': '#14283b', raised: '#1b344d', line: '#233f5a', 'line-strong': '#4b6a89', text: '#eaf3fb', muted: '#a8bfd3', accent: '#6fcbff', mine: '#153a59', theirs: '#14283b', danger: '#ff6b78', 'danger-bg': '#45202a', warn: '#f5c451', 'warn-bg': '#382d14', wallpaper: 'lines' },
  };
  const WALLPAPERS = { none: 'None', dots: 'Dots', grid: 'Grid', lines: 'Lines', gradient: 'Glow', circuit: 'Circuit' };
  const HEX = /^#[0-9a-f]{6}$/i, MAX_CHATS = 300;

  // ---------- Color math (WCAG relative luminance and contrast) ----------
  const rgb = hex => [1, 3, 5].map(index => parseInt(hex.slice(index, index + 2), 16));
  const hex = values => '#' + values.map(value => Math.round(Math.min(255, Math.max(0, value))).toString(16).padStart(2, '0')).join('');
  const luminance = color => { const [r, g, b] = rgb(color).map(value => { value /= 255; return value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4; }); return 0.2126 * r + 0.7152 * g + 0.0722 * b; };
  const contrast = (a, b) => { const [x, y] = [luminance(a), luminance(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };
  const mix = (a, b, amount) => { const [p, q] = [rgb(a), rgb(b)]; return hex(p.map((value, index) => value * amount + q[index] * (1 - amount))); };
  const ink = color => contrast(color, '#ffffff') >= contrast(color, '#0b0f12') ? '#ffffff' : '#0b0f12';

  /** Full token set for a preset, optionally re-tinted around a custom accent while keeping AA text contrast. */
  function tokens(presetName, accent) {
    const preset = PRESETS[presetName] || PRESETS.midnight, out = { ...preset };
    if (accent && HEX.test(accent)) {
      out.accent = accent;
      // Tint the outgoing bubble toward the accent, backing off until its text keeps 4.5:1 contrast.
      let amount = preset.scheme === 'light' ? 0.24 : 0.34, mine = mix(accent, preset.bg, amount);
      while (contrast(mine, preset.text) < 4.5 && amount > 0.04) { amount -= 0.03; mine = mix(accent, preset.bg, amount); }
      out.mine = mine;
    }
    out['accent-ink'] = ink(out.accent);
    out['ok-bg'] = mix(out.accent, out.bg, preset.scheme === 'light' ? 0.16 : 0.14);
    out['ok-line'] = mix(out.accent, out.bg, 0.35);
    out['mine-text'] = out.text; out['theirs-text'] = out.text;
    out.meta = mix(out.text, out.mine, 0.72);
    // Delivered ticks use the accent only where it stands out on the outgoing bubble.
    out['tick-read'] = contrast(out.accent, out.mine) >= 3 ? out.accent : out.text;
    out['danger-line'] = mix(out.danger, out.bg, 0.55);
    out['warn-line'] = mix(out.warn, out.bg, 0.45);
    out['danger-text'] = preset.scheme === 'light' ? out.danger : mix(out.danger, '#ffffff', 0.7);
    return out;
  }

  // ---------- Preferences ----------
  let account = 'guest', prefs = load(), currentChat = null;
  function clean(value) {
    const out = {};
    if (value && PRESETS[value.preset]) out.preset = value.preset;
    if (value && HEX.test(value.accent || '')) out.accent = value.accent.toLowerCase();
    if (value && WALLPAPERS[value.wallpaper]) out.wallpaper = value.wallpaper;
    return out;
  }
  function load() {
    let raw = {};
    try { raw = JSON.parse(localStorage.getItem(`theme-v1:${account}`) || '{}') || {}; } catch {}
    const chats = {};
    for (const [id, value] of Object.entries(raw.chats && typeof raw.chats === 'object' ? raw.chats : {}).slice(-MAX_CHATS)) if (/^[A-Za-z0-9_:-]{1,80}$/.test(id)) chats[id] = clean(value);
    return { app: clean(raw.app), chats };
  }
  function save() {
    const ids = Object.keys(prefs.chats);
    for (const id of ids.slice(0, Math.max(0, ids.length - MAX_CHATS))) delete prefs.chats[id];
    try { localStorage.setItem(`theme-v1:${account}`, JSON.stringify(prefs)); } catch {}
  }
  function resolved(chatId = currentChat) {
    const app = prefs.app, chat = chatId ? prefs.chats[chatId] || {} : {};
    const preset = chat.preset || app.preset || 'midnight';
    // A chat that picks its own preset starts from that preset's own accent unless it sets one too.
    const accent = chat.accent || (chat.preset ? null : app.accent) || null;
    const wallpaper = chat.wallpaper || app.wallpaper || PRESETS[preset].wallpaper;
    return { preset, accent, wallpaper };
  }
  function apply() {
    const { preset, accent, wallpaper } = resolved(), values = tokens(preset, accent), root = document.documentElement;
    for (const [key, value] of Object.entries(values)) if (typeof value === 'string' && key !== 'name' && key !== 'scheme' && key !== 'wallpaper') root.style.setProperty(`--${key}`, value);
    root.style.setProperty('color-scheme', values.scheme);
    root.style.setProperty('--chat-font', values.mono ? 'ui-monospace, "SF Mono", "Cascadia Mono", Menlo, monospace' : 'inherit');
    root.dataset.scheme = values.scheme;
    $('app').dataset.wallpaper = wallpaper; $('app').dataset.theme = preset;
    document.querySelector('meta[name="theme-color"]')?.setAttribute('content', values.bg);
  }

  // ---------- Picker ----------
  let scope = 'app';
  function swatch(name) {
    const button = document.createElement('button'), values = tokens(name);
    button.type = 'button'; button.className = 'swatch'; button.dataset.preset = name;
    button.setAttribute('role', 'radio'); button.setAttribute('aria-label', PRESETS[name].name);
    for (const key of ['bg', 'mine', 'theirs', 'accent', 'line']) button.style.setProperty(`--sw-${key}`, values[key]);
    const preview = document.createElement('span'); preview.className = 'swatch-preview'; preview.setAttribute('aria-hidden', 'true');
    preview.append(...['sw-theirs', 'sw-mine', 'sw-dot'].map(kind => { const part = document.createElement('i'); part.className = kind; return part; }));
    const label = document.createElement('span'); label.textContent = PRESETS[name].name;
    button.append(preview, label);
    button.onclick = () => choose({ preset: name, accent: undefined });
    return button;
  }
  function wallSwatch(name) {
    const button = document.createElement('button');
    button.type = 'button'; button.className = 'wall-swatch'; button.dataset.wallpaper = name;
    button.setAttribute('role', 'radio'); button.setAttribute('aria-label', WALLPAPERS[name]);
    const label = document.createElement('span'); label.textContent = WALLPAPERS[name]; button.append(label);
    button.onclick = () => choose({ wallpaper: name });
    return button;
  }
  function target() { return scope === 'chat' && currentChat ? (prefs.chats[currentChat] ||= {}) : prefs.app; }
  function choose(change) {
    const entry = target();
    for (const [key, value] of Object.entries(change)) { if (value === undefined) delete entry[key]; else entry[key] = value; }
    save(); apply(); paintPicker();
  }
  function paintPicker() {
    const entry = scope === 'chat' && currentChat ? prefs.chats[currentChat] || {} : prefs.app, effective = resolved();
    const presetChosen = scope === 'chat' ? entry.preset || 'inherit' : effective.preset;
    for (const button of $('theme-presets').children) button.setAttribute('aria-checked', String(button.dataset.preset === presetChosen));
    const wallChosen = scope === 'chat' ? entry.wallpaper || 'inherit' : prefs.app.wallpaper || 'inherit';
    for (const button of $('theme-walls').children) button.setAttribute('aria-checked', String(button.dataset.wallpaper === wallChosen));
    $('theme-accent').value = effective.accent || tokens(effective.preset).accent;
    $('theme-accent-reset').hidden = !entry.accent;
    $('theme-title').textContent = scope === 'chat' ? 'Chat theme' : 'App theme';
    $('theme-note').textContent = scope === 'chat' ? 'Only this conversation, on this device.' : 'Every conversation without its own theme, on this device.';
  }
  function inheritButton(kind) {
    const button = document.createElement('button');
    button.type = 'button'; button.className = kind === 'preset' ? 'swatch inherit' : 'wall-swatch inherit';
    button.dataset[kind === 'preset' ? 'preset' : 'wallpaper'] = 'inherit';
    button.setAttribute('role', 'radio');
    const label = document.createElement('span'); label.textContent = kind === 'preset' ? 'Same as app' : 'Theme default'; button.append(label);
    button.onclick = () => choose(kind === 'preset' ? { preset: undefined, accent: undefined } : { wallpaper: undefined });
    return button;
  }
  function open(nextScope) {
    scope = nextScope === 'chat' && currentChat ? 'chat' : 'app';
    $('theme-presets').replaceChildren(...(scope === 'chat' ? [inheritButton('preset')] : []), ...Object.keys(PRESETS).map(swatch));
    $('theme-walls').replaceChildren(inheritButton('wallpaper'), ...Object.keys(WALLPAPERS).map(wallSwatch));
    paintPicker();
    $('theme-dialog').hidden = false; $('theme-done').focus();
  }
  $('theme-accent').oninput = () => { if (HEX.test($('theme-accent').value)) choose({ accent: $('theme-accent').value.toLowerCase() }); };
  $('theme-accent-reset').onclick = () => choose({ accent: undefined });
  $('theme-done').onclick = () => { $('theme-dialog').hidden = true; };
  $('theme-dialog').addEventListener('keydown', event => { if (event.key === 'Escape') $('theme-dialog').hidden = true; });

  // ---------- Small icon animations (classes only; CSS decides whether motion is allowed) ----------
  const replay = (element, name) => { if (!element) return; element.classList.remove(name); requestAnimationFrame(() => element.classList.add(name)); };
  document.addEventListener('click', event => {
    const button = event.target.closest?.('#notify-enable, .toggle');
    if (button && (button.id === 'notify-enable' || button.querySelector('#notify-toggle'))) replay($('notify-banner').querySelector('.icon'), 'shake');
  });
  $('disappear').addEventListener('change', () => { replay($('disappear').closest('.timer'), 'sweep'); $('disappear').closest('.timer').dataset.on = String($('disappear').value !== 'off'); });
  $('disappear').closest('.timer').dataset.on = String($('disappear').value !== 'off');

  $('theme-app').onclick = () => open('app');
  $('conv-theme').onclick = () => { $('conv-menu').open = false; open('chat'); };
  $('theme-open').onclick = () => { $('menu').open = false; open('chat'); };

  window.Theme = Object.freeze({
    PRESETS, WALLPAPERS, tokens, contrast,
    /** Shows a conversation's theme (or the app theme with null). */
    use(chatId) { currentChat = chatId || null; apply(); },
    setAccount(id) { account = id || 'guest'; prefs = load(); apply(); },
    open,
  });
  currentChat = window.App?.conversationId || null; // A call link opened before this script loaded.
  apply();
})();
