'use strict';
// Emoji: `:shortcode:` → Unicode (gemoji names, vendored as emoji-data.json and loaded lazily), plus the
// workspace's custom emoji pack. Messages only ever carry text: standard shortcodes become Unicode on send,
// custom ones stay as `:name:` and each recipient renders them from its own copy of the pack (anyone without
// that emoji — a guest, an old client — simply sees the text).
(() => {
  const SHORTCODE = /:([a-z0-9_+-]{2,40}):/g;
  let table = null, loading = null, custom = new Map(), revision = 0;
  const reduceMotion = () => Boolean(globalThis.matchMedia?.('(prefers-reduced-motion: reduce)').matches);

  function load() {
    return loading ||= fetch('/emoji-data.json', { cache: 'force-cache' }).then(response => response.ok ? response.json() : {}).then(data => {
      table = data && typeof data === 'object' ? data : {}; revision++; return table;
    }).catch(() => { loading = null; table = table || {}; return table; });
  }
  /** Replaces the custom pack (from GET /api/emoji); only same-origin /emoji/ URLs are ever used. */
  function setCustom(list) {
    custom = new Map();
    for (const item of Array.isArray(list) ? list : []) {
      if (item && /^[a-z0-9_+-]{2,32}$/.test(item.name) && /^\/emoji\/[0-9a-f]{64}\.(png|gif|webp)$/.test(item.url)) custom.set(item.name, { url: item.url, animated: Boolean(item.animated), mine: Boolean(item.mine) });
    }
    revision++;
  }
  /** Standard shortcodes become Unicode; custom names and unknown text are left exactly as typed. */
  function expand(text) {
    if (!table || typeof text !== 'string') return text;
    return text.replace(SHORTCODE, (whole, name) => custom.has(name) ? whole : table[name] ?? whole);
  }
  const graphemes = text => globalThis.Intl?.Segmenter ? [...new Intl.Segmenter(undefined, { granularity: 'grapheme' }).segment(text)].map(part => part.segment) : [...text];
  const isEmoji = piece => /\p{Extended_Pictographic}|\p{Regional_Indicator}/u.test(piece);
  /** Splits text into plain runs, Unicode emoji and known custom emoji tokens. */
  function tokens(text) {
    const out = []; let last = 0;
    for (const match of text.matchAll(SHORTCODE)) {
      if (!custom.has(match[1])) continue;
      if (match.index > last) out.push({ text: text.slice(last, match.index) });
      out.push({ custom: match[1] }); last = match.index + match[0].length;
    }
    if (last < text.length) out.push({ text: text.slice(last) });
    return out;
  }
  /** 'sticker' for one custom emoji alone, 'big' for 1–3 emoji alone, '' otherwise. */
  function size(text) {
    const parts = tokens(text.trim()).flatMap(part => part.custom ? [part] : graphemes(part.text).filter(piece => piece.trim()).map(piece => ({ text: piece })));
    if (!parts.length || parts.length > 3 || !parts.every(part => part.custom || isEmoji(part.text))) return '';
    return parts.length === 1 && parts[0].custom ? 'sticker' : 'big';
  }
  function image(name) {
    const item = custom.get(name), img = document.createElement('img');
    img.className = 'custom-emoji'; img.alt = `:${name}:`; img.title = `:${name}:`; img.decoding = 'async'; img.loading = 'lazy'; img.src = item.url;
    if (item.animated) {
      img.dataset.animated = 'true';
      // Under reduced motion an animated emoji shows its first frame: a canvas snapshot of the image.
      if (reduceMotion()) img.addEventListener('load', () => {
        try {
          const canvas = document.createElement('canvas'); canvas.width = img.naturalWidth; canvas.height = img.naturalHeight;
          canvas.getContext('2d').drawImage(img, 0, 0); canvas.className = img.className; canvas.title = img.title;
          canvas.setAttribute('role', 'img'); canvas.setAttribute('aria-label', img.alt); img.replaceWith(canvas);
        } catch {}
      }, { once: true });
    }
    return img;
  }
  /** Renders message text into an element (text nodes and same-origin images only); returns the size class. */
  function render(element, text) {
    element.replaceChildren(...tokens(text).map(part => part.custom ? image(part.custom) : document.createTextNode(part.text)));
    return size(text);
  }
  /** Autocomplete entries for ":pre": custom emoji first, then standard shortcodes. */
  function suggestions(prefix, limit = 8) {
    const wanted = prefix.toLowerCase(), out = [];
    for (const [name, item] of custom) if (name.startsWith(wanted) && out.length < limit) out.push({ name, custom: true, url: item.url });
    if (table) for (const name in table) { if (out.length >= limit) break; if (name.startsWith(wanted) && !custom.has(name)) out.push({ name, emoji: table[name] }); }
    return out;
  }
  window.Emoji = Object.freeze({
    load, setCustom, expand, render, size, suggestions, tokens,
    get custom() { return custom; }, get revision() { return revision; }, get loaded() { return Boolean(table); },
  });
  // Load the shortcode table when the browser is idle, so ":smile:" can convert on send.
  (globalThis.requestIdleCallback || (callback => setTimeout(callback, 1500)))(() => load());
})();
