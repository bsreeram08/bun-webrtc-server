'use strict';
// Slash commands: a registry, a parser and the composer's autocomplete. Commands run on this device and act
// through a context the chat engine supplies (send a message, press an existing button, set the timer...),
// so a command can never do more than the visible UI can. `//text` sends a literal message starting with "/".
//
// Bots (planned): a bot member will publish its commands; the app registers them here with
// { provider: 'bot:<name>' } and a run() that sends an encrypted payload { v:1, type:'command', id, name,
// args } to that bot through the same end-to-end mailbox as messages. The server never sees command text,
// and a bot can only receive commands from chats it is a member of.
(() => {
  const NAME = /^[a-z][a-z0-9_-]{0,31}$/;
  const registry = new Map();

  /** Splits arguments on spaces, keeping "double", 'single' and “smart” quoted runs together. */
  function tokenize(text) {
    const args = [], pattern = /"([^"]*)"|'([^']*)'|“([^”]*)”|(\S+)/g;
    let match;
    while ((match = pattern.exec(text))) args.push(match[1] ?? match[2] ?? match[3] ?? match[4]);
    return args;
  }
  /** `/name rest` → { name, args, rest }; null for ordinary text and for `//literal`. */
  function parse(input) {
    if (typeof input !== 'string' || !input.startsWith('/') || input.startsWith('//')) return null;
    const match = /^\/(\S*)(?:\s+([\s\S]*))?$/.exec(input.trim());
    const rest = (match?.[2] ?? '').trim();
    return { name: (match?.[1] ?? '').toLowerCase(), args: tokenize(rest), rest };
  }
  function register(command) {
    if (!command || !NAME.test(command.name) || typeof command.run !== 'function') throw new Error('Invalid command');
    const existing = registry.get(command.name);
    // A provider can replace its own command, never another provider's (a bot cannot shadow /burn).
    if (existing && existing.provider !== (command.provider || 'built-in')) throw new Error(`/${command.name} already exists`);
    registry.set(command.name, Object.freeze({ args: '', description: '', available: () => true, provider: 'built-in', ...command }));
  }
  function unregister(name, provider) {
    if (registry.get(name)?.provider === provider) registry.delete(name);
  }
  const usable = (command, context) => { try { return Boolean(command.available(context)); } catch { return false; } };
  const list = context => [...registry.values()].filter(command => usable(command, context)).sort((a, b) => a.name.localeCompare(b.name));
  const suggestions = (prefix, context) => list(context).filter(command => command.name.startsWith(prefix.toLowerCase()));
  /** Runs a command line. Resolves { ok, error? }; unknown or unavailable commands are never sent as messages. */
  async function run(input, context) {
    const parsed = parse(input);
    if (!parsed) return { ok: false, error: 'Not a command.' };
    const command = registry.get(parsed.name);
    if (!command) return { ok: false, error: `Unknown command /${parsed.name || ''}. Type /help to see commands, or start with // to send text that begins with a slash.` };
    if (!usable(command, context)) return { ok: false, error: `/${command.name} is not available in this conversation.` };
    try {
      const result = await command.run(context, parsed.args, parsed.rest);
      return result?.error ? { ok: false, error: result.error } : { ok: true };
    } catch (error) { return { ok: false, error: error?.message || `/${command.name} failed.` }; }
  }

  // ---------- Reminders (local only: stored and fired on this device) ----------
  const UNIT = { m: 60000, min: 60000, h: 3600000, d: 86400000 };
  /** "in 10m", "1h", "2d", "tomorrow 9am", "9:30", "5pm" → a future timestamp, or null. Text follows the time. */
  function parseWhen(args, now = new Date()) {
    let index = 0, at = null;
    if (args[index]?.toLowerCase() === 'in') index++;
    const span = /^(\d{1,4})(m|min|h|d)$/i.exec(args[index] || '');
    if (span) { at = now.getTime() + Number(span[1]) * UNIT[span[2].toLowerCase()]; index++; }
    else {
      let day = 0;
      if (args[index]?.toLowerCase() === 'tomorrow') { day = 1; index++; }
      if (args[index]?.toLowerCase() === 'at') index++;
      const time = /^(\d{1,2})(?::(\d{2}))?\s*(am|pm)?$/i.exec(args[index] || '');
      if (!time) return null;
      let hours = Number(time[1]); const minutes = Number(time[2] || 0), meridiem = time[3]?.toLowerCase();
      if (minutes > 59 || hours > (meridiem ? 12 : 23) || meridiem && hours === 0) return null;
      if (meridiem === 'pm' && hours < 12) hours += 12;
      if (meridiem === 'am' && hours === 12) hours = 0;
      const target = new Date(now); target.setDate(target.getDate() + day); target.setHours(hours, minutes, 0, 0);
      if (!day && target <= now) target.setDate(target.getDate() + 1); // A time already past today means tomorrow.
      at = target.getTime(); index++;
    }
    if (at <= now.getTime() || at - now.getTime() > 30 * UNIT.d) return null;
    return { at, text: args.slice(index).join(' ').trim() };
  }

  // ---------- Built-in commands ----------
  const inChat = context => context.where !== 'none';
  const inAccountChat = context => context.where === 'account';
  const TIMERS = { off: 'off', '1h': '3600000', '24h': '86400000', '1d': '86400000', '7d': '604800000', '1w': '604800000' };
  const builtins = [
    { name: 'help', description: 'List commands', available: () => true, run: context => context.showHelp() },
    {
      name: 'emoji', args: '[name]', description: 'Find an emoji (or type :name in any message)', available: inChat,
      run: (context, args) => context.compose(`:${(args[0] || '').replace(/^:|:$/g, '').slice(0, 32)}`),
    },
    { name: 'call', description: 'Start a voice call', available: inAccountChat, run: context => context.press('conv-voice', 'They need to be online to call.') },
    { name: 'video', description: 'Start a video call', available: inAccountChat, run: context => context.press('conv-video', 'They need to be online to call.') },
    { name: 'burn', description: 'Delete this conversation on both devices', available: inChat, run: context => context.press('burn') },
    { name: 'reset', description: 'Reset the secure session (fresh keys)', available: inAccountChat, run: context => context.press('conv-rotate') },
    { name: 'verify', description: 'Show the security code', available: inAccountChat, run: context => context.press('conv-safety') },
    {
      name: 'timer', args: 'off|1h|24h|7d', description: 'Disappearing timer for new messages', available: inChat,
      run(context, args) {
        const value = TIMERS[(args[0] || '').toLowerCase()];
        if (!value) return { error: 'Use /timer off, /timer 1h, /timer 24h or /timer 7d.' };
        context.setTimer(value);
        context.notice(value === 'off' ? 'New messages no longer disappear.' : `New messages disappear after ${args[0].toLowerCase()}.`);
      },
    },
    {
      name: 'me', args: '<action>', description: 'Send an action, like "/me waves"', available: inChat,
      run(context, args, rest) { if (!rest) return { error: 'Add an action, like /me waves.' }; return context.send({ text: rest, kind: 'action' }); },
    },
    { name: 'shrug', args: '[text]', description: 'Append ¯\\_(ツ)_/¯', available: inChat, run: (context, args, rest) => context.send({ text: `${rest ? `${rest} ` : ''}¯\\_(ツ)_/¯` }) },
    {
      name: 'theme', args: '[name]', description: 'Theme for this chat (midnight, fsociety, daylight, amoled, dusk, ocean, default)', available: inChat,
      run(context, args) {
        if (!args.length) return context.press('conv-theme');
        if (!context.setTheme(args.join(' '))) return { error: 'Unknown theme. Try midnight, fsociety, daylight, amoled, dusk, ocean or default.' };
        context.notice(`Chat theme set to ${args.join(' ')} on this device.`);
      },
    },
    {
      name: 'clear', description: 'Delete this chat’s history on this device only', available: inChat,
      async run(context) {
        if (await context.confirm('Clear this chat on this device?', 'Messages are deleted here only. The other person keeps theirs — use /burn to delete on both devices.', 'Clear')) await context.clearChat();
      },
    },
    {
      name: 'poll', args: '"Question" "Option" "Option" …', description: 'Start a poll (2–10 options)', available: inChat,
      run(context, args) {
        const [question, ...options] = args;
        const max = window.ChatStore?.MAX_OPTIONS || 10;
        if (!question || options.length < 2) return { error: 'Use /poll "Question" "Option 1" "Option 2" (quote anything with spaces).' };
        if (options.length > max) return { error: `A poll can have at most ${max} options.` };
        if ([question, ...options].some(value => value.length > 200)) return { error: 'Keep the question and each option under 200 characters.' };
        // `text` is the readable fallback for anything that cannot show polls.
        return context.send({ kind: 'poll', poll: { question, options }, text: `📊 ${question}\n${options.map((option, index) => `${index + 1}. ${option}`).join('\n')}` });
      },
    },
    {
      name: 'remind', args: '<in 10m|1h|tomorrow 9am> <text>', description: 'A reminder on this device only', available: inChat,
      run(context, args) {
        const when = parseWhen(args);
        if (!when) return { error: 'Use /remind in 10m <text>, /remind 1h <text> or /remind tomorrow 9am <text> (up to 30 days).' };
        if (!when.text) return { error: 'Add what to remind you about.' };
        context.remind(when.at, when.text);
        context.notice(`Reminder set for ${new Date(when.at).toLocaleString([], { weekday: 'short', hour: 'numeric', minute: '2-digit' })} — on this device only; it is not sent to anyone.`);
      },
    },
  ];
  for (const command of builtins) register(command);

  // ---------- Composer autocomplete ----------
  // One listbox for both "/" commands and ":" emoji: arrows move, Tab or Enter completes, Escape closes,
  // tap selects. Combobox semantics on the textarea (aria-expanded, aria-activedescendant).
  let ui = null;
  function attach(input, popup, getContext) {
    ui = { input, popup, getContext, items: [], index: 0, help: false, mode: null, token: null };
    input.setAttribute('aria-autocomplete', 'list'); input.setAttribute('aria-controls', popup.id); input.setAttribute('aria-expanded', 'false');
    input.addEventListener('input', () => refresh());
    input.addEventListener('blur', () => setTimeout(() => { if (document.activeElement !== input) close(); }, 150));
    popup.addEventListener('mousedown', event => event.preventDefault()); // Keep focus in the composer.
    popup.addEventListener('click', event => { const item = event.target.closest?.('[data-index]'); if (item) choose(Number(item.dataset.index)); });
  }
  function close() {
    if (!ui) return;
    ui.popup.hidden = true; ui.items = []; ui.help = false; ui.mode = null;
    ui.input.setAttribute('aria-expanded', 'false'); ui.input.removeAttribute('aria-activedescendant');
  }
  function option(index, id, parts) {
    const item = document.createElement('li');
    item.id = id; item.setAttribute('role', 'option'); item.dataset.index = String(index); item.setAttribute('aria-selected', String(index === 0));
    item.append(...parts);
    return item;
  }
  const span = (className, text) => { const node = document.createElement('span'); node.className = className; node.textContent = text; return node; };
  function show(items, mode, help = false) {
    ui.items = items; ui.index = 0; ui.help = help; ui.mode = mode;
    if (!items.length) { close(); return; }
    ui.popup.dataset.mode = mode;
    ui.popup.replaceChildren(...items.map((entry, index) => {
      if (mode === 'emoji') {
        const glyph = entry.custom ? Object.assign(document.createElement('img'), { className: 'custom-emoji', src: entry.url, alt: '', decoding: 'async' }) : span('cmd-glyph', entry.emoji);
        if (!entry.custom) glyph.setAttribute('aria-hidden', 'true');
        return option(index, `cmd-emoji-${index}`, [glyph, span('cmd-name', `:${entry.name}:`), span('cmd-desc', entry.custom ? 'custom' : '')]);
      }
      const description = entry.provider === 'built-in' ? entry.description : `${entry.description} · from ${entry.provider.replace(/^bot:/, 'bot ')}`;
      return option(index, `cmd-option-${entry.name}`, [span('cmd-name', `/${entry.name}`), span('cmd-args', entry.args), span('cmd-desc', description)]);
    }));
    ui.popup.hidden = false; ui.input.setAttribute('aria-expanded', 'true'); highlight(0);
  }
  function highlight(index) {
    ui.index = (index + ui.items.length) % ui.items.length;
    [...ui.popup.children].forEach((item, position) => item.setAttribute('aria-selected', String(position === ui.index)));
    const active = ui.popup.children[ui.index];
    ui.input.setAttribute('aria-activedescendant', active.id); active.scrollIntoView?.({ block: 'nearest' });
  }
  function refresh() {
    if (!ui) return;
    const value = ui.input.value, caret = ui.input.selectionStart ?? value.length;
    const command = /^\/([a-z0-9_-]*)$/i.exec(value);
    if (command && !value.startsWith('//')) { show(suggestions(command[1], ui.getContext()), 'command'); return; }
    // ":pa" (two or more characters after a colon, at a word start) offers emoji.
    const before = value.slice(0, caret), emoji = /(^|\s):([a-z0-9_+-]{2,32})$/i.exec(before);
    if (emoji && window.Emoji) {
      ui.token = { start: caret - emoji[2].length - 1, end: caret };
      const offer = () => show(window.Emoji.suggestions(emoji[2]), 'emoji');
      if (window.Emoji.loaded) offer(); else window.Emoji.load().then(() => { if (ui.input.value === value) offer(); });
      return;
    }
    close();
  }
  function choose(index) {
    const entry = ui.items[index];
    if (!entry) return;
    if (ui.mode === 'emoji') {
      const { start, end } = ui.token, insert = entry.custom ? `:${entry.name}: ` : `${entry.emoji} `;
      ui.input.value = ui.input.value.slice(0, start) + insert + ui.input.value.slice(end);
      const at = start + insert.length;
      close(); ui.input.dispatchEvent(new Event('input')); ui.input.focus(); ui.input.setSelectionRange?.(at, at);
      return;
    }
    ui.input.value = `/${entry.name}${entry.args ? ' ' : ''}`;
    close(); ui.input.dispatchEvent(new Event('input')); ui.input.focus();
    ui.input.setSelectionRange?.(ui.input.value.length, ui.input.value.length);
  }
  /** The composer calls this first on keydown; true means the popup consumed the key. */
  function keydown(event) {
    if (!ui || ui.popup.hidden || !ui.items.length) return false;
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') { highlight(ui.index + (event.key === 'ArrowDown' ? 1 : -1)); event.preventDefault(); return true; }
    if (event.key === 'Escape') { close(); event.preventDefault(); return true; }
    if (event.key === 'Tab' || event.key === 'Enter' && !event.shiftKey) {
      const entry = ui.items[ui.index];
      // Enter on an exact, argument-free command runs it (e.g. "/help"); otherwise complete it.
      if (event.key === 'Enter' && ui.mode === 'command' && !ui.help && ui.input.value.trim() === `/${entry.name}` && !entry.args) { close(); return false; }
      choose(ui.index); event.preventDefault(); return true;
    }
    return false;
  }
  const showHelp = context => { if (ui) { ui.input.focus(); show(list(context), 'command', true); } };

  window.Commands = Object.freeze({ register, unregister, parse, tokenize, parseWhen, list, suggestions, run, attach, keydown, close, showHelp });
})();
