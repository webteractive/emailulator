// emailulator web UI.
//
// Everything that comes out of an email — subjects, names, addresses, snippets,
// headers, filenames, link text — is attacker-controlled. It only ever enters the
// page as a text node or an attribute value through h() below, never as markup,
// and the HTML body is shown in a sandboxed frame that cannot run script.

const PAGE = 50;
const MAX_PAGE = 500; // the API's own ceiling
const RAW_PREVIEW_CHARS = 500_000;
const MANY_INBOXES = 8;
const DEFAULT_INBOX = 'default';
const SVG_NS = 'http://www.w3.org/2000/svg';

const ICONS = {
  inbox: ['M2 9.5 4 3.5h8l2 6v3H2z', 'M2 9.5h3.5l1 1.5h3l1-1.5H14'],
  star: ['M8 1.8l1.9 3.9 4.3.6-3.1 3 .7 4.3L8 11.6l-3.8 2 .7-4.3-3.1-3 4.3-.6z'],
  at: ['M10.5 8a2.5 2.5 0 1 1-5 0 2.5 2.5 0 0 1 5 0v1a1.6 1.6 0 0 0 3.2 0V8A5.7 5.7 0 1 0 11 12.8'],
  clip: ['M13 7.5 8 12.5a3 3 0 0 1-4.2-4.2l5.3-5.3a2 2 0 0 1 2.8 2.8L6.7 11a1 1 0 0 1-1.4-1.4L10 5'],
  trash: ['M3 4.5h10', 'M6.5 4.5V3h3v1.5', 'M4.5 4.5l.6 8.5h5.8l.6-8.5', 'M6.8 7v4', 'M9.2 7v4'],
  mail: ['M2 4h12v8.5H2z', 'M2 4.5l6 4.5 6-4.5'],
  download: ['M8 2.5V10', 'M5 7.5l3 3 3-3', 'M3 13h10'],
  menu: ['M2.5 4.5h11', 'M2.5 8h11', 'M2.5 11.5h11'],
  back: ['M9.5 3.5 5 8l4.5 4.5'],
  check: ['M1.5 8.5l3 3 5.5-6.5', 'M8 11.5l6-7'],
  copy: ['M5.5 5.5h7v8h-7z', 'M3.5 10.5v-8h7'],
  key: ['M8 10.5a2.5 2.5 0 1 1-5 0 2.5 2.5 0 0 1 5 0z', 'M7.3 8.7 13 3', 'M11 5l1.6 1.6'],
  plus: ['M8 3.5v9', 'M3.5 8h9'],
  close: ['M4 4l8 8', 'M12 4l-8 8'],
};

const $ = (id) => document.getElementById(id);

/** Build an element. Strings among the children become text nodes. */
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value == null || value === false) continue;
    if (key === 'class') el.className = value;
    else if (key === 'text') el.textContent = value;
    else if (key === 'dataset') Object.assign(el.dataset, value);
    else if (key.startsWith('on')) el.addEventListener(key.slice(2), value);
    else el.setAttribute(key, value === true ? '' : value);
  }
  for (const child of children.flat()) {
    if (child != null && child !== false) el.append(child);
  }
  return el;
}

/** Replace an element's children. Unlike replaceChildren, null means "nothing", not the text "null". */
function fill(el, ...children) {
  el.replaceChildren(...children.flat().filter((child) => child != null && child !== false));
}

function icon(name, extra) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', '0 0 16 16');
  svg.setAttribute('class', extra ? `icon ${extra}` : 'icon');
  svg.setAttribute('aria-hidden', 'true');
  for (const d of ICONS[name]) {
    const path = document.createElementNS(SVG_NS, 'path');
    path.setAttribute('d', d);
    svg.append(path);
  }
  return svg;
}

const state = {
  info: null,
  access: 'admin', // or 'inbox': a session confined to ownInbox
  ownInbox: null,
  inboxes: [],
  inboxesLoaded: false,
  stats: { total: 0, unread: 0, starred: 0, bytes: 0 },
  statsLoaded: false,
  view: { kind: 'all' }, // or {kind: 'starred'} or {kind: 'inbox', id}
  panel: null, // 'connect' while an inbox's connection details are open
  keys: null, // {inbox, list} once fetched for the open panel
  query: '',
  messages: [],
  total: 0,
  unread: 0,
  listLoaded: false,
  selectedId: null,
  detail: null,
  detailError: null,
  tabPref: 'html',
  width: 'desktop',
  raw: null, // {id, text} once fetched
  links: null, // {id, links} once fetched
  check: null, // {id, all, report} once fetched
  checkAll: false, // every client in the dataset, not only the main five
  inboxFilter: '',
};

// An API key that was just created. The server returns it once and this page
// shows it once: it lives in this variable until the panel closes, and nowhere
// else — not in storage, not in the address bar.
let freshKey = null;
// The New inbox dialog's pending credentials: the id the inbox will get and
// the key it will be created with. Held only while the dialog is open.
let draft = null;
let draftTimer = null;
let draftSeq = 0;
// An inbox being deleted from here: its keys are not worth asking for again.
let leavingInbox = null;

let listSeq = 0;
let detailSeq = 0;
let keysSeq = 0;
let events = null;
let everConnected = false;
let reconnectTimer = null;
let refreshTimer = null;
let searchTimer = null;
let toastTimer = null;
let settleConfirm = null; // answers the open confirmation, if there is one

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

async function api(path, options = {}) {
  const init = { method: options.method || 'GET', headers: {}, credentials: 'same-origin' };
  if (options.body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(options.body);
  }
  let response;
  try {
    response = await fetch(path, init);
  } catch {
    throw new HttpError(0, 'The server is not reachable.');
  }
  if (response.status === 401 && path !== '/api/v1/session') {
    showLogin();
    throw new HttpError(401, 'Sign in to continue.');
  }
  if (!response.ok) {
    let message = `Request failed (${response.status}).`;
    try {
      message = (await response.json()).error || message;
    } catch {
      // Not JSON; keep the generic message.
    }
    throw new HttpError(response.status, message);
  }
  if (response.status === 204) return null;
  return options.text ? response.text() : response.json();
}

function report(error) {
  if (error instanceof HttpError && error.status === 401) return; // the sign-in screen says it
  toast(error.message || String(error));
}

function toast(message) {
  const el = $('toast');
  el.textContent = message;
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    el.hidden = true;
  }, 4000);
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

function relativeTime(ms) {
  const age = Date.now() - ms;
  if (age < 60_000) return 'now';
  if (age < 3_600_000) return `${Math.floor(age / 60_000)}m`;
  if (age < 86_400_000) return `${Math.floor(age / 3_600_000)}h`;
  const date = new Date(ms);
  if (age < 6 * 86_400_000) return date.toLocaleDateString(undefined, { weekday: 'short' });
  const sameYear = date.getFullYear() === new Date().getFullYear();
  return date.toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    year: sameYear ? undefined : 'numeric',
  });
}

function fullTime(ms) {
  return new Date(ms).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'medium' });
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(bytes < 10_240 ? 1 : 0)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function addressLabel(address) {
  if (!address) return '(unknown sender)';
  return address.name || address.address;
}

function addressFull(address) {
  return address.name ? `${address.name} <${address.address}>` : address.address;
}

function plural(count, word) {
  return `${count} ${word}${count === 1 ? '' : 's'}`;
}

// ---------------------------------------------------------------------------
// Routing: the location hash is the source of truth for view, search and message
// ---------------------------------------------------------------------------

function isAdmin() {
  return state.access === 'admin';
}

/** Where a session lands when the address names nothing it may open. */
function homeView() {
  return isAdmin() ? { kind: 'all' } : { kind: 'inbox', id: state.ownInbox };
}

function viewKey(view) {
  return view.kind === 'inbox' ? `inbox:${view.id}` : view.kind;
}

function parseHash() {
  const raw = location.hash.replace(/^#\/?/, '');
  const [path, search = ''] = raw.split('?');
  const parts = path.split('/');
  let view = homeView();
  let rest = parts[1];
  if (parts[0] === 'starred') {
    view = { kind: 'starred' };
  } else if (parts[0] === 'inbox') {
    rest = undefined;
    try {
      const id = decodeURIComponent(parts[1] || '');
      // A session confined to one inbox has no other to open.
      if (id && (isAdmin() || id === state.ownInbox)) {
        view = { kind: 'inbox', id };
        rest = parts[2];
      }
    } catch {
      // A mangled link falls back to the home view.
    }
  } else if (parts[0] !== 'all') {
    rest = undefined;
  }
  const panel = rest === 'connect' && view.kind === 'inbox' ? 'connect' : null;
  const id = /^\d+$/.test(rest || '') ? Number(rest) : null;
  return { view, id, panel, query: new URLSearchParams(search).get('q') || '' };
}

function formatHash({ view, id, panel, query }) {
  let hash = '#/' + (view.kind === 'inbox' ? `inbox/${encodeURIComponent(view.id)}` : view.kind);
  if (panel) hash += `/${panel}`;
  else if (id != null) hash += `/${id}`;
  if (query) hash += `?q=${encodeURIComponent(query)}`;
  return hash;
}

/**
 * Move to a new route. Unspecified parts keep their current value, except that
 * opening a message or changing view closes an open panel.
 */
function setRoute(change, { replace = false } = {}) {
  const leaving = 'view' in change || change.id != null;
  const next = {
    view: change.view ?? state.view,
    id: change.id !== undefined ? change.id : state.selectedId,
    panel: 'panel' in change ? change.panel : leaving ? null : state.panel,
    query: change.query ?? state.query,
  };
  if (next.panel) next.id = null;
  const hash = formatHash(next);
  if (hash !== location.hash) {
    if (replace) history.replaceState(null, '', hash);
    else history.pushState(null, '', hash);
  }
  applyRoute();
}

function applyRoute(force = false) {
  const route = parseHash();
  const viewChanged =
    force || viewKey(route.view) !== viewKey(state.view) || route.query !== state.query;
  const inboxChanged = force || viewKey(route.view) !== viewKey(state.view);
  const panelChanged = force || route.panel !== state.panel || (route.panel != null && inboxChanged);
  state.view = route.view;
  state.query = route.query;
  state.panel = route.panel;
  if (!route.panel || inboxChanged) {
    // Leaving the panel is what ends a new key's one showing.
    freshKey = null;
    state.keys = null;
  }
  if ($('search').value !== state.query && document.activeElement !== $('search')) {
    $('search').value = state.query;
  }
  if (viewChanged) {
    state.messages = [];
    state.listLoaded = false;
    renderSidebar();
    renderList();
    loadList({ reset: true });
  }
  if (force || route.id !== state.selectedId || panelChanged) {
    loadDetail(route.id);
  }
  if (route.panel && panelChanged) loadKeys();
  // The welcome is drawn for one view, so a new view needs it drawn again:
  // the Connect button it offers belongs to the inbox being looked at.
  if (panelChanged || viewChanged) {
    renderListHead();
    renderEmptiness();
  }
  closeDrawer();
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

function listParams() {
  const params = new URLSearchParams();
  if (state.view.kind === 'inbox') params.set('inbox', state.view.id);
  if (state.view.kind === 'starred') params.set('starred', 'true');
  if (state.query) params.set('q', state.query);
  return params;
}

async function loadList({ reset = false } = {}) {
  const seq = ++listSeq;
  const params = listParams();
  const keep = reset ? PAGE : Math.max(state.messages.length, PAGE);
  params.set('limit', String(Math.min(keep, MAX_PAGE)));
  try {
    const page = await api(`/api/v1/messages?${params}`);
    if (seq !== listSeq) return;
    state.messages = page.messages;
    state.total = page.total;
    state.unread = page.unread;
    state.listLoaded = true;
    syncDetailFlags();
    renderList();
  } catch (error) {
    if (seq === listSeq) report(error);
  }
}

async function loadMore() {
  const last = state.messages[state.messages.length - 1];
  if (!last) return;
  const seq = listSeq;
  const params = listParams();
  params.set('limit', String(PAGE));
  params.set('before', String(last.id));
  $('load-more').disabled = true;
  try {
    const page = await api(`/api/v1/messages?${params}`);
    if (seq !== listSeq) return;
    state.messages = state.messages.concat(page.messages);
    state.total = page.total;
    state.unread = page.unread;
    renderList();
  } catch (error) {
    report(error);
  } finally {
    $('load-more').disabled = false;
  }
}

async function loadInboxes() {
  try {
    const data = await api('/api/v1/inboxes');
    state.inboxes = data.inboxes;
    state.stats = data.stats;
    state.statsLoaded = true;
    state.inboxesLoaded = true;
    if (state.view.kind === 'inbox' && !data.inboxes.some((inbox) => inbox.id === state.view.id)) {
      toast('That inbox no longer exists.');
      setRoute({ view: homeView(), id: null, query: '', panel: null }, { replace: true });
    }
    renderSidebar();
    renderEmptiness();
  } catch (error) {
    report(error);
  }
}

/** The keys of the inbox whose panel is open. Only an admin may list them. */
async function loadKeys() {
  if (!isAdmin() || state.panel !== 'connect' || state.view.kind !== 'inbox') return;
  const inbox = state.view.id;
  if (inbox === leavingInbox) return;
  const seq = ++keysSeq;
  try {
    const data = await api(`/api/v1/inboxes/${encodeURIComponent(inbox)}/keys`);
    if (seq !== keysSeq || state.panel !== 'connect' || state.view.id !== inbox) return;
    state.keys = { inbox, list: data.keys };
    renderKeys();
    renderSnippets();
  } catch (error) {
    // 404: the inbox went away; the inbox list notices and leaves.
    if (seq === keysSeq && error.status !== 404) report(error);
  }
}

async function loadDetail(id) {
  const seq = ++detailSeq;
  state.selectedId = id;
  state.detail = null;
  state.detailError = null;
  state.raw = null;
  state.links = null;
  state.check = null;
  document.body.dataset.pane = id == null && !state.panel ? 'list' : 'reader';
  renderSelection();
  renderReader();
  if (id == null) return;
  try {
    const detail = await api(`/api/v1/messages/${id}`);
    if (seq !== detailSeq) return;
    state.detail = detail;
    renderReader();
    if (!detail.read) setFlags(id, { read: true });
  } catch (error) {
    if (seq !== detailSeq) return;
    if (error.status === 404) {
      toast('That message no longer exists.');
      setRoute({ id: null }, { replace: true });
    } else {
      state.detailError = error.message;
      renderReader();
    }
  }
}

/** Reload after a change that may have come from anywhere. */
function scheduleRefresh() {
  clearTimeout(refreshTimer);
  refreshTimer = setTimeout(() => {
    loadList();
    loadInboxes();
  }, 120);
}

/** The list is refreshed more often than the open message; carry its flags over. */
function syncDetailFlags() {
  if (!state.detail) return;
  const summary = state.messages.find((m) => m.id === state.detail.id);
  if (!summary) return;
  if (summary.read !== state.detail.read || summary.starred !== state.detail.starred) {
    state.detail.read = summary.read;
    state.detail.starred = summary.starred;
    renderReaderActions();
  }
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

function patchLocal(id, flags) {
  const summary = state.messages.find((m) => m.id === id);
  if (summary) Object.assign(summary, flags);
  if (state.detail && state.detail.id === id) Object.assign(state.detail, flags);
}

async function setFlags(id, flags) {
  patchLocal(id, flags);
  renderList();
  renderReaderActions();
  try {
    await api(`/api/v1/messages/${id}`, { method: 'PATCH', body: flags });
  } catch (error) {
    report(error);
  }
  scheduleRefresh();
}

function currentMessage() {
  return state.detail || state.messages.find((m) => m.id === state.selectedId) || null;
}

function toggleStar(id = state.selectedId) {
  const message = state.messages.find((m) => m.id === id) || (state.detail?.id === id ? state.detail : null);
  if (message) setFlags(id, { starred: !message.starred });
}

function toggleUnread() {
  const message = currentMessage();
  if (message) setFlags(message.id, { read: !message.read });
}

async function deleteSelected() {
  const message = currentMessage();
  if (!message) return;
  const confirmed = await confirmAction({
    title: 'Delete this message?',
    body: message.subject ? `“${message.subject}” will be deleted for good.` : 'It will be deleted for good.',
    action: 'Delete',
    focusAction: true,
  });
  if (!confirmed) return;
  const index = state.messages.findIndex((m) => m.id === message.id);
  const neighbour = index >= 0 ? state.messages[index + 1] || state.messages[index - 1] : null;
  try {
    await api(`/api/v1/messages/${message.id}`, { method: 'DELETE' });
  } catch (error) {
    if (error.status !== 404) return report(error);
  }
  state.messages = state.messages.filter((m) => m.id !== message.id);
  // On a phone, deleting returns to the list rather than opening the next message.
  const next = isSinglePane() ? null : neighbour;
  setRoute({ id: next ? next.id : null }, { replace: true });
  renderList();
  scheduleRefresh();
}

/** What people call an inbox. Its id is for machines: the SMTP username. */
function inboxName(id) {
  return state.inboxes.find((inbox) => inbox.id === id)?.name || id;
}

function viewName() {
  if (state.view.kind === 'inbox') return inboxName(state.view.id);
  return state.view.kind === 'starred' ? 'Starred' : 'All mail';
}

/** What the bulk actions are about to touch, in words. */
function scopeName() {
  const where =
    state.view.kind === 'inbox'
      ? `in the ${inboxName(state.view.id)} inbox`
      : isAdmin()
        ? 'across every inbox'
        : `in the ${inboxName(state.ownInbox)} inbox`;
  if (state.query) return `matching “${state.query}” ${where}`;
  if (state.view.kind === 'starred') return `starred ${where}`;
  return where;
}

async function markAllRead() {
  try {
    await api(`/api/v1/messages?${listParams()}`, { method: 'PATCH', body: { read: true } });
  } catch (error) {
    report(error);
  }
  scheduleRefresh();
}

async function deleteAll() {
  const narrowed = state.query || state.view.kind === 'starred';
  const confirmed = await confirmAction({
    title: narrowed
      ? `Delete ${plural(state.total, 'listed message')}?`
      : state.view.kind === 'inbox'
        ? `Delete everything in ${inboxName(state.view.id)}?`
        : isAdmin()
          ? 'Delete all mail in every inbox?'
          : 'Delete all mail?',
    body: `${plural(state.total, 'message')} ${scopeName()} will be deleted for good.`,
    action: narrowed ? 'Delete listed' : 'Delete all',
    focusAction: false,
  });
  if (!confirmed) return;
  try {
    await api(`/api/v1/messages?${listParams()}`, { method: 'DELETE' });
    setRoute({ id: null }, { replace: true });
  } catch (error) {
    report(error);
  }
  scheduleRefresh();
}

/** A key of the shape the server mints, made here so it can be shown before the inbox exists. */
function randomKey() {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return 'emu_' + Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function renderDraft() {
  if (!draft) return;
  const id = $('new-inbox-id');
  id.textContent = draft.id || 'made from the name';
  id.classList.toggle('credential-empty', !draft.id);
  $('new-inbox-key').textContent = draft.key;
  const copyId = $('new-inbox-id-actions').querySelector('button');
  if (copyId) copyId.disabled = !draft.id;
}

/** A Copy button for a value that changes while the dialog is open. */
function draftCopyButton(read) {
  if (!navigator.clipboard) return null;
  return h(
    'button',
    { class: 'btn btn-quiet copy', type: 'button', onclick: (event) => copyText(read(), event.currentTarget) },
    icon('copy'),
    h('span', { class: 'copy-label', text: 'Copy' }),
  );
}

function openNewInbox() {
  draft = { id: '', key: randomKey() };
  $('new-inbox-name').value = '';
  $('new-inbox-description').value = '';
  $('new-inbox-error').hidden = true;
  $('new-inbox-create').disabled = false;
  fill($('new-inbox-id-actions'), draftCopyButton(() => draft.id));
  fill(
    $('new-inbox-key-actions'),
    h(
      'button',
      {
        class: 'btn btn-quiet',
        type: 'button',
        title: 'Make a different key',
        onclick: () => {
          draft.key = randomKey();
          renderDraft();
        },
      },
      'Regenerate',
    ),
    draftCopyButton(() => draft.key),
  );
  renderDraft();
  $('new-inbox-dialog').showModal();
  $('new-inbox-name').focus();
}

/** Close the dialog and forget the key it showed. */
function closeNewInbox() {
  clearTimeout(draftTimer);
  draftSeq += 1;
  draft = null;
  const dialog = $('new-inbox-dialog');
  if (dialog.open) dialog.close();
  $('new-inbox-key').textContent = '';
}

/**
 * Ask the server which id this name would get. Only it knows which ids are
 * taken, and so when a name's plain slug needs a number added.
 */
async function suggestInboxId() {
  clearTimeout(draftTimer);
  if (!draft) return;
  const seq = ++draftSeq;
  const name = $('new-inbox-name').value.trim();
  let id = '';
  if (name) {
    try {
      id = (await api('/api/v1/inboxes', { method: 'POST', body: { name, dry_run: true } })).id;
    } catch {
      // Creating will say what is wrong with the name.
    }
  }
  if (!draft || seq !== draftSeq) return; // a later keystroke has asked again
  draft.id = id;
  renderDraft();
}

async function createInbox(event) {
  event.preventDefault();
  if (!draft) return;
  const field = $('new-inbox-name');
  const error = $('new-inbox-error');
  const fail = (message) => {
    error.textContent = message.charAt(0).toUpperCase() + message.slice(1);
    error.hidden = false;
    field.focus();
  };
  error.hidden = true;
  const name = field.value.trim();
  if (!name) return fail('Give the inbox a name.');

  const submit = $('new-inbox-create');
  submit.disabled = true;
  try {
    // Enter can beat the debounce; what is created must be what is shown.
    await suggestInboxId();
    if (!draft) return;
    const body = { name, description: $('new-inbox-description').value.trim(), key: draft.key };
    if (draft.id) body.id = draft.id;
    const inbox = await api('/api/v1/inboxes', { method: 'POST', body });
    closeNewInbox();
    await loadInboxes();
    // A new inbox is no use until an app can deliver into it: land on Connect,
    // where its key gets its one showing outside this dialog.
    setRoute({ view: { kind: 'inbox', id: inbox.id }, id: null, query: '', panel: 'connect' });
    freshKey = { inbox: inbox.id, id: null, key: inbox.key, label: 'first key' };
    renderReader();
  } catch (failure) {
    if (failure.status === 401) return closeNewInbox();
    // The server says what is wrong with the name, or that it is taken.
    fail(failure.message);
    field.select();
    suggestInboxId();
  } finally {
    submit.disabled = false;
  }
}

async function deleteInbox() {
  const id = state.view.id;
  const inbox = state.inboxes.find((candidate) => candidate.id === id);
  const total = inbox ? inbox.total : 0;
  const keys = inbox ? inbox.keys : 0;
  const confirmed = await confirmAction({
    title: `Delete the ${inboxName(id)} inbox?`,
    body: keys
      ? `${plural(total, 'message')} and ${plural(keys, 'API key')} will be deleted for good. Anything still using ${keys === 1 ? 'that key' : 'those keys'} will be refused.`
      : `${plural(total, 'message')} will be deleted for good, along with the inbox itself.`,
    action: 'Delete inbox',
    focusAction: false,
  });
  if (!confirmed) return;
  leavingInbox = id;
  try {
    await api(`/api/v1/inboxes/${encodeURIComponent(id)}`, { method: 'DELETE' });
    setRoute({ view: homeView(), id: null, query: '', panel: null }, { replace: true });
    toast(`Deleted the ${inbox ? inbox.name : id} inbox.`);
  } catch (error) {
    report(error);
  } finally {
    leavingInbox = null;
  }
  scheduleRefresh();
}

async function createKey(event) {
  event.preventDefault();
  const inbox = state.view.id;
  const field = $('key-label');
  try {
    const created = await api(`/api/v1/inboxes/${encodeURIComponent(inbox)}/keys`, {
      method: 'POST',
      body: { label: field.value.trim() },
    });
    if (state.panel !== 'connect' || state.view.id !== inbox) return;
    freshKey = { inbox, id: created.id, key: created.key, label: created.label };
    renderReader();
    loadKeys();
    loadInboxes();
  } catch (error) {
    report(error);
  }
}

async function regenerateKey(key) {
  const confirmed = await confirmAction({
    title: `Regenerate the key “${key.label}”?`,
    body: `${key.prefix}… will stop working at once: SMTP logins, API and MCP calls, and any browser signed in with it. The key gets a new value, shown once; whatever uses it has to be given that.`,
    action: 'Regenerate key',
    focusAction: false,
  });
  if (!confirmed) return;
  try {
    const renewed = await api(
      `/api/v1/inboxes/${encodeURIComponent(key.inbox)}/keys/${key.id}/regenerate`,
      { method: 'POST' },
    );
    if (state.panel !== 'connect' || state.view.id !== key.inbox) return;
    freshKey = { inbox: key.inbox, id: renewed.id, key: renewed.key, label: renewed.label };
    renderReader();
  } catch (error) {
    report(error);
  }
  loadKeys();
}

async function revokeKey(key) {
  const confirmed = await confirmAction({
    title: `Revoke the key “${key.label}”?`,
    body: `${key.prefix}… will stop working at once: SMTP logins, API and MCP calls, and any browser signed in with it. It cannot be restored.`,
    action: 'Revoke key',
    focusAction: false,
  });
  if (!confirmed) return;
  try {
    await api(`/api/v1/inboxes/${encodeURIComponent(key.inbox)}/keys/${key.id}`, { method: 'DELETE' });
  } catch (error) {
    if (error.status !== 404) return report(error);
  }
  if (freshKey && freshKey.id === key.id) {
    freshKey = null;
    if (state.panel === 'connect') renderReader();
  }
  loadKeys();
  loadInboxes();
}

/**
 * Ask before something irreversible. The answer comes from the buttons, never
 * from the dialog's `close` event: that event is delivered late, and one left
 * over from a dismissed prompt would otherwise answer the next prompt.
 */
function confirmAction({ title, body, action, focusAction }) {
  const dialog = $('confirm');
  if (settleConfirm) settleConfirm(false);
  $('confirm-title').textContent = title;
  $('confirm-body').textContent = body;
  $('confirm-ok').textContent = action;
  return new Promise((resolve) => {
    settleConfirm = (answer) => {
      settleConfirm = null;
      if (dialog.open) dialog.close();
      resolve(answer);
    };
    dialog.showModal();
    (focusAction ? $('confirm-ok') : $('confirm-cancel')).focus();
  });
}

function moveSelection(delta) {
  if (!state.messages.length) return;
  const index = state.messages.findIndex((m) => m.id === state.selectedId);
  const next = index < 0 ? (delta > 0 ? 0 : state.messages.length - 1) : index + delta;
  const target = state.messages[Math.min(Math.max(next, 0), state.messages.length - 1)];
  if (!target || target.id === state.selectedId) return;
  setRoute({ id: target.id }, { replace: state.selectedId != null });
  document
    .querySelector(`#messages li[data-id="${target.id}"]`)
    ?.scrollIntoView({ block: 'nearest' });
}

async function copyText(text, button) {
  try {
    await navigator.clipboard.writeText(text);
    const label = button.querySelector('.copy-label');
    label.textContent = 'Copied';
    setTimeout(() => {
      label.textContent = 'Copy';
    }, 1500);
  } catch {
    toast('Copying is not available here; select the text instead.');
  }
}

// ---------------------------------------------------------------------------
// Rendering: sidebar
// ---------------------------------------------------------------------------

function navItem({ view, label, iconName, badge, count, title }) {
  const current = viewKey(view) === viewKey(state.view);
  return h(
    'li',
    null,
    h(
      'button',
      {
        class: 'nav-item',
        type: 'button',
        title,
        'aria-current': current ? 'page' : null,
        onclick: () => setRoute({ view, id: null, query: '' }),
      },
      icon(iconName),
      h('span', { class: 'nav-label', text: label }),
      badge
        ? h('span', { class: 'badge' }, String(badge), h('span', { class: 'visually-hidden', text: ' unread' }))
        : count
          ? h('span', { class: 'nav-count', text: String(count) })
          : null,
    ),
  );
}

function renderSidebar() {
  const { stats, inboxes } = state;
  const admin = isAdmin();
  $('nav-fixed').replaceChildren(
    ...[
      // "All mail" spans inboxes, which a session confined to one cannot do.
      admin
        ? navItem({ view: { kind: 'all' }, label: 'All mail', iconName: 'mail', badge: stats.unread, count: stats.total })
        : null,
      navItem({ view: { kind: 'starred' }, label: 'Starred', iconName: 'star', count: stats.starred }),
    ].filter(Boolean),
  );

  $('new-inbox').hidden = !admin;
  if (!admin && draft) closeNewInbox();

  const filterField = $('inbox-filter');
  filterField.hidden = inboxes.length <= MANY_INBOXES;
  if (filterField.hidden && state.inboxFilter) {
    state.inboxFilter = '';
    filterField.value = '';
  }
  const needle = state.inboxFilter.trim().toLowerCase();
  const shown = inboxes.filter(
    (inbox) => !needle || inbox.name.toLowerCase().includes(needle) || inbox.id.includes(needle),
  );
  $('nav-inboxes').replaceChildren(
    ...shown.map((inbox) =>
      navItem({
        view: { kind: 'inbox', id: inbox.id },
        label: inbox.name,
        title: [inbox.name, inbox.description, `ID ${inbox.id}`].filter(Boolean).join(' — '),
        iconName: 'inbox',
        badge: inbox.unread,
        count: inbox.total,
      }),
    ),
  );
  $('inbox-count').textContent = admin && inboxes.length ? String(inboxes.length) : '';
  $('nav-empty').hidden = !state.inboxesLoaded || shown.length > 0;
}

/**
 * Where an app reaches SMTP: the host the server names, which is its listener's
 * address or the one an operator set. Only a server listening on every
 * interface leaves it to the page's own host, which behind a proxy can be a
 * name that only carries HTTP.
 */
function smtpEndpoint() {
  const info = state.info;
  return {
    host: (info && info.smtp_host) || location.hostname,
    port: info ? info.smtp_port : 1025,
  };
}

/** The sidebar footer: where this server listens and who you are to it. */
function renderServer() {
  const info = state.info;
  if (!info) return;
  const { host, port } = smtpEndpoint();
  const row = (term, value) => [h('dt', { text: term }), h('dd', { text: value })];
  $('connect-info').replaceChildren(
    ...row('SMTP', `${host}:${port}`),
    ...row('Login', info.smtp_auth_required ? 'inbox id + API key' : 'optional; without a key, mail goes to default'),
    ...row('STARTTLS', info.smtp_starttls ? 'offered' : 'off'),
    ...(info.auth_required ? row('Access', isAdmin() ? 'admin' : `the ${state.ownInbox} inbox only`) : []),
  );
  $('version').textContent = `v${info.version}`;
  $('sign-out').hidden = !info.auth_required;
}

function setLive(stateName) {
  $('live').dataset.state = stateName;
  $('live-text').textContent = { live: 'Live', connecting: 'Connecting…', offline: 'Reconnecting…' }[stateName];
}

// ---------------------------------------------------------------------------
// Rendering: message list
// ---------------------------------------------------------------------------

function messageRow(message) {
  const selected = message.id === state.selectedId;
  const classes = ['row'];
  if (!message.read) classes.push('unread');
  if (selected) classes.push('selected');
  return h(
    'li',
    { class: classes.join(' '), dataset: { id: String(message.id) } },
    h(
      'button',
      {
        class: 'row-main',
        type: 'button',
        'aria-current': selected ? 'true' : null,
        onclick: () => setRoute({ id: message.id }),
      },
      h(
        'span',
        { class: 'row-top' },
        message.read ? null : h('span', { class: 'visually-hidden', text: 'Unread. ' }),
        h('span', { class: 'row-from', text: addressLabel(message.from) }),
        isAdmin() && state.view.kind !== 'inbox'
          ? h('span', {
              class: 'tag row-inbox',
              title: `In the ${message.inbox_name || message.inbox} inbox`,
              text: message.inbox_name || message.inbox,
            })
          : null,
        h('time', {
          class: 'row-time',
          datetime: new Date(message.received_at).toISOString(),
          title: fullTime(message.received_at),
          text: relativeTime(message.received_at),
        }),
      ),
      h('span', { class: 'row-subject', text: message.subject || '(no subject)' }),
      h('span', { class: 'row-snippet', text: message.snippet || ' ' }),
    ),
    h(
      'span',
      { class: 'row-marks' },
      message.attachment_count
        ? h(
            'span',
            { class: 'row-clip', title: plural(message.attachment_count, 'attachment') },
            icon('clip'),
            h('span', { class: 'visually-hidden', text: plural(message.attachment_count, 'attachment') }),
          )
        : null,
      h(
        'button',
        {
          class: `star${message.starred ? ' on' : ''}`,
          type: 'button',
          'aria-pressed': message.starred ? 'true' : 'false',
          'aria-label': message.starred ? 'Remove star' : 'Add star',
          title: message.starred ? 'Remove star' : 'Add star',
          onclick: () => toggleStar(message.id),
        },
        icon('star', message.starred ? 'filled' : ''),
      ),
    ),
  );
}

/** The parts of the list header that depend on the view rather than its messages. */
function renderListHead() {
  $('view-title').textContent = viewName();
  $('view-title').title = viewName();
  const connect = $('connect-open');
  connect.hidden = state.view.kind !== 'inbox';
  connect.setAttribute('aria-pressed', state.panel === 'connect' ? 'true' : 'false');
}

function renderList() {
  renderListHead();
  const counts = [];
  if (state.listLoaded) {
    counts.push(state.query ? `${state.total} ${state.total === 1 ? 'match' : 'matches'}` : String(state.total));
    if (state.unread) counts.push(`${state.unread} unread`);
  }
  $('view-count').textContent = counts.join(' · ');

  $('messages').replaceChildren(...state.messages.map(messageRow));

  const empty = $('list-empty');
  empty.hidden = !state.listLoaded || state.messages.length > 0;
  if (!empty.hidden) {
    empty.textContent = state.query
      ? 'Nothing matches that search.'
      : state.view.kind === 'starred'
        ? 'No starred messages. Press s on a message to star it.'
        : state.view.kind === 'inbox'
          ? 'Nothing has been delivered to this inbox yet. Connect, above, shows how to point an app at it.'
          : 'No messages yet.';
  }

  const remaining = state.total - state.messages.length;
  $('load-more').hidden = remaining <= 0 || state.messages.length === 0;
  $('load-more').textContent = `Load more (${remaining} older)`;

  // Both act on exactly what this view lists: its inbox, search and star filter.
  const what = state.query || state.view.kind === 'starred' ? 'listed' : 'all';
  for (const [id, label] of [['mark-read', `Mark ${what} read`], ['delete-all', `Delete ${what}`]]) {
    $(id).title = label;
    $(id).setAttribute('aria-label', label);
  }
  $('mark-read').disabled = state.unread === 0;
  $('delete-all').disabled = state.total === 0;
}

/** Cheaper than a full list render when only the selection moved. */
function renderSelection() {
  for (const row of document.querySelectorAll('#messages li')) {
    const selected = Number(row.dataset.id) === state.selectedId;
    row.classList.toggle('selected', selected);
    const main = row.querySelector('.row-main');
    if (selected) main.setAttribute('aria-current', 'true');
    else main.removeAttribute('aria-current');
  }
}

// ---------------------------------------------------------------------------
// Rendering: reader
// ---------------------------------------------------------------------------

function effectiveTab() {
  return state.tabPref === 'html' && state.detail && !state.detail.html ? 'text' : state.tabPref;
}

function addressList(addresses) {
  return addresses.map(addressFull).join(', ');
}

function metaRows(detail) {
  const rows = [];
  const add = (term, content, extraClass) =>
    rows.push(h('dt', { text: term }), h('dd', { class: extraClass || null }, content));

  add('From', detail.from ? addressFull(detail.from) : '(none)');
  if (detail.to.length) add('To', addressList(detail.to));
  if (detail.cc.length) add('Cc', addressList(detail.cc));
  if (detail.bcc.length) add('Bcc', addressList(detail.bcc));
  if (detail.reply_to.length) add('Reply-To', addressList(detail.reply_to));

  // Envelope recipients. One that appears in no header was a Bcc.
  const visible = new Set([...detail.to, ...detail.cc, ...detail.bcc].map((a) => a.address.toLowerCase()));
  const delivered = detail.recipients.flatMap((address, i) => [
    i ? ', ' : null,
    h(
      'button',
      {
        class: 'link',
        type: 'button',
        title: `Search for mail delivered to ${address}`,
        onclick: () => setRoute({ query: `to:${address}`, id: null }),
      },
      address,
    ),
    visible.has(address) ? null : h('span', { class: 'tag', title: 'Delivered to, but named in no header', text: 'bcc' }),
  ]);
  if (delivered.length) add('Delivered to', delivered);

  add(
    'Inbox',
    isAdmin() && state.view.kind !== 'inbox'
      ? h(
          'button',
          {
            class: 'link',
            type: 'button',
            title: `Open the ${detail.inbox_name || detail.inbox} inbox`,
            onclick: () => setRoute({ view: { kind: 'inbox', id: detail.inbox }, query: '', id: detail.id }),
          },
          detail.inbox_name || detail.inbox,
        )
      : detail.inbox_name || detail.inbox,
  );

  add(
    'Received',
    [
      fullTime(detail.received_at),
      h('span', { class: 'meta-aside', text: ` · via ${detail.source === 'api' ? 'API' : 'SMTP'} · ${formatSize(detail.size)}` }),
    ],
  );
  return rows;
}

function attachmentList(detail) {
  if (!detail.attachments.length) return null;
  return h(
    'ul',
    { class: 'attachments', 'aria-label': 'Attachments' },
    detail.attachments.map((attachment) => {
      const name = attachment.filename || `attachment-${attachment.index}`;
      return h(
        'li',
        null,
        h(
          'a',
          {
            class: 'attachment',
            href: `/api/v1/messages/${detail.id}/attachments/${attachment.index}`,
            download: name,
            title: `Download ${name}`,
          },
          icon('clip'),
          h('span', { class: 'attachment-name', text: name }),
          h('span', {
            class: 'attachment-meta',
            text: `${attachment.content_type} · ${formatSize(attachment.size)}${attachment.inline ? ' · inline' : ''}`,
          }),
          icon('download', 'attachment-download'),
        ),
      );
    }),
  );
}

function renderReaderActions() {
  const bar = $('reader-actions');
  const detail = state.detail;
  if (!bar || !detail) return;
  bar.replaceChildren(
    h(
      'button',
      {
        class: `icon-btn star${detail.starred ? ' on' : ''}`,
        type: 'button',
        'aria-pressed': detail.starred ? 'true' : 'false',
        'aria-label': detail.starred ? 'Remove star' : 'Add star',
        title: detail.starred ? 'Remove star (s)' : 'Add star (s)',
        onclick: () => toggleStar(detail.id),
      },
      icon('star', detail.starred ? 'filled' : ''),
    ),
    h(
      'button',
      {
        class: 'icon-btn',
        type: 'button',
        'aria-label': detail.read ? 'Mark unread' : 'Mark read',
        title: detail.read ? 'Mark unread (u)' : 'Mark read (u)',
        onclick: toggleUnread,
      },
      icon('mail', detail.read ? '' : 'accent'),
    ),
    h(
      'a',
      {
        class: 'icon-btn',
        href: `/api/v1/messages/${detail.id}/raw`,
        download: `message-${detail.id}.eml`,
        'aria-label': 'Download .eml',
        title: 'Download .eml',
      },
      icon('download'),
    ),
    h(
      'button',
      {
        class: 'icon-btn icon-btn-danger',
        type: 'button',
        'aria-label': 'Delete',
        title: 'Delete (#)',
        onclick: deleteSelected,
      },
      icon('trash'),
    ),
  );
}

function renderReader() {
  const root = $('reader');
  const back = h(
    'button',
    { class: 'icon-btn back-btn', type: 'button', 'aria-label': 'Back to messages', onclick: () => setRoute({ id: null }) },
    icon('back'),
  );

  if (state.panel === 'connect' && state.view.kind === 'inbox') {
    renderConnectPanel(root);
    return;
  }

  if (state.selectedId == null) {
    root.replaceChildren(
      h(
        'div',
        { class: 'reader-empty' },
        icon('mail', 'reader-empty-icon'),
        h('p', { text: 'Select a message to read it.' }),
        h(
          'p',
          { class: 'hint' },
          h('kbd', { text: 'j' }), ' ', h('kbd', { text: 'k' }), ' move · ',
          h('kbd', { text: 's' }), ' star · ',
          h('kbd', { text: 'u' }), ' unread · ',
          h('kbd', { text: '#' }), ' delete · ',
          h('kbd', { text: '/' }), ' search',
        ),
      ),
    );
    return;
  }

  const detail = state.detail;
  if (!detail) {
    root.replaceChildren(
      h('header', { class: 'reader-head' }, back),
      h('div', { class: 'reader-empty' }, h('p', { text: state.detailError || 'Loading…' })),
    );
    return;
  }

  const tab = effectiveTab();
  const tabs = [
    ['html', 'HTML', !detail.html],
    ['text', 'Text', false],
    ['headers', 'Headers', false],
    ['raw', 'Raw', false],
    ['links', 'Links', false],
    ['check', 'Check', false],
  ];
  const widths = [
    ['desktop', 'Desktop', 'Full width'],
    ['tablet', 'Tablet', '768 px wide'],
    ['phone', 'Phone', '375 px wide'],
  ];

  fill(
    root,
    h(
      'header',
      { class: 'reader-head' },
      back,
      h('h2', { class: 'reader-subject', text: detail.subject || '(no subject)' }),
      h('div', { id: 'reader-actions', class: 'reader-actions' }),
    ),
    h('dl', { class: 'meta' }, metaRows(detail)),
    attachmentList(detail),
    h(
      'div',
      { class: 'tabbar' },
      h(
        'div',
        { class: 'tabs', role: 'tablist', 'aria-label': 'Message views' },
        tabs.map(([key, label, disabled]) =>
          h('button', {
            class: 'tab',
            type: 'button',
            role: 'tab',
            id: `tab-${key}`,
            'aria-selected': key === tab ? 'true' : 'false',
            'aria-controls': 'reader-body',
            disabled,
            title: disabled ? 'This message has no HTML part' : null,
            text: label,
            onclick: () => {
              state.tabPref = key;
              renderReader();
            },
          }),
        ),
      ),
      tab === 'html'
        ? h(
            'div',
            { class: 'segmented', role: 'group', 'aria-label': 'Preview width' },
            widths.map(([key, label, title]) =>
              h('button', {
                class: 'segment',
                type: 'button',
                title,
                'aria-pressed': key === state.width ? 'true' : 'false',
                text: label,
                onclick: () => {
                  state.width = key;
                  for (const button of root.querySelectorAll('.segment')) {
                    button.setAttribute('aria-pressed', button.textContent === label ? 'true' : 'false');
                  }
                  root.querySelector('.frame-wrap').dataset.width = key;
                },
              }),
            ),
          )
        : null,
    ),
    h('div', { id: 'reader-body', class: 'reader-body', role: 'tabpanel', 'aria-labelledby': `tab-${tab}` }),
  );
  renderReaderActions();
  renderTab(tab);
}

function renderTab(tab) {
  const body = $('reader-body');
  const detail = state.detail;
  const note = (text) => h('p', { class: 'body-note', text });

  if (tab === 'html') {
    // No allow-scripts and no allow-same-origin: the email can neither run code
    // nor reach this page. The server sends the same policy as a header.
    const frame = h('iframe', {
      sandbox: 'allow-popups allow-popups-to-escape-sandbox',
      referrerpolicy: 'no-referrer',
      title: 'Message body',
      src: `/api/v1/messages/${detail.id}/html`,
    });
    body.replaceChildren(h('div', { class: 'frame-wrap', dataset: { width: state.width } }, frame));
  } else if (tab === 'text') {
    body.replaceChildren(
      detail.text != null ? h('pre', { class: 'plain', text: detail.text }) : note('This message has no plain-text part.'),
    );
  } else if (tab === 'headers') {
    body.replaceChildren(
      h(
        'table',
        { class: 'headers' },
        h(
          'tbody',
          null,
          detail.headers.map((header) =>
            h('tr', null, h('th', { scope: 'row', text: header.name }), h('td', { text: header.value })),
          ),
        ),
      ),
    );
  } else if (tab === 'raw') {
    if (state.raw && state.raw.id === detail.id) {
      const text = state.raw.text;
      fill(
        body,
        text.length > RAW_PREVIEW_CHARS
          ? note(`Showing the first ${formatSize(RAW_PREVIEW_CHARS)} of ${formatSize(text.length)}. Download the .eml for the rest.`)
          : null,
        h('pre', { class: 'plain source', text: text.slice(0, RAW_PREVIEW_CHARS) }),
      );
    } else {
      body.replaceChildren(note('Loading…'));
      const id = detail.id;
      api(`/api/v1/messages/${id}/raw`, { text: true })
        .then((text) => {
          if (state.detail?.id !== id) return;
          state.raw = { id, text };
          if (effectiveTab() === 'raw') renderTab('raw');
        })
        .catch(report);
    }
  } else if (tab === 'links') {
    if (state.links && state.links.id === detail.id) {
      const links = state.links.links;
      body.replaceChildren(
        links.length
          ? h(
              'ol',
              { class: 'links' },
              links.map((link) => {
                // Only schemes that cannot run script in this page become links.
                const safe = /^(https?:|mailto:)/i.test(link.url);
                return h(
                  'li',
                  null,
                  link.text ? h('span', { class: 'link-text', text: link.text }) : null,
                  safe
                    ? h('a', { href: link.url, target: '_blank', rel: 'noopener noreferrer', text: link.url })
                    : h('span', { text: link.url }),
                  navigator.clipboard
                    ? h(
                        'button',
                        { class: 'btn btn-quiet copy', type: 'button', onclick: (event) => copyText(link.url, event.currentTarget) },
                        icon('copy'),
                        h('span', { class: 'copy-label', text: 'Copy' }),
                      )
                    : null,
                );
              }),
            )
          : note('This message contains no links.'),
      );
    } else {
      body.replaceChildren(note('Loading…'));
      const id = detail.id;
      api(`/api/v1/messages/${id}/links`)
        .then((data) => {
          if (state.detail?.id !== id) return;
          state.links = { id, links: data.links };
          if (effectiveTab() === 'links') renderTab('links');
        })
        .catch(report);
    }
  } else if (tab === 'check') {
    const all = state.checkAll;
    if (state.check && state.check.id === detail.id && state.check.all === all) {
      body.replaceChildren(renderCheck(state.check.report, all));
    } else {
      body.replaceChildren(note('Checking…'));
      const id = detail.id;
      const clients = all ? '' : `?clients=${MAIN_CLIENTS.join(',')}`;
      api(`/api/v1/messages/${id}/check${clients}`)
        .then((data) => {
          if (state.detail?.id !== id) return;
          state.check = { id, all, report: data };
          if (effectiveTab() === 'check') renderTab('check');
        })
        .catch(report);
    }
  }
}

// The clients most mail is read in; the check starts with these.
const MAIN_CLIENTS = ['gmail', 'outlook', 'apple-mail', 'yahoo', 'samsung-email'];

// A dataset note arrives with its links flattened to "label (address)". Give
// the address back as a link, named by its host; when the label already is
// that host, the label becomes the link.
function noteContent(text) {
  const parts = text.split(/ ?\((https:\/\/[^\s()]+)\)/);
  const out = [];
  parts.forEach((part, i) => {
    if (i % 2 === 0) {
      out.push(part);
      return;
    }
    let host;
    try {
      host = new URL(part).hostname.replace(/^www\./, '');
    } catch {
      out.push(` (${part})`);
      return;
    }
    const link = h('a', { href: part, target: '_blank', rel: 'noopener noreferrer', title: part, text: host });
    const before = out[out.length - 1];
    if (typeof before === 'string' && before.endsWith(host)) {
      out[out.length - 1] = before.slice(0, -host.length);
      out.push(link);
    } else {
      out.push(' (', link, ')');
    }
  });
  return out.filter((part) => part !== '');
}

// Which email clients will render the message as written. Everything shown
// comes from the message or from the compatibility dataset, and goes in as
// text: feature titles such as "<video> element" are not markup.
function renderCheck(data, all) {
  const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;
  const clientLine = (client) => {
    const parts = [];
    if (client.unsupported.length) parts.push(`not supported on ${client.unsupported.join(', ')}`);
    if (client.partial.length) parts.push(`partly on ${client.partial.join(', ')}`);
    return h(
      'li',
      null,
      h('span', { class: 'check-client', text: client.name }),
      h('span', { class: 'check-where', text: parts.join('; ') }),
      client.notes.length
        ? h('ul', { class: 'check-notes' }, client.notes.map((text) => h('li', null, noteContent(text))))
        : null,
    );
  };
  const issue = (item) =>
    h(
      'li',
      { class: `check-issue check-${item.severity}` },
      h(
        'div',
        { class: 'check-issue-head' },
        // The link goes to the feature's page on caniemail.com.
        /^https:\/\//.test(item.url)
          ? h('a', { href: item.url, target: '_blank', rel: 'noopener noreferrer', text: item.title })
          : h('span', { text: item.title }),
        h('span', { class: 'check-count', text: `used ${plural(item.count, 'time')}` }),
      ),
      h('ul', { class: 'check-clients' }, item.clients.map(clientLine)),
    );
  const group = (title, severity, blurb) => {
    const items = data.issues.filter((item) => item.severity === severity);
    if (!items.length) return null;
    return h(
      'section',
      { class: 'check-group' },
      h('h3', { text: `${title} (${items.length})` }),
      h('p', { class: 'check-blurb', text: blurb }),
      h('ul', { class: 'check-issues' }, items.map(issue)),
    );
  };

  const scores = h(
    'ul',
    { class: 'check-scores' },
    data.clients.map((client) => {
      const total = client.supported + client.partial + client.unsupported + client.unknown;
      const status = client.unsupported ? 'bad' : client.partial ? 'warn' : 'ok';
      const detail = [];
      if (client.unsupported) detail.push(`${client.unsupported} unsupported`);
      if (client.partial) detail.push(`${client.partial} partial`);
      if (client.unknown) detail.push(`${client.unknown} unknown`);
      return h(
        'li',
        { class: `check-score check-score-${status}` },
        h('span', { class: 'check-score-name', text: client.name }),
        h('span', { class: 'check-score-num', text: `${client.supported} of ${total}` }),
        // Each count stays on one line; a narrow card wraps between them.
        h(
          'span',
          { class: 'check-score-detail' },
          detail.length
            ? detail.flatMap((part, i) => [i ? ', ' : null, h('span', { text: part })])
            : 'all supported',
        ),
      );
    }),
  );

  return h(
    'div',
    { class: 'check' },
    h(
      'p',
      { class: 'check-intro' },
      h('span', {
        text: data.features_found
          ? `This message uses ${plural(data.features_found, 'HTML and CSS feature')}. Below is how many of them each client supports, from caniemail.com data of ${data.data_updated}. It reads the markup; it is not a rendering.`
          : 'This message has no HTML to check.',
      }),
    ),
    data.features_found ? scores : null,
    h(
      'p',
      { class: 'check-toggle' },
      h(
        'button',
        {
          class: 'btn btn-quiet',
          type: 'button',
          onclick: () => {
            state.checkAll = !all;
            renderTab('check');
          },
        },
        h('span', { text: all ? 'Show the main clients only' : 'Check against every client' }),
      ),
    ),
    data.notices.length
      ? h(
          'section',
          { class: 'check-group' },
          h('h3', { text: 'Worth knowing' }),
          h('ul', { class: 'check-notices' }, data.notices.map((notice) => h('li', { text: notice.message }))),
        )
      : null,
    group('Not supported', 'unsupported', 'These do nothing at all in at least one of the main clients.'),
    group('Partly supported', 'partial', 'These work, with the caveats noted.'),
    data.features_found && !data.issues.length
      ? h('p', { class: 'body-note', text: 'Every feature this message uses is supported by these clients.' })
      : null,
  );
}

// ---------------------------------------------------------------------------
// Rendering: an inbox's Connect panel
// ---------------------------------------------------------------------------

function copyButton(text) {
  if (!navigator.clipboard) return null;
  return h(
    'button',
    { class: 'btn btn-quiet copy', type: 'button', onclick: (event) => copyText(text, event.currentTarget) },
    icon('copy'),
    h('span', { class: 'copy-label', text: 'Copy' }),
  );
}

function codeBlock(label, code) {
  return h(
    'figure',
    { class: 'code' },
    h('figcaption', null, h('span', { text: label }), copyButton(code)),
    h('pre', null, h('code', { text: code })),
  );
}

/** What an application needs in order to deliver into `inbox`, as snippets. */
function snippets(inbox, key) {
  const info = state.info;
  const { host, port } = smtpEndpoint();
  const env = ['MAIL_MAILER=smtp', `MAIL_HOST=${host}`, `MAIL_PORT=${port}`, `MAIL_USERNAME=${inbox}`, `MAIL_PASSWORD=${key}`];
  if (info.smtp_starttls) env.push('MAIL_SCHEME=smtp', 'MAIL_ENCRYPTION=tls');
  const curl = [
    `curl -X POST ${location.origin}/api/v1/messages \\`,
    `  -H 'Authorization: Bearer ${key}' \\`,
    "  -H 'Content-Type: application/json' \\",
    `  -d '{"from": "app@example.test", "to": "you@example.test", "subject": "Hello", "text": "It works."}'`,
  ].join('\n');
  const mcp = [
    `claude mcp add --transport http emailulator ${location.origin}/mcp \\`,
    `  --header "Authorization: Bearer ${key}"`,
  ].join('\n');
  return { env: env.join('\n'), curl, mcp };
}

function renderKeys() {
  const root = $('keys-list');
  if (!root) return;
  if (!state.keys || state.keys.inbox !== state.view.id) {
    root.replaceChildren(h('p', { class: 'hint', text: 'Loading…' }));
    return;
  }
  const keys = state.keys.list;
  const starter = keys.find((key) => key.key);
  // The starter key is the one key kept readable. Show it in full, and say why
  // it should be replaced before it travels.
  const starterBlock = starter
    ? h(
        'div',
        { class: 'starter-key' },
        h('p', { class: 'fresh-key-title', text: 'Starter key' }),
        h(
          'div',
          { class: 'fresh-key-row' },
          h('code', { class: 'fresh-key-value', text: starter.key }),
          copyButton(starter.key),
        ),
        h(
          'p',
          { class: 'fresh-key-note' },
          'Made for you when this server first started, and kept readable so it can be shown here. ' +
            'Before an app outside this machine uses it, ',
          h('button', { class: 'link-btn', type: 'button', onclick: () => regenerateKey(starter) }, 'regenerate it'),
          ': the new key is kept only as a hash and shown once.',
        ),
      )
    : null;
  if (!keys.length) {
    root.replaceChildren(
      h('p', {
        class: 'hint',
        text:
          state.view.id === DEFAULT_INBOX
            ? 'No keys. Mail sent without one still lands here; a key is only needed to sign an app in as this inbox.'
            : 'No keys yet. Until it has one, nothing can deliver into this inbox or read it by key.',
      }),
    );
    return;
  }
  fill(
    root,
    starterBlock,
    h(
      'table',
      { class: 'keys' },
      h(
        'thead',
        null,
        h(
          'tr',
          null,
          h('th', { scope: 'col', text: 'Label' }),
          h('th', { scope: 'col', text: 'Key' }),
          h('th', { scope: 'col', text: 'Created' }),
          h('th', { scope: 'col', text: 'Last used' }),
          h('th', { scope: 'col' }, h('span', { class: 'visually-hidden', text: 'Actions' })),
        ),
      ),
      h(
        'tbody',
        null,
        keys.map((key) =>
          h(
            'tr',
            null,
            h('th', { scope: 'row', text: key.label }),
            h('td', { class: 'key-prefix', text: `${key.prefix}…` }),
            h('td', { title: fullTime(key.created_at), text: relativeTime(key.created_at) }),
            h('td', {
              title: key.last_used_at ? fullTime(key.last_used_at) : null,
              text: key.last_used_at ? relativeTime(key.last_used_at) : 'never',
            }),
            h(
              'td',
              { class: 'key-actions' },
              h('button', { class: 'btn btn-quiet', type: 'button', onclick: () => regenerateKey(key) }, 'Regenerate'),
              h('button', { class: 'btn btn-quiet btn-quiet-danger', type: 'button', onclick: () => revokeKey(key) }, 'Revoke'),
            ),
          ),
        ),
      ),
    ),
  );
}

function renderConnectPanel(root) {
  const id = state.view.id;
  const info = state.info;
  const admin = isAdmin();
  const isDefault = id === DEFAULT_INBOX;
  const { host, port } = smtpEndpoint();
  const inbox = state.inboxes.find((candidate) => candidate.id === id);
  const fresh = freshKey && freshKey.inbox === id ? freshKey : null;
  const close = () => setRoute({ panel: null });

  const lead = isDefault
    ? `Mail that arrives without an inbox key lands here. ${
        info.smtp_auth_required
          ? 'This server requires a key over SMTP, so an app reaches this inbox the same way as any other: its id and one of its keys.'
          : 'An app on this server can send here with no username or password at all; with this inbox’s id and a key it lands here just the same.'
      }`
    : 'Give the app whose mail belongs here this inbox’s ID and one of its API keys. The same key reads the inbox back over the API and MCP, and nothing else.';

  const fact = (term, value, mono) => [h('dt', { text: term }), h('dd', { class: mono ? 'mono' : null, text: value })];

  fill(
    root,
    h(
      'header',
      { class: 'reader-head panel-head' },
      h('button', { class: 'icon-btn back-btn', type: 'button', 'aria-label': 'Back to messages', onclick: close }, icon('back')),
      h('h2', { class: 'reader-subject', text: `Connect to ${inbox ? inbox.name : id}` }),
      h(
        'div',
        { class: 'reader-actions' },
        h('button', { class: 'icon-btn', type: 'button', 'aria-label': 'Close', title: 'Close (Esc)', onclick: close }, icon('close')),
      ),
    ),
    h(
      'div',
      { class: 'panel' },
      inbox && inbox.description ? h('p', { class: 'panel-description', text: inbox.description }) : null,
      h('p', { class: 'panel-lead', text: lead }),
      h(
        'dl',
        { class: 'facts' },
        ...fact('SMTP host', host, true),
        ...fact('SMTP port', String(port), true),
        ...fact('Inbox ID', id, true),
        ...fact('Username', 'the inbox ID'),
        ...fact(
          'Password',
          fresh ? 'the new key below' : admin ? 'one of this inbox’s API keys' : 'this inbox’s API key, the one you signed in with',
        ),
        ...fact('Encryption', info.smtp_starttls ? 'STARTTLS' : 'none'),
        ...fact('API', 'Authorization: Bearer <API key>', true),
        ...fact('MCP', `${location.origin}/mcp`, true),
      ),

      admin
        ? h(
            'section',
            { class: 'panel-section', 'aria-labelledby': 'keys-title' },
            h('h3', { id: 'keys-title', text: 'API keys' }),
            fresh
              ? h(
                  'div',
                  { class: 'fresh-key', role: 'status' },
                  h('p', { class: 'fresh-key-title' }, 'New key', fresh.label ? ` “${fresh.label}”` : ''),
                  h(
                    'div',
                    { class: 'fresh-key-row' },
                    h('code', { class: 'fresh-key-value', id: 'fresh-key-value', text: fresh.key }),
                    copyButton(fresh.key),
                  ),
                  h('p', {
                    class: 'fresh-key-note',
                    text: 'Copy it now. Only a hash of it is kept, so it will not be shown again — not here, not anywhere.',
                  }),
                )
              : null,
            h('div', { id: 'keys-list' }),
            h(
              'form',
              { class: 'key-form', onsubmit: createKey },
              h('label', { class: 'visually-hidden', for: 'key-label', text: 'Label for the new key' }),
              h('input', {
                id: 'key-label',
                class: 'field',
                type: 'text',
                maxlength: '80',
                autocomplete: 'off',
                placeholder: 'Label, e.g. staging app (optional)',
              }),
              h('button', { class: 'btn btn-primary', type: 'submit' }, icon('key'), 'Create key'),
            ),
          )
        : h('p', {
            class: 'hint panel-note',
            text: 'You are signed in with one of this inbox’s API keys. Creating and revoking keys takes the admin token.',
          }),

      h('section', { id: 'snippets', class: 'panel-section', 'aria-labelledby': 'snippets-title' }),

      admin && !isDefault
        ? h(
            'section',
            { class: 'panel-section danger-zone', 'aria-labelledby': 'danger-title' },
            h('h3', { id: 'danger-title', text: 'Delete this inbox' }),
            h('p', { class: 'hint', text: 'Removes the inbox with every message in it and all of its keys.' }),
            h('button', { class: 'btn btn-danger-outline', type: 'button', onclick: deleteInbox }, icon('trash'), 'Delete inbox'),
          )
        : null,
    ),
  );
  renderKeys();
  renderSnippets();
}

/** The connect panel's snippets, filled with a key when one can be shown. */
function renderSnippets() {
  const root = $('snippets');
  if (!root) return;
  const id = state.view.id;
  const fresh = freshKey && freshKey.inbox === id ? freshKey : null;
  const starter =
    state.keys && state.keys.inbox === id ? state.keys.list.find((key) => key.key) : null;
  const key = fresh ? fresh.key : starter ? starter.key : null;
  const { env, curl, mcp } = snippets(id, key || '<API key>');
  fill(
    root,
    h('h3', { id: 'snippets-title', text: 'Paste into your app' }),
    key
      ? starter && !fresh
        ? h('p', { class: 'hint', text: 'These use the starter key.' })
        : null
      : h('p', { class: 'hint', text: 'Replace <API key> with a key. A key is shown in full only when it is created.' }),
    codeBlock('Laravel .env', env),
    codeBlock('Send over HTTP', curl),
    codeBlock('Give an agent this inbox (Claude Code)', mcp),
  );
}

// ---------------------------------------------------------------------------
// Rendering: first-run welcome
// ---------------------------------------------------------------------------

function renderWelcome() {
  const info = state.info;
  const { host, port } = smtpEndpoint();
  // In an inbox, show how to reach that inbox; otherwise the keyless way in.
  const inbox = state.view.kind === 'inbox' ? state.view.id : isAdmin() ? null : state.ownInbox;
  const keyed = inbox != null && (inbox !== DEFAULT_INBOX || info.smtp_auth_required || !isAdmin());

  let env;
  let curl;
  if (keyed) {
    ({ env, curl } = snippets(inbox, '<API key>'));
  } else {
    const lines = ['MAIL_MAILER=smtp', `MAIL_HOST=${host}`, `MAIL_PORT=${port}`];
    if (info.smtp_auth_required) lines.push('MAIL_USERNAME=<inbox id>', 'MAIL_PASSWORD=<API key>');
    else lines.push('MAIL_USERNAME=null', 'MAIL_PASSWORD=null');
    if (info.smtp_starttls) lines.push('MAIL_SCHEME=smtp', 'MAIL_ENCRYPTION=tls');
    env = lines.join('\n');
    curl = [
      `curl -X POST ${location.origin}/api/v1/messages \\`,
      info.auth_required ? "  -H 'Authorization: Bearer <admin token or API key>' \\" : null,
      "  -H 'Content-Type: application/json' \\",
      `  -d '{"from": "app@example.test", "to": "you@example.test", "subject": "Hello", "text": "It works."}'`,
    ]
      .filter(Boolean)
      .join('\n');
  }

  const login = keyed
    ? `username ${inbox}, password one of its API keys`
    : info.smtp_auth_required
      ? 'an inbox id as username, one of its API keys as password'
      : 'not needed — mail without a key lands in the default inbox';

  $('welcome').replaceChildren(
    h(
      'div',
      { class: 'welcome-inner' },
      h('h2', { text: keyed ? `Waiting for mail in ${inboxName(inbox)}` : 'Waiting for the first email' }),
      h('p', {
        class: 'welcome-lead',
        text: 'Point your application at this server and whatever it sends shows up here. Nothing is ever delivered onward.',
      }),
      h(
        'dl',
        { class: 'welcome-facts' },
        h('dt', { text: 'SMTP host' }), h('dd', { text: host }),
        h('dt', { text: 'SMTP port' }), h('dd', { text: String(port) }),
        h('dt', { text: 'Login' }), h('dd', { text: login }),
        h('dt', { text: 'Encryption' }), h('dd', { text: info.smtp_starttls ? 'STARTTLS' : 'none' }),
      ),
      inbox != null
        ? h(
            'p',
            { class: 'welcome-action' },
            h(
              'button',
              { class: 'btn', type: 'button', onclick: () => setRoute({ view: { kind: 'inbox', id: inbox }, panel: 'connect' }) },
              icon('key'),
              isAdmin() ? 'Connection details and API keys' : 'Connection details',
            ),
          )
        : isAdmin()
          ? h('p', {
              class: 'hint welcome-action',
              text: 'To keep each app’s mail apart, create an inbox for it in the sidebar and give the app that inbox’s key.',
            })
          : null,
      codeBlock('Laravel .env', env),
      codeBlock('Or send over HTTP', curl),
      h('p', { class: 'hint', text: 'This page updates by itself when mail arrives.' }),
    ),
  );
}

let welcomeFor = null;

function renderEmptiness() {
  // The welcome stands in for an empty server's home view. An inbox someone
  // opened keeps the list and its header, where Connect is, even while it is
  // empty; and it never stands in for an open panel.
  const fresh =
    state.statsLoaded &&
    state.stats.total === 0 &&
    !state.query &&
    !state.panel &&
    state.view.kind !== 'inbox';
  const main = $('main');
  const key = fresh ? viewKey(state.view) : null;
  if (fresh === main.classList.contains('is-fresh') && key === welcomeFor) return;
  welcomeFor = key;
  main.classList.toggle('is-fresh', fresh);
  $('welcome').hidden = !fresh;
  if (fresh && state.info) renderWelcome();
}

// ---------------------------------------------------------------------------
// Live updates
// ---------------------------------------------------------------------------

function handleEvent(event) {
  switch (event.type) {
    case 'deleted':
      if (event.id === state.selectedId) {
        state.messages = state.messages.filter((m) => m.id !== event.id);
        setRoute({ id: null }, { replace: true });
      }
      break;
    case 'inboxes':
      // A key was added or revoked, or an inbox came or went.
      if (state.panel === 'connect') loadKeys();
      break;
    case 'new':
      // Mail arriving in the open inbox was sent with one of its keys; show the use.
      if (state.panel === 'connect' && event.message?.inbox === state.view.id) loadKeys();
      break;
    case 'cleared':
    case 'resync':
      // The open message may be gone; asking for it again settles that.
      if (state.selectedId != null) recheckDetail();
      break;
    default:
      break;
  }
  scheduleRefresh();
}

async function recheckDetail() {
  const id = state.selectedId;
  try {
    await api(`/api/v1/messages/${id}`);
  } catch (error) {
    if (error.status === 404 && state.selectedId === id) setRoute({ id: null }, { replace: true });
  }
}

function closeEvents() {
  clearTimeout(reconnectTimer);
  if (events) events.close();
  events = null;
}

function connectEvents() {
  closeEvents();
  setLive(everConnected ? 'offline' : 'connecting');
  const source = new EventSource('/api/v1/events');
  events = source;
  source.onopen = () => {
    setLive('live');
    // Anything could have happened while the stream was down.
    if (everConnected) {
      scheduleRefresh();
      if (state.selectedId != null) recheckDetail();
    }
    everConnected = true;
  };
  source.onmessage = (message) => {
    try {
      handleEvent(JSON.parse(message.data));
    } catch {
      // A malformed event is not worth breaking the stream over.
    }
  };
  source.onerror = () => {
    if (events !== source) return;
    setLive('offline');
    // The browser retries by itself unless the server refused outright, which
    // is what an expired session looks like. Check, then try again.
    if (source.readyState === EventSource.CLOSED) {
      events = null;
      reconnectTimer = setTimeout(async () => {
        try {
          const session = await api('/api/v1/session');
          if (session.auth_required && !session.authenticated) return showLogin();
        } catch {
          // Still unreachable; keep trying.
        }
        if ($('login').hidden) connectEvents();
      }, 3000);
    }
  };
}

// ---------------------------------------------------------------------------
// Sign-in
// ---------------------------------------------------------------------------

function showLogin() {
  closeEvents();
  clearTimeout(refreshTimer);
  settleConfirm?.(false);
  closeNewInbox();
  freshKey = null;
  state.keys = null;
  $('app').hidden = true;
  $('login').hidden = false;
  $('token').value = '';
  $('token').focus();
}

async function submitLogin(event) {
  event.preventDefault();
  const error = $('login-error');
  const submit = $('login-submit');
  error.hidden = true;
  submit.disabled = true;
  try {
    await api('/api/v1/session', { method: 'POST', body: { token: $('token').value } });
    $('token').value = '';
    await start();
  } catch (failure) {
    error.textContent =
      failure.status === 401 ? 'That is neither the admin token nor an inbox API key.' : failure.message;
    error.hidden = false;
    $('token').select();
  } finally {
    submit.disabled = false;
  }
}

async function signOut() {
  try {
    await api('/api/v1/session', { method: 'DELETE' });
  } catch (error) {
    return report(error);
  }
  state.messages = [];
  state.inboxes = [];
  state.inboxesLoaded = false;
  state.detail = null;
  $('messages').replaceChildren();
  $('reader').replaceChildren();
  $('nav-inboxes').replaceChildren();
  // The next sign-in may be a different inbox, or none; start from its home.
  history.replaceState(null, '', location.pathname);
  showLogin();
}

// ---------------------------------------------------------------------------
// Chrome: drawer, keyboard, wiring
// ---------------------------------------------------------------------------

function isSinglePane() {
  return window.matchMedia('(max-width: 720px)').matches;
}

function openDrawer() {
  document.body.classList.add('drawer-open');
  $('scrim').hidden = false;
}

function closeDrawer() {
  document.body.classList.remove('drawer-open');
  $('scrim').hidden = true;
}

function setQuery(query, { replace = true } = {}) {
  setRoute({ query, id: null }, { replace });
}

function onKeydown(event) {
  if (event.defaultPrevented || event.metaKey || event.ctrlKey || event.altKey) return;
  if ($('confirm').open || $('app').hidden) return;
  const target = event.target;
  const typing =
    target instanceof HTMLElement &&
    (target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName));
  if (typing) {
    if (event.key === 'Escape' && target.id === 'search') {
      event.preventDefault();
      clearTimeout(searchTimer);
      target.value = '';
      if (state.query) setQuery('');
      target.blur();
    } else if (event.key === 'Escape' && target.closest('dialog')) {
      // The dialog closes itself on Escape; blurring first would eat the key.
    } else if (event.key === 'Escape') {
      target.blur();
    }
    return;
  }
  switch (event.key) {
    case 'j':
      moveSelection(1);
      break;
    case 'k':
      moveSelection(-1);
      break;
    case 's':
      toggleStar();
      break;
    case 'u':
      toggleUnread();
      break;
    case '#':
    case 'Delete':
      deleteSelected();
      break;
    case '/':
      $('search').focus();
      $('search').select();
      break;
    case 'Escape':
      if (document.body.classList.contains('drawer-open')) closeDrawer();
      else if (state.panel) setRoute({ panel: null });
      else if (state.query) {
        $('search').value = '';
        setQuery('');
      } else return;
      break;
    default:
      return;
  }
  event.preventDefault();
}

function bind() {
  $('menu').append(icon('menu'));
  $('mark-read').append(icon('check'));
  $('delete-all').append(icon('trash'));
  $('new-inbox').append(icon('plus'));
  $('connect-open').append(icon('key'), 'Connect');

  $('menu').addEventListener('click', openDrawer);
  $('scrim').addEventListener('click', closeDrawer);
  $('mark-read').addEventListener('click', markAllRead);
  $('delete-all').addEventListener('click', deleteAll);
  $('load-more').addEventListener('click', loadMore);
  $('sign-out').addEventListener('click', signOut);
  $('login-form').addEventListener('submit', submitLogin);
  $('confirm-ok').addEventListener('click', () => settleConfirm?.(true));
  $('confirm-cancel').addEventListener('click', () => settleConfirm?.(false));
  // Escape. Fired before the dialog closes, unlike `close`.
  $('confirm').addEventListener('cancel', (event) => {
    event.preventDefault();
    settleConfirm?.(false);
  });

  $('search').addEventListener('input', (event) => {
    const value = event.target.value.trim();
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      if (value !== state.query) setQuery(value);
    }, 250);
  });
  $('inbox-filter').addEventListener('input', (event) => {
    state.inboxFilter = event.target.value;
    renderSidebar();
  });
  $('new-inbox').addEventListener('click', openNewInbox);
  $('new-inbox-form').addEventListener('submit', createInbox);
  $('new-inbox-cancel').addEventListener('click', closeNewInbox);
  // Escape, or anything else that dismisses the dialog: forget the key too.
  $('new-inbox-dialog').addEventListener('close', closeNewInbox);
  $('new-inbox-name').addEventListener('input', () => {
    $('new-inbox-error').hidden = true;
    clearTimeout(draftTimer);
    draftTimer = setTimeout(suggestInboxId, 150);
  });
  $('connect-open').addEventListener('click', () => setRoute({ panel: state.panel === 'connect' ? null : 'connect' }));

  document.addEventListener('keydown', onKeydown);
  window.addEventListener('hashchange', () => applyRoute());
  window.addEventListener('popstate', () => applyRoute());
  // Relative times go stale on a page left open.
  setInterval(() => {
    if (!$('app').hidden && !document.hidden) renderList();
  }, 60_000);
}

async function start() {
  $('login').hidden = true;
  $('app').hidden = false;
  state.info = await api('/api/v1/info');
  // Who this session is: the admin, or one inbox's key.
  state.access = state.info.access === 'inbox' ? 'inbox' : 'admin';
  state.ownInbox = state.info.inbox;
  state.stats = state.info.stats;
  state.statsLoaded = true;
  state.inboxes = [];
  state.inboxesLoaded = false;
  closeNewInbox();
  renderServer();
  renderSidebar();
  $('main').classList.remove('is-fresh');
  $('welcome').hidden = true;
  welcomeFor = null;
  applyRoute(true);
  renderEmptiness();
  loadInboxes();
  everConnected = false;
  connectEvents();
}

// The two panes beside the reader can be resized by dragging their right edge,
// or with the arrow keys on the handle; a double-click restores the default.
// Each width is kept in this browser only, and is clamped so the reader always
// keeps room to read in.
const PANES = {
  sidebar: { property: '--sidebar-width', initial: 232, min: 180, max: 400 },
  list: { property: '--list-width', initial: 360, min: 260, max: 640 },
};
const READER_MIN = 400;

function paneStore(name, width) {
  const key = `emailulator.pane.${name}`;
  try {
    if (width === undefined) return Number(localStorage.getItem(key)) || null;
    if (width === null) localStorage.removeItem(key);
    else localStorage.setItem(key, String(width));
  } catch {
    // Storage blocked or unavailable: widths last for this visit only.
  }
  return null;
}

function paneWidth(name) {
  const value = getComputedStyle(document.documentElement).getPropertyValue(PANES[name].property);
  return parseFloat(value) || PANES[name].initial;
}

function paneMax(name) {
  const pane = PANES[name];
  const other = name === 'sidebar' ? paneWidth('list') : paneWidth('sidebar');
  return Math.max(pane.min, Math.min(pane.max, window.innerWidth - other - READER_MIN));
}

function setPaneWidth(name, width) {
  const pane = PANES[name];
  const clamped = Math.round(Math.min(Math.max(width, pane.min), paneMax(name)));
  document.documentElement.style.setProperty(pane.property, `${clamped}px`);
  const handle = document.querySelector(`.resizer[data-resize="${name}"]`);
  if (handle) {
    handle.setAttribute('aria-valuenow', String(clamped));
    handle.setAttribute('aria-valuemin', String(pane.min));
    handle.setAttribute('aria-valuemax', String(paneMax(name)));
  }
  return clamped;
}

function bindResizers() {
  for (const name of Object.keys(PANES)) setPaneWidth(name, paneStore(name) ?? PANES[name].initial);

  for (const handle of document.querySelectorAll('.resizer')) {
    const name = handle.dataset.resize;
    const pane = handle.parentElement;

    handle.addEventListener('pointerdown', (event) => {
      if (event.button !== 0) return;
      event.preventDefault();
      handle.setPointerCapture(event.pointerId);
      handle.classList.add('is-active');
      document.body.classList.add('is-resizing');
      const left = pane.getBoundingClientRect().left;
      const move = (moved) => setPaneWidth(name, moved.clientX - left);
      const end = () => {
        handle.removeEventListener('pointermove', move);
        handle.classList.remove('is-active');
        document.body.classList.remove('is-resizing');
        paneStore(name, paneWidth(name));
      };
      handle.addEventListener('pointermove', move);
      handle.addEventListener('lostpointercapture', end, { once: true });
    });

    handle.addEventListener('dblclick', () => {
      setPaneWidth(name, PANES[name].initial);
      paneStore(name, null);
    });

    handle.addEventListener('keydown', (event) => {
      const step = event.shiftKey ? 48 : 16;
      const width = paneWidth(name);
      let next;
      if (event.key === 'ArrowLeft') next = width - step;
      else if (event.key === 'ArrowRight') next = width + step;
      else if (event.key === 'Home') next = PANES[name].min;
      else if (event.key === 'End') next = paneMax(name);
      else return;
      event.preventDefault();
      // The global shortcuts must not also see these keys.
      event.stopPropagation();
      paneStore(name, setPaneWidth(name, next));
    });
  }

  // A smaller window takes room from the panes before the reader; a larger one
  // gives them back the width that was chosen.
  window.addEventListener('resize', () => {
    for (const name of Object.keys(PANES)) setPaneWidth(name, paneStore(name) ?? PANES[name].initial);
  });
}

async function boot() {
  bindResizers();
  bind();
  try {
    const session = await api('/api/v1/session');
    if (session.auth_required && !session.authenticated) return showLogin();
    await start();
  } catch (error) {
    if (error.status === 401) return;
    $('app').hidden = false;
    toast(`${error.message} Retrying…`);
    setTimeout(() => location.reload(), 5000);
  }
}

boot();
