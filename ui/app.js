// emailulator web UI.
//
// Everything that comes out of an email — subjects, names, addresses, snippets,
// headers, filenames, link text — is attacker-controlled. It only ever enters the
// page as a text node or an attribute value through h() below, never as markup,
// and the HTML body is shown in a sandboxed frame that cannot run script.

const PAGE = 50;
const MAX_PAGE = 500; // the API's own ceiling
const RAW_PREVIEW_CHARS = 500_000;
const MANY_MAILBOXES = 8;
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
  mailboxes: [],
  stats: { total: 0, unread: 0, starred: 0, bytes: 0 },
  statsLoaded: false,
  view: { kind: 'all' }, // or {kind: 'starred'} or {kind: 'box', address}
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
  mailboxFilter: '',
};

let listSeq = 0;
let detailSeq = 0;
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

function viewKey(view) {
  return view.kind === 'box' ? `box:${view.address}` : view.kind;
}

function parseHash() {
  const raw = location.hash.replace(/^#\/?/, '');
  const [path, search = ''] = raw.split('?');
  const [viewPart = '', idPart] = path.split('/');
  let view = { kind: 'all' };
  if (viewPart === 'starred') {
    view = { kind: 'starred' };
  } else if (viewPart.startsWith('box:')) {
    try {
      const address = decodeURIComponent(viewPart.slice(4));
      if (address) view = { kind: 'box', address };
    } catch {
      // A mangled link falls back to all mail.
    }
  }
  const id = /^\d+$/.test(idPart || '') ? Number(idPart) : null;
  return { view, id, query: new URLSearchParams(search).get('q') || '' };
}

function formatHash({ view, id, query }) {
  let hash = '#/' + (view.kind === 'box' ? `box:${encodeURIComponent(view.address)}` : view.kind);
  if (id != null) hash += `/${id}`;
  if (query) hash += `?q=${encodeURIComponent(query)}`;
  return hash;
}

/** Move to a new route. Unspecified parts keep their current value. */
function setRoute(change, { replace = false } = {}) {
  const next = {
    view: change.view ?? state.view,
    id: change.id !== undefined ? change.id : state.selectedId,
    query: change.query ?? state.query,
  };
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
  state.view = route.view;
  state.query = route.query;
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
  if (force || route.id !== state.selectedId) {
    loadDetail(route.id);
  }
  closeDrawer();
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

function listParams() {
  const params = new URLSearchParams();
  if (state.view.kind === 'box') params.set('mailbox', state.view.address);
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

async function loadMailboxes() {
  try {
    const data = await api('/api/v1/mailboxes');
    state.mailboxes = data.mailboxes;
    state.stats = data.stats;
    state.statsLoaded = true;
    renderSidebar();
    renderEmptiness();
  } catch (error) {
    report(error);
  }
}

async function loadDetail(id) {
  const seq = ++detailSeq;
  state.selectedId = id;
  state.detail = null;
  state.detailError = null;
  state.raw = null;
  state.links = null;
  document.body.dataset.pane = id == null ? 'list' : 'reader';
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
    loadMailboxes();
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

function viewName() {
  if (state.view.kind === 'box') return state.view.address;
  return state.view.kind === 'starred' ? 'Starred' : 'All mail';
}

async function markAllRead() {
  const mailbox = state.view.kind === 'box' ? `?mailbox=${encodeURIComponent(state.view.address)}` : '';
  try {
    await api(`/api/v1/messages${mailbox}`, { method: 'PATCH', body: { read: true } });
  } catch (error) {
    report(error);
  }
  scheduleRefresh();
}

async function deleteAll() {
  const inBox = state.view.kind === 'box';
  const confirmed = await confirmAction({
    title: inBox ? `Delete everything in ${state.view.address}?` : 'Delete all mail?',
    body: `${plural(state.total, 'message')} will be deleted for good${
      inBox ? ', including copies that were also delivered to other mailboxes' : ''
    }.`,
    action: inBox ? 'Delete mailbox contents' : 'Delete all',
    focusAction: false,
  });
  if (!confirmed) return;
  const mailbox = inBox ? `?mailbox=${encodeURIComponent(state.view.address)}` : '';
  try {
    await api(`/api/v1/messages${mailbox}`, { method: 'DELETE' });
    setRoute({ id: null }, { replace: true });
  } catch (error) {
    report(error);
  }
  scheduleRefresh();
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
  const { stats, mailboxes } = state;
  $('nav-fixed').replaceChildren(
    navItem({ view: { kind: 'all' }, label: 'All mail', iconName: 'inbox', badge: stats.unread, count: stats.total }),
    navItem({ view: { kind: 'starred' }, label: 'Starred', iconName: 'star', count: stats.starred }),
  );

  const filterField = $('mailbox-filter');
  filterField.hidden = mailboxes.length <= MANY_MAILBOXES;
  if (filterField.hidden && state.mailboxFilter) {
    state.mailboxFilter = '';
    filterField.value = '';
  }
  const needle = state.mailboxFilter.trim().toLowerCase();
  const shown = mailboxes.filter((box) => !needle || box.address.includes(needle));
  // A mailbox that is open but has since emptied still needs its entry.
  if (state.view.kind === 'box' && !mailboxes.some((box) => box.address === state.view.address)) {
    shown.unshift({ address: state.view.address, total: 0, unread: 0 });
  }
  $('nav-mailboxes').replaceChildren(
    ...shown.map((box) =>
      navItem({
        view: { kind: 'box', address: box.address },
        label: box.address,
        title: box.address,
        iconName: 'at',
        badge: box.unread,
        count: box.total,
      }),
    ),
  );
  $('mailbox-count').textContent = mailboxes.length ? String(mailboxes.length) : '';
  const empty = $('nav-empty');
  empty.hidden = shown.length > 0;
  empty.textContent = mailboxes.length
    ? 'No mailbox matches that filter.'
    : 'Every address that receives mail gets its own mailbox here.';
}

function smtpEndpoint() {
  return { host: location.hostname, port: state.info ? state.info.smtp_port : 1025 };
}

function renderConnect() {
  const info = state.info;
  if (!info) return;
  const { host, port } = smtpEndpoint();
  const row = (term, value) => [h('dt', { text: term }), h('dd', { text: value })];
  $('connect-info').replaceChildren(
    ...row('SMTP', `${host}:${port}`),
    ...row('Login', info.smtp_auth_required ? 'required' : 'none (any is accepted)'),
    ...row('STARTTLS', info.smtp_starttls ? 'offered' : 'off'),
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

function renderList() {
  $('view-title').textContent = viewName();
  $('view-title').title = viewName();
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
        : state.view.kind === 'box'
          ? 'Nothing has been delivered to this address.'
          : 'No messages yet.';
  }

  const remaining = state.total - state.messages.length;
  $('load-more').hidden = remaining <= 0 || state.messages.length === 0;
  $('load-more').textContent = `Load more (${remaining} older)`;

  // The API clears and marks read by mailbox, not by search or star.
  const bulk = !state.query && state.view.kind !== 'starred';
  $('mark-read').hidden = !bulk;
  $('delete-all').hidden = !bulk;
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
  const delivered = detail.mailboxes.flatMap((address, i) => [
    i ? ', ' : null,
    h(
      'button',
      {
        class: 'link',
        type: 'button',
        title: `Open the ${address} mailbox`,
        onclick: () => setRoute({ view: { kind: 'box', address }, query: '' }),
      },
      address,
    ),
    visible.has(address) ? null : h('span', { class: 'tag', title: 'Delivered to, but named in no header', text: 'bcc' }),
  ]);
  if (delivered.length) add('Delivered to', delivered);

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
  }
}

// ---------------------------------------------------------------------------
// Rendering: first-run welcome
// ---------------------------------------------------------------------------

function codeBlock(label, code) {
  return h(
    'figure',
    { class: 'code' },
    h(
      'figcaption',
      null,
      h('span', { text: label }),
      navigator.clipboard
        ? h(
            'button',
            { class: 'btn btn-quiet copy', type: 'button', onclick: (event) => copyText(code, event.currentTarget) },
            icon('copy'),
            h('span', { class: 'copy-label', text: 'Copy' }),
          )
        : null,
    ),
    h('pre', null, h('code', { text: code })),
  );
}

function renderWelcome() {
  const info = state.info;
  const { host, port } = smtpEndpoint();
  const env = ['MAIL_MAILER=smtp', `MAIL_HOST=${host}`, `MAIL_PORT=${port}`];
  if (info.smtp_auth_required) env.push('MAIL_USERNAME=<smtp user>', 'MAIL_PASSWORD=<smtp password>');
  else env.push('MAIL_USERNAME=null', 'MAIL_PASSWORD=null');
  if (info.smtp_starttls) env.push('MAIL_SCHEME=smtp', 'MAIL_ENCRYPTION=tls');

  const curl = [
    `curl -X POST ${location.origin}/api/v1/messages \\`,
    info.auth_required ? "  -H 'Authorization: Bearer <auth token>' \\" : null,
    "  -H 'Content-Type: application/json' \\",
    `  -d '{"from": "app@example.test", "to": "you@example.test", "subject": "Hello", "text": "It works."}'`,
  ]
    .filter(Boolean)
    .join('\n');

  $('welcome').replaceChildren(
    h(
      'div',
      { class: 'welcome-inner' },
      h('h2', { text: 'Waiting for the first email' }),
      h('p', {
        class: 'welcome-lead',
        text: 'Point your application at this server and whatever it sends shows up here. Nothing is ever delivered onward.',
      }),
      h(
        'dl',
        { class: 'welcome-facts' },
        h('dt', { text: 'SMTP host' }), h('dd', { text: host }),
        h('dt', { text: 'SMTP port' }), h('dd', { text: String(port) }),
        h('dt', { text: 'Login' }), h('dd', { text: info.smtp_auth_required ? 'required' : 'not needed — any username and password is accepted' }),
        h('dt', { text: 'Encryption' }), h('dd', { text: info.smtp_starttls ? 'STARTTLS' : 'none' }),
      ),
      codeBlock('Laravel .env', env.join('\n')),
      codeBlock('Or send over HTTP', curl),
      h('p', { class: 'hint', text: 'This page updates by itself when mail arrives.' }),
    ),
  );
}

function renderEmptiness() {
  const fresh = state.statsLoaded && state.stats.total === 0 && !state.query;
  const main = $('main');
  if (fresh === main.classList.contains('is-fresh')) return;
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
    error.textContent = failure.status === 401 ? 'That token is not right.' : failure.message;
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
  state.mailboxes = [];
  state.detail = null;
  $('messages').replaceChildren();
  $('reader').replaceChildren();
  $('nav-mailboxes').replaceChildren();
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
  $('mailbox-filter').addEventListener('input', (event) => {
    state.mailboxFilter = event.target.value;
    renderSidebar();
  });

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
  state.stats = state.info.stats;
  state.statsLoaded = true;
  renderConnect();
  renderSidebar();
  $('main').classList.remove('is-fresh');
  $('welcome').hidden = true;
  renderEmptiness();
  applyRoute(true);
  loadMailboxes();
  everConnected = false;
  connectEvents();
}

async function boot() {
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
