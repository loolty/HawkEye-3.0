/* Small UI behaviours that used to be inline onchange/onsubmit attributes
   (inline handlers are blocked by the site's Content-Security-Policy). */
document.addEventListener('change', function (e) {
  var el = e.target;
  if (el.matches && el.matches('[data-autosubmit]') && el.form) el.form.submit();
});
document.addEventListener('submit', function (e) {
  var msg = e.target.getAttribute && e.target.getAttribute('data-confirm');
  if (msg && !window.confirm(msg)) e.preventDefault();
});

/* Show / hide password: adds an eye button to every password box (sign in, sign up, reset, change password). */
(function () {
  var EYE = '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12z"/><circle cx="12" cy="12" r="3"/></svg>';
  var EYE_OFF = '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M17.94 17.94A10.9 10.9 0 0 1 12 19C5 19 1 12 1 12a18.5 18.5 0 0 1 5.06-5.94"/><path d="M9.9 4.24A10.9 10.9 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><path d="M14.12 14.12a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';
  function enhance(input) {
    if (input.dataset.pwReady) return;
    input.dataset.pwReady = '1';
    var wrap = document.createElement('div');
    wrap.className = 'pw-field';
    input.parentNode.insertBefore(wrap, input);
    wrap.appendChild(input);
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'pw-toggle';
    btn.setAttribute('aria-label', 'Show password');
    btn.setAttribute('aria-pressed', 'false');
    btn.innerHTML = EYE;
    btn.addEventListener('click', function () {
      var show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      btn.innerHTML = show ? EYE_OFF : EYE;
      btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
      btn.setAttribute('aria-pressed', show ? 'true' : 'false');
      input.focus();
    });
    wrap.appendChild(btn);
    // never leave a typed password visible if the page is restored from the back/forward cache
    window.addEventListener('pagehide', function () { if (input.type === 'text') { input.type = 'password'; btn.innerHTML = EYE; } });
  }
  function init() { document.querySelectorAll('input[type=password]').forEach(enhance); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();

/* Staff menu on small screens: opens/closes the nav panel. */
(function () {
  var side = document.querySelector('.side');
  var btn = document.querySelector('[data-menu-toggle]');
  if (!side || !btn) return;
  function set(open) {
    side.classList.toggle('open', open);
    btn.setAttribute('aria-expanded', open ? 'true' : 'false');
    var label = btn.querySelector('.menu-label'); if (label) label.textContent = open ? 'Close' : 'Menu';
  }
  btn.addEventListener('click', function () { set(!side.classList.contains('open')); });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && side.classList.contains('open')) { set(false); btn.focus(); } });
  document.addEventListener('click', function (e) { if (side.classList.contains('open') && !side.contains(e.target)) set(false); });
  var mq = window.matchMedia('(min-width: 901px)');
  (mq.addEventListener ? mq.addEventListener.bind(mq, 'change') : mq.addListener.bind(mq))(function () { set(false); });
})();

/* Tables on phones: copy each column heading onto its cells so a row can be shown as a labelled card.
   Works for tables with or without a <thead>, inside or outside .table-wrap.
   Tables that should stay tables (the prescription slip) are skipped. */
(function () {
  var clean = function (t) { return (t || '').replace(/\s+/g, ' ').trim(); };
  document.querySelectorAll('.content table, .patient table').forEach(function (table) {
    if (table.classList.contains('rx') || table.hasAttribute('data-keep-table') || table.classList.contains('stack')) return;
    var head = table.tHead && table.tHead.rows[0];
    if (!head) {                                   // header row written straight into the table
      var first = table.rows[0];
      if (first && first.cells.length && Array.prototype.every.call(first.cells, function (c) { return c.tagName === 'TH'; })) { head = first; head.classList.add('stack-head'); }
    }
    if (!head) return;
    if (!table.closest('.table-wrap')) {           // give bare tables a scroll wrapper so nothing can widen the page
      var wrap = document.createElement('div'); wrap.className = 'table-wrap';
      table.parentNode.insertBefore(wrap, table); wrap.appendChild(table);
    }
    var labels = Array.prototype.map.call(head.cells, function (th) { return clean(th.textContent); });
    Array.prototype.forEach.call(table.rows, function (row) {
      if (row === head || row.cells.length !== labels.length) return;   // e.g. a single "nothing here" cell
      Array.prototype.forEach.call(row.cells, function (td, i) {
        var l = labels[i];
        td.setAttribute('data-label', /^(actions?|quick actions?)$/i.test(l) ? '' : l);
      });
    });
    table.classList.add('stack');
  });
})();

/* Patient tab bar: scroll the current tab into view and hint when more tabs sit off-screen. */
(function () {
  var nav = document.querySelector('.patientnav');
  if (!nav) return;
  var cur = nav.querySelector('[aria-current=page]');
  if (cur) nav.scrollLeft = Math.max(0, cur.offsetLeft - (nav.clientWidth - cur.offsetWidth) / 2);
  function hint() { nav.classList.toggle('has-more', nav.scrollLeft + nav.clientWidth < nav.scrollWidth - 4); }
  nav.addEventListener('scroll', hint, { passive: true });
  window.addEventListener('resize', hint);
  hint();
})();
