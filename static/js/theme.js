/* Light/dark theme toggle. The initial theme is applied by an inline script in <head>
   (templates/_theme.html) so there is no flash; this file wires up the buttons. */
(function () {
  var KEY = 'hk-theme', root = document.documentElement;
  function current() { return root.getAttribute('data-theme') === 'dark' ? 'dark' : 'light'; }
  function apply(theme) {
    var dark = theme === 'dark';
    root.setAttribute('data-theme', theme);
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute('content', dark ? '#0e1115' : '#f4f5f7');
    var label = dark ? 'Switch to light theme' : 'Switch to dark theme';
    document.querySelectorAll('[data-theme-toggle]').forEach(function (b) {
      b.setAttribute('aria-label', label); b.setAttribute('title', label);
      b.setAttribute('aria-pressed', dark ? 'true' : 'false');
    });
  }
  document.addEventListener('click', function (e) {
    var b = e.target.closest && e.target.closest('[data-theme-toggle]');
    if (!b) return;
    var next = current() === 'dark' ? 'light' : 'dark';
    try { localStorage.setItem(KEY, next); } catch (_) {}
    apply(next);
  });
  window.addEventListener('storage', function (e) {          // keep other open tabs in sync
    if (e.key === KEY && (e.newValue === 'dark' || e.newValue === 'light')) apply(e.newValue);
  });
  apply(current());
})();
