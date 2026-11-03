/* Clinic Chat: live thread (send + poll) and, for staff, the conversation list. No dependencies. */
(function () {
  'use strict';
  var POLL_THREAD_MS = 4000, POLL_LIST_MS = 8000;

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }
  function getJSON(url) {
    return fetch(url, { credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.json(); });
  }

  /* ---------- thread ---------- */
  var root = document.getElementById('chat');
  if (root) {
    var me = root.dataset.me;                 // 'Patient' or 'Staff'
    var pollUrl = root.dataset.poll, sendUrl = root.dataset.send, csrf = root.dataset.csrf;
    var otherName = root.dataset.other || 'Clinic team';
    var last = parseInt(root.dataset.last || '0', 10) || 0;
    var scroller = document.getElementById('chat-scroll');
    var form = document.getElementById('chat-form');
    var ta = document.getElementById('chat-text');
    var btn = document.getElementById('chat-send');
    var errBox = document.getElementById('chat-error');
    var count = document.getElementById('chat-count');
    var sending = false, connLost = false;

    function nearBottom() { return scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight < 90; }
    function toBottom() { scroller.scrollTop = scroller.scrollHeight; }

    function bubble(m, fresh) {
      var mine = (me === 'Patient') ? m.sender === 'Patient' : m.sender === 'Staff';
      var row = el('div', 'msg ' + (mine ? 'mine' : 'theirs') + (fresh ? ' fresh' : ''));
      row.dataset.id = m.id;
      row.appendChild(el('div', 'bubble', m.message));
      var who;
      if (me === 'Patient') who = mine ? 'You' : (m.staff_name || 'Clinic team');
      else who = mine ? (m.staff_name || 'Staff') : otherName;
      row.appendChild(el('div', 'meta', who + ' · ' + m.created_at));
      return row;
    }
    function append(messages, fresh) {
      if (!messages || !messages.length) return;
      var stick = nearBottom();
      var empty = document.getElementById('chat-empty');
      messages.forEach(function (m) {
        if (m.id <= last && scroller.querySelector('[data-id="' + m.id + '"]')) return;
        if (empty) { empty.remove(); empty = null; }
        scroller.appendChild(bubble(m, fresh));
        if (m.id > last) last = m.id;
      });
      if (stick || (messages.length && messages[messages.length - 1].sender === me)) toBottom();
    }
    function setError(t) { if (errBox) errBox.textContent = t || ''; }

    toBottom();
    scroller.querySelectorAll('.msg').forEach(function (n) { n.classList.remove('fresh'); });

    function poll() {
      if (document.hidden) return;
      getJSON(pollUrl + '?after=' + last).then(function (j) {
        if (j && j.ok) {
          append(j.messages, true);
          if (connLost) { connLost = false; setError(''); }   // only clear errors that polling itself raised
        }
      }).catch(function () {
        connLost = true; setError('Connection lost or session expired. Reload the page if this persists.');
      });
    }
    setInterval(poll, POLL_THREAD_MS);
    document.addEventListener('visibilitychange', function () { if (!document.hidden) poll(); });

    function autosize() { ta.style.height = 'auto'; ta.style.height = Math.min(ta.scrollHeight, 140) + 'px'; }
    ta.addEventListener('input', function () { autosize(); if (count) count.textContent = ta.value.length + '/' + ta.maxLength; });
    ta.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); form.requestSubmit ? form.requestSubmit() : form.dispatchEvent(new Event('submit', { cancelable: true })); }
    });

    form.addEventListener('submit', function (e) {
      e.preventDefault();
      var text = ta.value.trim();
      if (!text || sending) return;
      sending = true; btn.disabled = true; setError('');
      var fd = new FormData();
      fd.append('message', text); fd.append('csrf_token', csrf);
      fetch(sendUrl, { method: 'POST', body: fd, credentials: 'same-origin',
                       headers: { 'X-CSRFToken': csrf, 'Accept': 'application/json' } })
        .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
        .then(function (res) {
          if (res.ok && res.j.ok) { append(res.j.messages, true); ta.value = ''; autosize(); if (count) count.textContent = '0/' + ta.maxLength; toBottom(); }
          else setError((res.j && res.j.error) || 'Message could not be sent.');
        })
        .catch(function () { setError('Message could not be sent. Check your connection and try again.'); })
        .then(function () { sending = false; btn.disabled = false; ta.focus(); });
    });
  }

  /* ---------- staff conversation list + nav badge ---------- */
  var list = document.getElementById('convlist');
  var badges = document.querySelectorAll('[data-chat-badge]');
  if (list || badges.length) {
    var stateUrl = (list && list.dataset.state) || (badges[0] && badges[0].dataset.state);
    var activePid = list ? list.dataset.active : '';
    var base = list ? list.dataset.base : '';

    function setBadges(n) {
      badges.forEach(function (b) { b.textContent = n; b.hidden = !n; });
    }
    function itemFor(c) {
      var a = el('a', 'conv'); a.dataset.pid = c.id; a.href = base + '?patient_id=' + c.id;
      var t = el('div', 'conv-top'); t.appendChild(el('b', null, c.name)); t.appendChild(el('span', 'conv-time', ''));
      var code = el('div', 'conv-code muted small', c.code);
      var b = el('div', 'conv-bottom'); b.appendChild(el('span', 'conv-preview', '')); b.appendChild(el('span', 'ubadge', '0'));
      a.appendChild(t); a.appendChild(code); a.appendChild(b);
      return a;
    }
    function refreshList() {
      if (document.hidden || !stateUrl) return;
      getJSON(stateUrl).then(function (j) {
        if (!j || !j.ok) return;
        var total = 0, empty = document.getElementById('conv-empty');
        j.conversations.forEach(function (c) {
          var isActive = String(c.id) === String(activePid);
          var unread = isActive ? 0 : c.unread;
          total += unread;
          if (!list) return;
          if (empty) { empty.remove(); empty = null; }
          var a = list.querySelector('.conv[data-pid="' + c.id + '"]');
          if (!a) { a = itemFor(c); list.appendChild(a); }
          a.querySelector('.conv-time').textContent = c.last_at;
          a.querySelector('.conv-preview').textContent = (c.last_sender === 'Staff' ? 'You: ' : '') + c.last_message;
          var ub = a.querySelector('.ubadge'); ub.textContent = unread; ub.hidden = !unread;
          a.dataset.last = c.last_at;
        });
        if (list) {
          Array.prototype.slice.call(list.querySelectorAll('.conv'))
            .sort(function (x, y) { return (y.dataset.last || '').localeCompare(x.dataset.last || ''); })
            .forEach(function (n) { list.appendChild(n); });
        }
        setBadges(total);
      }).catch(function () {});
    }
    refreshList();
    setInterval(refreshList, POLL_LIST_MS);
  }
})();
