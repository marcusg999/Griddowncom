/* GridDown message screen prototype - UI and instrumentation.
 *
 * No build step, no network, no modules (file:// blocks ES modules). Open
 * index.html directly.
 *
 * Instrumentation contract, so the numbers mean something:
 *   t_wake    the moment the screen-off overlay is dismissed. "Screen-on".
 *   t_commit  the moment the user's send action is taken: the pad tile press,
 *             or the SEND press in the type pane. This is the number the
 *             "under 3 s to a canned message" target is measured against.
 *   t_release t_commit + the 4 s undo hold, when the frame actually enters the
 *             queue. Reported separately and never confused with t_commit.
 *   taps      every pointerdown inside the screen, counted from the wake tap
 *             (which is itself counted and reported, not hidden).
 */
'use strict';

var gd = (function () {

  /* ================= the canned pad =================
   * Eight entries, one screen, no pages, no sub-menus: every canned message is
   * exactly one press. Each carries a short code on the wire (not the text), so
   * a selection plus a position pin fits the 64-byte bucket in gdc-wire and can
   * be rendered in the reader's own language.
   * The justification for each entry, and what was rejected, is in NOTES.md.
   */
  var CANNED = [
    { code: 1, label: 'I AM OK',       body: 'I am OK.',                      urgent: false },
    { code: 2, label: 'I NEED HELP',   body: 'I need help.',                  urgent: true  },
    { code: 3, label: 'INJURED',       sub: 'NEED A MEDIC',
                                       body: 'Injured. Need a medic.',        urgent: true  },
    { code: 4, label: 'TRAPPED',       sub: 'CANNOT MOVE',
                                       body: 'Trapped. I cannot move.',       urgent: true  },
    { code: 5, label: 'WHERE ARE YOU?', body: 'Where are you?',               urgent: false },
    { code: 6, label: 'ON MY WAY',     body: 'On my way.',                    urgent: false },
    { code: 7, label: 'DANGER HERE',   sub: 'KEEP AWAY',
                                       body: 'Danger here. Keep away.',       urgent: true  },
    { code: 8, label: 'SAFE HERE',     sub: 'COME TO ME',
                                       body: 'I am safe here. Come to me.',   urgent: false }
  ];

  var ORDER = { hold: 0, queued: 1, carried: 2, delivered: 3, read: 4, expired: 5 };

  var TASKS = [
    { id: 'T1', label: 'Send I NEED HELP as fast as you can.',            want: { canned: 2 } },
    { id: 'T2', label: 'Tell the channel you are unhurt.',                want: { canned: 1 } },
    { id: 'T3', label: 'Warn the channel that a road is flooded, in your own words.', want: { text: true } },
    { id: 'T4', label: 'Send any message WITHOUT your position attached.', want: { noPin: true } },
    { id: 'T5', label: 'Say out loud whether your last message actually reached anyone.', want: { scored: true } },
    { id: 'T6', label: 'Say out loud whether you can trust the name at the top of the roster.', want: { scored: true } },
    { id: 'T7', label: 'Send DANGER HERE with your position.',            want: { canned: 7, pin: true } }
  ];

  /* ================= state ================= */

  var sim = GDSim.create('7');
  var ui = {
    pane: 'pad',
    pinOn: true,
    holdId: null,
    theme: 'day'
  };
  var M = {           // instrumentation
    t0: Date.now(),
    tWake: 0,
    taps: 0,
    tapsSinceWake: 0,
    wakeTaps: 0,
    events: [],
    sends: [],
    task: null,
    taskLog: []
  };
  var el = {};

  function $(id) { return document.getElementById(id); }
  function now() { return Date.now(); }
  function rel(t) { return Math.round((t || now()) - M.t0); }

  function log(type, detail) {
    var e = { t: rel(), type: type };
    if (detail) for (var k in detail) if (detail.hasOwnProperty(k)) e[k] = detail[k];
    M.events.push(e);
    if (M.events.length > 4000) M.events.shift();
    return e;
  }

  /* ================= formatting ================= */

  function esc(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function secs(ms) {
    if (ms < 1000) return '0 s';
    if (ms < 60000) return Math.floor(ms / 1000) + ' s';
    var m = Math.floor(ms / 60000);
    if (m < 60) return m + ' min';
    return Math.floor(m / 60) + ' h ' + (m % 60) + ' min';
  }

  function clockOf(t) {
    var d = new Date(t);
    return ('0' + d.getHours()).slice(-2) + ':' + ('0' + d.getMinutes()).slice(-2);
  }

  function pinText(p) {
    return p.lat.toFixed(5) + ', ' + p.lon.toFixed(5) + '  +/-' + Math.round(p.acc) + ' m';
  }

  function bytesOf(s) {
    if (window.TextEncoder) return new TextEncoder().encode(s).length;
    return unescape(encodeURIComponent(s)).length;
  }

  /* ================= delivery state wording =================
   * Five states, each with: a position on a five-slot rail, a distinct glyph
   * shape, a short word, and a full sentence. Four redundant channels, none of
   * them colour. Nothing here claims more than the stack actually knows.
   */

  function stateWord(m) {
    switch (m.state) {
      case 'hold':      return 'HOLDING';
      case 'queued':    return 'WAITING';
      case 'carried':   return 'CARRIED';
      case 'delivered': return 'ARRIVED';
      case 'read':      return 'READ BY ' + m.readers;
      case 'expired':   return 'NOT DELIVERED';
    }
    return '';
  }

  function stateSay(m) {
    var t = now();
    switch (m.state) {
      case 'hold':
        return 'Not sent yet. ' + Math.max(0, Math.ceil((m.holdUntil - t) / 1000)) + ' seconds to take it back.';
      case 'queued':
        if (!sim.peers.length) {
          return 'No one is in range. It is held in your phone and goes the moment somebody comes near. Waiting ' + secs(t - m.tQueued) + '.';
        }
        if (!sim.inChannelInRange().length) {
          return 'Nobody in range is in this channel yet. It goes when one of them arrives, or when someone carries it. Waiting ' + secs(t - m.tQueued) + '.';
        }
        return 'Going out now. Waiting ' + secs(t - m.tQueued) + '.';
      case 'carried':
        return (m.carriers[0] || 'Someone') + ' is carrying it in their pocket. It has not arrived anywhere yet.';
      case 'delivered':
        return 'A phone in this channel has it. We do not know whether any person has looked at it.';
      case 'read':
        return m.readers + (m.readers === 1 ? ' person has' : ' people have') + ' opened it on their screen. Others may have it without opening it.';
      case 'expired':
        return 'No one ever came in range, so this reached nobody. It gave up waiting. Tap to send it again.';
    }
    return '';
  }

  var EXPLAIN = {
    hold: ['NOT SENT YET',
      'Every send is held for four seconds so that a wrong press can be taken back. Press NOW to skip the wait.'],
    queued: ['WAITING',
      'Your phone is holding this message. Nothing has been lost and nothing is your fault. There is simply no other phone running this app close enough to hand it to. The instant one comes near, it goes on its own. You do not have to do anything, and you can put the phone away.'],
    carried: ['CARRIED',
      'A person who was near you took a sealed copy and walked away with it. That is how a message crosses a city with no network: in a pocket. It has not arrived anywhere yet and we cannot say when it will, because we do not know where they are going. If it matters right now, send it again when somebody else is close.'],
    delivered: ['ARRIVED',
      'A phone in this channel has the message and said so. That is all we know and all we will claim. The person holding that phone may not have picked it up. Do not assume anybody has read it.'],
    read: ['READ',
      'This many people opened the message on their screen. Others in the channel may be holding it without having opened it, and others again may never have received it at all. This is a count of who told us, not a count of everyone.'],
    expired: ['NOT DELIVERED',
      'No phone ever came in range before this message ran out of time. It reached nobody. Nothing of it got out. Send it again when you can see somebody.']
  };

  /* five-slot rail, built as inline SVG */
  function rail(m) {
    var cur = ORDER[m.state];
    var occurred = {};
    for (var i = 0; i < m.history.length; i++) occurred[ORDER[m.history[i].state]] = true;
    var xs = [12, 37, 62, 87, 110], y = 13, out = '';
    var broken = m.state === 'expired' ? ' broken' : '';
    out += '<line class="track' + broken + '" x1="12" y1="' + y + '" x2="110" y2="' + y + '"/>';
    for (var s = 1; s <= 5; s++) {
      var x = xs[s - 1];
      var cls = (s === cur) ? 'g now' : (occurred[s] && s < cur ? 'g past' : 'g future');
      if (s === cur && (s === 1 || s === 5)) cls += ' hollow';
      if (s === 1) {
        out += '<circle class="' + cls + '" cx="' + x + '" cy="' + y + '" r="7"/>';
      } else if (s === 2) {
        out += '<polygon class="' + cls + '" points="' + (x - 6) + ',' + (y - 7) + ' ' + (x + 7) + ',' + y + ' ' + (x - 6) + ',' + (y + 7) + '"/>';
      } else if (s === 3) {
        out += '<rect class="' + cls + '" x="' + (x - 6) + '" y="' + (y - 6) + '" width="12" height="12"/>';
      } else if (s === 4) {
        out += '<rect class="' + cls + '" x="' + (x - 7) + '" y="' + (y - 6) + '" width="5" height="12"/>'
             + '<rect class="' + cls + '" x="' + (x + 2) + '" y="' + (y - 6) + '" width="5" height="12"/>';
      } else {
        out += '<line class="' + cls + '" x1="' + (x - 6) + '" y1="' + (y - 6) + '" x2="' + (x + 6) + '" y2="' + (y + 6) + '"/>'
             + '<line class="' + cls + '" x1="' + (x - 6) + '" y1="' + (y + 6) + '" x2="' + (x + 6) + '" y2="' + (y - 6) + '"/>';
      }
    }
    return '<svg class="rail" viewBox="0 0 122 26" aria-hidden="true">' + out + '</svg>';
  }

  /* ================= rendering ================= */

  function renderPad() {
    var h = '';
    for (var i = 0; i < CANNED.length; i++) {
      var c = CANNED[i];
      h += '<button class="tile" data-code="' + c.code + '" aria-label="Send: ' + esc(c.body) + '">'
         + '<span class="tile-label">' + esc(c.label) + '</span>'
         + (c.sub ? '<span class="tile-sub">' + esc(c.sub) + '</span>' : '')
         + '</button>';
    }
    el.pad.innerHTML = h;
  }

  function renderFeed() {
    var keepBottom = el.feed.scrollTop + el.feed.clientHeight >= el.feed.scrollHeight - 40;
    var prevTop = el.feed.scrollTop;
    var h = '', i, m;

    if (!sim.msgs.length) {
      h = '<div class="r-empty">Nothing yet. Press one of the big buttons below to send.</div>';
    }

    for (i = 0; i < sim.msgs.length; i++) {
      m = sim.msgs[i];
      h += '<article class="msg' + (m.mine ? ' mine' : '') + (m.urgent ? ' urgent' : '') + '">';

      if (m.mine) {
        h += '<div class="who">YOU &middot; ' + clockOf(m.tCreated) + '</div>';
      } else {
        h += '<div class="who">' + esc(m.fromNick) + ' &middot; '
           + (m.fromVerified ? '<span class="vmark">[V] VERIFIED</span>' : '<span class="vmark">[?] NOT VERIFIED</span>')
           + ' &middot; ' + clockOf(m.tCreated) + '</div>';
      }

      if (!m.mine && m.arrivedCarried) {
        h += '<div class="stale">[&gt;] CARRIED TO YOU &middot; WRITTEN ' + secs(m.ageMs + (now() - m.tCreated)) + ' AGO</div>';
      }

      h += '<div class="body">'
         + (m.urgent ? '<span class="urgentmark">URGENT</span>' : '')
         + esc(m.body) + '</div>';

      if (m.pin) {
        h += '<div class="pin">[+] ' + (m.mine ? 'YOUR POSITION SENT' : 'THEIR POSITION') + ' &middot; ' + pinText(m.pin) + '</div>';
      }

      if (m.mine) {
        h += '<button class="state" data-explain="' + m.state + '" data-msg="' + m.id + '">'
           + rail(m)
           + '<span class="words"><span class="word">' + esc(stateWord(m)) + '</span>'
           + '<span class="say">' + esc(stateSay(m)) + ' <em>What does this mean?</em></span></span>'
           + '</button>';
      }
      h += '</article>';
    }
    el.feed.innerHTML = h;
    el.feed.scrollTop = keepBottom ? el.feed.scrollHeight : prevTop;
  }

  function renderRoster() {
    var prevTop = el.roster.scrollTop;
    var counts = {}, i, p;
    for (i = 0; i < sim.peers.length; i++) {
      counts[sim.peers[i].nick] = (counts[sim.peers[i].nick] || 0) + 1;
    }
    var dupes = Object.keys(counts).filter(function (n) { return counts[n] > 1; });
    if (dupes.length) {
      el.dupe.hidden = false;
      el.dupe.innerHTML = '[!] ' + dupes.length + ' name' + (dupes.length > 1 ? 's are' : ' is')
        + ' being used by more than one phone: ' + esc(dupes.join(', '))
        + '. A name is not proof of who somebody is. Check it in person before you trust it.';
    } else {
      el.dupe.hidden = true;
    }

    if (!sim.peers.length) {
      el.roster.innerHTML = '<div class="r-empty"><b>No one is in range.</b><br>'
        + 'Anything you send waits in your phone and goes the moment a phone running this app comes near you. '
        + 'Walking to higher or more open ground helps.</div>';
      return;
    }

    var h = '';
    for (i = 0; i < sim.peers.length; i++) {
      p = sim.peers[i];
      var heard = now() - p.lastHeard;
      h += '<button class="r-row" data-peer="' + p.id + '">'
         + '<span class="r-top"><span class="r-nick">' + esc(p.nick) + '</span>'
         + (p.disputed
             ? '<span class="r-badge un">[X] NAME DISPUTED</span>'
             : p.verified
               ? '<span class="r-badge">[V] VERIFIED</span>'
               : '<span class="r-badge un">[?] NOT VERIFIED</span>')
         + '</span>'
         + '<span class="r-meta">'
         + (p.hops === 0 ? 'Straight to your phone' : 'Through ' + p.hops + ' other phone' + (p.hops > 1 ? 's' : ''))
         + ' &middot; ' + (p.link === 'WIFI' ? 'fast link' : 'short-range link')
         + ' &middot; ' + (heard < 6000 ? 'heard just now' : 'last heard ' + secs(heard) + ' ago' + (heard > 25000 ? ' - may be gone' : ''))
         + (p.inChannel ? '' : ' &middot; not in this channel, can only carry')
         + '</span>'
         + '<span class="r-act">'
         + (p.disputed
             ? 'Two phones claimed this name. Do not act on it.'
             : p.verified
               ? 'You checked this name in person. The name is real.'
               : 'Treat this name as a guess. Tap to check it in person.')
         + '</span>'
         + '</button>';
    }
    el.roster.innerHTML = h;
    el.roster.scrollTop = prevTop;
  }

  function renderChrome() {
    var n = sim.peers.length;
    el.chipRange.textContent = 'IN RANGE ' + n;
    el.tabWho.textContent = 'WHO ' + n;

    if (n === 0) {
      el.banner.hidden = false;
      el.banner.innerHTML = '<b>NO ONE IN RANGE</b><span>Nothing is lost. Messages wait in your phone and go the moment somebody comes near.</span>';
    } else {
      el.banner.hidden = true;
    }

    el.pinMark.textContent = ui.pinOn ? '[+]' : '[ ]';
    el.pinText.textContent = ui.pinOn ? 'YOUR POSITION WILL BE SENT' : 'NO POSITION WILL BE SENT';
    el.pinRow.setAttribute('aria-pressed', ui.pinOn ? 'true' : 'false');
    el.pinAct.textContent = ui.pinOn ? 'TAP TO STOP' : 'TAP TO ADD';
  }

  function renderUndo() {
    var m = null, i;
    for (i = 0; i < sim.msgs.length; i++) if (sim.msgs[i].id === ui.holdId) m = sim.msgs[i];
    if (!m || m.state !== 'hold') {
      ui.holdId = null;
      el.undo.hidden = true;
      el.pinRow.hidden = false;
      return;
    }
    el.undo.hidden = false;
    el.pinRow.hidden = true;
    var left = Math.max(0, Math.ceil((m.holdUntil - now()) / 1000));
    el.undoHead.textContent = 'SENDING IN ' + left;
    el.undoSub.textContent = (m.pin ? 'WITH YOUR POSITION - ' : 'NO POSITION - ') + m.body;
  }

  /* A pointer that is already down must never have the element under it
     replaced: swapping innerHTML between pointerdown and pointerup swallows the
     click outright. Under stress that reads as an unresponsive screen, which is
     the one failure this product cannot afford. So while a finger is down,
     redraws of the two list regions are deferred. */
  function renderAll() {
    renderChrome();
    renderUndo();
    if (ui.pressing) { ui.renderPending = true; return; }
    ui.renderPending = false;
    var fsig = feedSig();
    if (fsig !== ui.fsig) { ui.fsig = fsig; renderFeed(); }
    if (ui.pane === 'who') {
      var rsig = rosterSig();
      if (rsig !== ui.rsig) { ui.rsig = rsig; renderRoster(); }
    }
  }

  function feedSig() {
    var out = sim.msgs.length + '|' + sim.peers.length + '|', i, m;
    for (i = 0; i < sim.msgs.length; i++) {
      m = sim.msgs[i];
      out += m.id + ':' + m.state + ':' + (m.readers || 0) + ':'
          + (m.mine ? Math.floor((now() - (m.tQueued || m.tCreated)) / 1000) : Math.floor((now() - m.tCreated) / 60000)) + ';';
    }
    return out;
  }

  function rosterSig() {
    var out = '', i, p;
    for (i = 0; i < sim.peers.length; i++) {
      p = sim.peers[i];
      out += p.id + ':' + p.verified + ':' + p.disputed + ':' + Math.floor((now() - p.lastHeard) / 2000) + ';';
    }
    return out;
  }

  /* ================= actions ================= */

  function forceRender() { ui.fsig = null; ui.rsig = null; renderAll(); }

  function setPane(name) {
    ui.pane = name;
    var panes = { pad: el.panePad, type: el.paneType, who: el.paneWho };
    for (var k in panes) if (panes.hasOwnProperty(k)) panes[k].hidden = (k !== name);
    var tabs = el.tabs.querySelectorAll('.tab');
    for (var i = 0; i < tabs.length; i++) {
      var on = tabs[i].getAttribute('data-pane') === name;
      tabs[i].classList.toggle('is-on', on);
      tabs[i].setAttribute('aria-selected', on ? 'true' : 'false');
    }
    if (name === 'who') { ui.rsig = null; renderRoster(); ui.rsig = rosterSig(); }
    log('pane', { pane: name });
  }

  function commitSend(spec, label) {
    // Any still-held message is released immediately rather than cancelled: a
    // second send must never silently throw the first one away.
    if (ui.holdId) sim.releaseNow(ui.holdId);

    var tCommit = now();
    spec.pin = ui.pinOn ? { lat: sim.pos.lat, lon: sim.pos.lon, acc: sim.pos.acc } : null;
    var m = sim.send(spec);
    ui.holdId = m.id;

    var rec = {
      id: m.id,
      kind: spec.kind,
      code: spec.code || 0,
      label: label,
      pin: !!spec.pin,
      urgent: !!spec.urgent,
      bytes: bytesOf(spec.body),
      tWakeRel: M.tWake ? rel(M.tWake) : null,
      tCommitRel: rel(tCommit),
      msFromWake: M.tWake ? (tCommit - M.tWake) : null,
      tapsFromWake: M.tapsSinceWake,
      task: M.task ? M.task.id : null
    };
    M.sends.push(rec);
    log('send_commit', rec);
    checkTask({ sendRec: rec, spec: spec });
    forceRender();
    return m;
  }

  function sendCanned(code) {
    var c = null;
    for (var i = 0; i < CANNED.length; i++) if (CANNED[i].code === code) c = CANNED[i];
    if (!c) return;
    commitSend({ kind: 'canned', code: c.code, body: c.body, urgent: c.urgent }, c.label);
  }

  function sendText() {
    var s = el.ta.value.trim();
    if (!s) return;
    commitSend({ kind: 'text', body: s, urgent: false }, 'free text');
    el.ta.value = '';
    updateBytes();
  }

  function updateBytes() {
    var b = bytesOf(el.ta.value);
    while (b > 500) { el.ta.value = el.ta.value.slice(0, -1); b = bytesOf(el.ta.value); }
    el.bytes.textContent = b + ' of 500 bytes';
    el.bytes.classList.toggle('full', b > 440);
    el.send.disabled = b === 0;
  }

  function togglePin() {
    ui.pinOn = !ui.pinOn;
    log('pin_toggle', { on: ui.pinOn });
    renderChrome();
  }

  function setTheme(t) {
    ui.theme = t;
    document.documentElement.setAttribute('data-theme', t);
    el.btnTheme.textContent = t === 'day' ? 'DARK' : 'DAY';
    log('theme', { theme: t });
  }

  function openExplain(state, msgId) {
    var e = EXPLAIN[state] || ['', ''];
    el.explainTitle.textContent = e[0];
    el.explainBody.innerHTML = '<p>' + esc(e[1]) + '</p>';
    el.explainClose.textContent = (state === 'expired') ? 'SEND IT AGAIN' : 'GOT IT';
    el.explain.dataset.retry = (state === 'expired') ? msgId : '';
    el.explain.hidden = false;
    log('explain_open', { state: state });
  }

  function openVerify(peerId) {
    var p = null;
    for (var i = 0; i < sim.peers.length; i++) if (sim.peers[i].id === peerId) p = sim.peers[i];
    if (!p) return;
    el.sheet.dataset.peer = p.id;
    el.sheetTitle.textContent = p.verified ? 'ALREADY CHECKED: ' + p.nick : 'CHECK THE NAME: ' + p.nick;
    el.sheetWords.textContent = p.words.join('  ');
    el.sheet.hidden = false;
    log('verify_open', { nick: p.nick, verified: p.verified });
  }

  function lockScreen() {
    el.lock.hidden = false;
    M.tWake = 0;
    log('screen_off');
  }

  function wake() {
    el.lock.hidden = true;
    M.tWake = now();
    M.tapsSinceWake = 0;
    M.wakeTaps += 1;
    log('screen_on');
    forceRender();
  }

  /* ================= scripted tasks ================= */

  function startTask(id) {
    var t = null;
    for (var i = 0; i < TASKS.length; i++) if (TASKS[i].id === id) t = TASKS[i];
    if (!t) return;
    M.task = { id: t.id, label: t.label, want: t.want, tStart: now(), done: false };
    lockScreen();
    log('task_start', { task: t.id, label: t.label });
    paintTaskLive();
  }

  function checkTask(ctx) {
    var T = M.task;
    if (!T || T.done || !T.want) return;
    var w = T.want, ok = false;
    if (w.canned && ctx.sendRec && ctx.sendRec.kind === 'canned' && ctx.sendRec.code === w.canned) {
      ok = !w.pin || ctx.sendRec.pin;
    }
    if (w.text && ctx.sendRec && ctx.sendRec.kind === 'text') ok = true;
    if (w.noPin && ctx.sendRec && !ctx.sendRec.pin) ok = true;
    if (!ok) return;
    finishTask('completed', ctx.sendRec);
  }

  function finishTask(how, rec) {
    var T = M.task;
    if (!T || T.done) return;
    T.done = true;
    var entry = {
      task: T.id,
      label: T.label,
      outcome: how,
      msFromScreenOn: M.tWake ? (now() - M.tWake) : null,
      msFromTaskStart: now() - T.tStart,
      tapsFromScreenOn: M.tapsSinceWake,
      wakeTapIncluded: false,
      sendId: rec ? rec.id : null
    };
    M.taskLog.push(entry);
    log('task_end', entry);
    paintTaskLive();
  }

  function paintTaskLive() {
    var h = '';
    if (M.task) {
      h += '<div><b>' + esc(M.task.id) + '</b> ' + esc(M.task.label) + '<br>'
        + (M.task.done ? 'finished' : 'running') + '</div>';
    }
    if (M.taskLog.length) {
      h += '<table style="border-collapse:collapse;margin-top:6px">';
      for (var i = M.taskLog.length - 1; i >= 0; i--) {
        var e = M.taskLog[i];
        h += '<tr><td style="padding-right:8px">' + esc(e.task) + '</td>'
          + '<td style="padding-right:8px">' + esc(e.outcome) + '</td>'
          + '<td style="padding-right:8px">' + (e.msFromScreenOn === null ? '-' : e.msFromScreenOn + ' ms') + '</td>'
          + '<td>' + e.tapsFromScreenOn + ' taps</td></tr>';
      }
      h += '</table>';
    }
    el.tlive.innerHTML = h;
  }

  /* ================= instrumentation read-back ================= */

  function median(a) {
    if (!a.length) return null;
    var s = a.slice().sort(function (x, y) { return x - y; });
    var mid = s.length >> 1;
    return s.length % 2 ? s[mid] : Math.round((s[mid - 1] + s[mid]) / 2);
  }

  function summarise(list) {
    var ms = list.map(function (r) { return r.msFromWake; }).filter(function (v) { return v !== null; });
    var taps = list.map(function (r) { return r.tapsFromWake; });
    return {
      n: list.length,
      msFromScreenOn: { median: median(ms), min: ms.length ? Math.min.apply(null, ms) : null, max: ms.length ? Math.max.apply(null, ms) : null, all: ms },
      tapsFromScreenOn: { median: median(taps), min: taps.length ? Math.min.apply(null, taps) : null, max: taps.length ? Math.max.apply(null, taps) : null }
    };
  }

  function report() {
    var canned = M.sends.filter(function (r) { return r.kind === 'canned'; });
    var text = M.sends.filter(function (r) { return r.kind === 'text'; });
    return {
      note: 'msFromScreenOn is measured from the screen-off overlay being dismissed to the send press. The 4 s undo hold is after this and is reported separately per send.',
      seed: sim.seed,
      wakes: M.wakeTaps,
      totalTapsOnScreen: M.taps,
      canned: summarise(canned),
      text: summarise(text),
      tasks: M.taskLog
    };
  }

  function csv() {
    var head = 'id,kind,code,label,bytes,pin,urgent,ms_from_screen_on,taps_from_screen_on,task\n';
    return head + M.sends.map(function (r) {
      return [r.id, r.kind, r.code, '"' + String(r.label).replace(/"/g, '""') + '"', r.bytes,
              r.pin ? 1 : 0, r.urgent ? 1 : 0,
              r.msFromWake === null ? '' : r.msFromWake, r.tapsFromWake, r.task || ''].join(',');
    }).join('\n') + '\n';
  }

  function download(name, text, type) {
    var b = new Blob([text], { type: type || 'text/plain' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(b);
    a.download = name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  }

  /* ================= wiring ================= */

  function bind() {
    el.screen = $('screen');
    el.feed = $('feed');
    el.banner = $('banner');
    el.chipRange = $('chip-range');
    el.btnTheme = $('btn-theme');
    el.tabs = $('tabs');
    el.tabWho = el.tabs.querySelector('[data-pane="who"]');
    el.panePad = $('pane-pad');
    el.paneType = $('pane-type');
    el.paneWho = $('pane-who');
    el.pad = $('pane-pad');
    el.ta = $('ta');
    el.bytes = $('bytes');
    el.send = $('btn-send');
    el.roster = $('roster');
    el.dupe = $('dupe-warn');
    el.pinRow = $('btn-pin');
    el.pinMark = $('pin-mark');
    el.pinText = $('pin-text');
    el.pinAct = el.pinRow.querySelector('.pinrow-act');
    el.undo = $('undo');
    el.undoHead = $('undo-head');
    el.undoSub = $('undo-sub');
    el.sheet = $('sheet');
    el.sheetTitle = $('sheet-title');
    el.sheetWords = $('sheet-words');
    el.explain = $('explain');
    el.explainTitle = $('explain-title');
    el.explainBody = $('explain-body');
    el.explainClose = $('explain-close');
    el.lock = $('lock');
    el.tlive = $('t-live');

    // count every touch on the product surface, including the wake tap
    el.screen.addEventListener('pointerdown', function () {
      M.taps += 1;
      if (M.tWake) M.tapsSinceWake += 1;
      ui.pressing = true;
    }, true);
    var release = function () {
      ui.pressing = false;
      if (ui.renderPending) renderAll();
    };
    el.screen.addEventListener('pointerup', release, true);
    el.screen.addEventListener('pointercancel', release, true);
    window.addEventListener('pointerup', release, true);

    el.lock.addEventListener('click', wake);

    el.btnTheme.addEventListener('click', function () { setTheme(ui.theme === 'day' ? 'dark' : 'day'); });

    el.tabs.addEventListener('click', function (e) {
      var b = e.target.closest ? e.target.closest('.tab') : null;
      if (b) setPane(b.getAttribute('data-pane'));
    });

    el.pad.addEventListener('click', function (e) {
      var b = e.target.closest ? e.target.closest('.tile') : null;
      if (b) sendCanned(parseInt(b.getAttribute('data-code'), 10));
    });

    el.pinRow.addEventListener('click', togglePin);
    $('btn-undo').addEventListener('click', function () {
      if (!ui.holdId) return;
      var m = sim.cancel(ui.holdId);
      log('send_undo', { id: ui.holdId, body: m ? m.body : null });
      for (var i = M.sends.length - 1; i >= 0; i--) {
        if (M.sends[i].id === ui.holdId) { M.sends[i].undone = true; break; }
      }
      ui.holdId = null;
      forceRender();
    });
    $('btn-now').addEventListener('click', function () {
      if (ui.holdId) { sim.releaseNow(ui.holdId); log('send_now', { id: ui.holdId }); forceRender(); }
    });

    el.ta.addEventListener('input', updateBytes);
    el.send.addEventListener('click', sendText);

    el.feed.addEventListener('click', function (e) {
      var b = e.target.closest ? e.target.closest('.state') : null;
      if (b) openExplain(b.getAttribute('data-explain'), b.getAttribute('data-msg'));
    });

    el.roster.addEventListener('click', function (e) {
      var b = e.target.closest ? e.target.closest('.r-row') : null;
      if (b) openVerify(b.getAttribute('data-peer'));
    });

    $('sheet-match').addEventListener('click', function () {
      var id = el.sheet.dataset.peer, i;
      for (i = 0; i < sim.peers.length; i++) if (sim.peers[i].id === id) {
        sim.peers[i].verified = true; sim.peers[i].disputed = false;
        log('verify_match', { nick: sim.peers[i].nick });
      }
      el.sheet.hidden = true;
      forceRender();
    });
    $('sheet-nomatch').addEventListener('click', function () {
      var id = el.sheet.dataset.peer, i;
      for (i = 0; i < sim.peers.length; i++) if (sim.peers[i].id === id) {
        sim.peers[i].verified = false; sim.peers[i].disputed = true;
        log('verify_mismatch', { nick: sim.peers[i].nick });
      }
      el.sheet.hidden = true;
      forceRender();
    });
    $('sheet-cancel').addEventListener('click', function () { el.sheet.hidden = true; });

    el.explainClose.addEventListener('click', function () {
      var retry = el.explain.dataset.retry;
      el.explain.hidden = true;
      if (retry) {
        for (var i = 0; i < sim.msgs.length; i++) {
          if (sim.msgs[i].id === retry) {
            var old = sim.msgs[i];
            commitSend({ kind: old.kind, code: old.code, body: old.body, urgent: old.urgent }, 'retry');
            break;
          }
        }
      }
    });

    /* ---- rig ---- */
    var taskSel = $('task');
    taskSel.innerHTML = TASKS.map(function (t) {
      return '<option value="' + t.id + '">' + t.id + ' - ' + esc(t.label) + '</option>';
    }).join('');

    $('t-start').addEventListener('click', function () { startTask(taskSel.value); });
    $('t-pass').addEventListener('click', function () { finishTask('scored correct', null); });
    $('t-fail').addEventListener('click', function () { finishTask('scored wrong', null); });

    $('r-reset').addEventListener('click', function () {
      sim.reset($('seed').value || '7');
      ui.holdId = null;
      log('world_reset', { seed: sim.seed });
      forceRender();
    });
    $('r-churn').addEventListener('change', function () { sim.churn = this.checked; });
    $('r-inbound').addEventListener('change', function () { sim.autoInbound = this.checked; });
    $('r-join').addEventListener('click', function () { sim.joinPeer(); forceRender(); });
    $('r-leave').addEventListener('click', function () { sim.leavePeer(); forceRender(); });
    $('r-zero').addEventListener('click', function () { sim.zeroPeers(); forceRender(); });
    $('r-msg').addEventListener('click', function () { sim.inbound({}); forceRender(); });
    $('r-carried').addEventListener('click', function () { sim.inbound({ carried: true, ageMs: 23 * 60000 }); forceRender(); });
    $('r-dupe').addEventListener('click', function () { sim.duplicateNick(); setPane('who'); forceRender(); });
    $('r-expire').addEventListener('click', function () { sim.expireOldestQueued(); forceRender(); });
    $('r-courier').addEventListener('click', function () { sim.forceCourierNext = true; });

    $('m-report').addEventListener('click', function () {
      $('m-out').textContent = JSON.stringify(report(), null, 2);
    });
    $('m-csv').addEventListener('click', function () { download('griddown-sends.csv', csv(), 'text/csv'); });
    $('m-json').addEventListener('click', function () {
      download('griddown-metrics.json', JSON.stringify({ report: report(), events: M.events, sends: M.sends }, null, 2), 'application/json');
    });
    $('m-clear').addEventListener('click', function () {
      M.events = []; M.sends = []; M.taskLog = []; M.taps = 0; M.tapsSinceWake = 0; M.wakeTaps = 0;
      $('m-out').textContent = ''; paintTaskLive();
    });

    $('clocknote').textContent = 'Demo clock: carried phase ' + (sim.constants.CARRY_MIN_MS / 1000) + '-'
      + (sim.constants.CARRY_MAX_MS / 1000) + ' s stands in for minutes to hours in a pocket; expiry '
      + (sim.constants.EXPIRY_MS / 1000) + ' s stands in for the real 2 h limit; undo hold '
      + (sim.constants.HOLD_MS / 1000) + ' s is the real value.';
  }

  function start() {
    bind();
    renderPad();
    setTheme('day');
    renderAll();
    setInterval(function () {
      var changed = sim.tick();
      for (var i = 0; i < changed.length; i++) {
        if (changed[i].kind === 'state') log('delivery_state', { id: changed[i].msg.id, state: changed[i].msg.state });
        if (changed[i].kind === 'inbound') log('inbound', { from: changed[i].msg.fromNick, carried: changed[i].msg.arrivedCarried });
      }
      renderAll();
    }, 400);
    log('boot', { seed: sim.seed });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();

  return {
    report: report,
    events: function () { return M.events; },
    sends: function () { return M.sends; },
    tasks: function () { return M.taskLog; },
    csv: csv,
    canned: CANNED,
    sim: sim,
    startTask: startTask,
    lock: lockScreen,
    setTheme: setTheme,
    setPane: setPane,
    _m: M
  };
})();

window.gd = gd;
