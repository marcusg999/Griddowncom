/* GridDown onboarding prototype -- pure logic.
 *
 * Everything here is DOM-free on purpose so it can be exercised under node
 * (`node selftest.js`) in a container that has no browser. The DOM wiring lives
 * in app.js and does nothing clever.
 */
(function (root) {
  'use strict';

  // ---------------------------------------------------------------- copy ---
  // Every user-visible string in the flow lives here, so the "number of words
  // the user must read" metric is computed from the real strings rather than
  // asserted in a design note. `crit: true` marks a string that sits on the
  // critical path from launch to first message sent.
  //
  // Deliberately absent: the word "mesh", "network", "node", "peer", "relay",
  // "Bluetooth Low Energy", "encryption", "channel key", "hop", "TTL",
  // "broadcast", "offline", "sync". A panicking stranger owes us no vocabulary.
  var COPY = {
    // --- screen 1: start -------------------------------------------------
    start_reassure:   { s: 'Nothing to set up. No internet needed.', crit: true },
    start_scan:       { s: 'Scan someone’s code', crit: true },
    start_create:     { s: 'Start a channel', crit: true },
    start_create_sub: { s: 'if nobody has a code', crit: true },

    // --- OS permission purpose strings (ours; the rest of the sheet is OS) --
    perm_bt:   { s: 'So this phone can reach phones nearby.', crit: true },
    perm_cam:  { s: 'To read the code on their screen.', crit: true },
    perm_loc:  { s: 'To put your position in the message.', crit: false },

    // --- screen 2: scan --------------------------------------------------
    scan_aim:    { s: 'Point at their code', crit: true },
    scan_escape: { s: 'No code to scan? Start a channel', crit: true },
    scan_found:  { s: 'Got it', crit: true },

    // --- screen 3: channel ------------------------------------------------
    // The two most important strings in the application. They are on screen
    // BEFORE the first send, not after it, because a user who reads
    // "no one in range" and concludes the app is broken never sends at all.
    reach_none:     { s: 'No one in range yet', crit: true },
    reach_none_sub: { s: 'Send anyway — it goes when someone comes near.', crit: true },
    reach_some:     { s: 'in range', crit: true },          // "2 phones in range"
    show_code:      { s: 'Show my code', crit: true },
    you_are:        { s: 'You’re', crit: true },        // "You're Rook-4"
    composer_hint:  { s: 'Type a message', crit: true },
    bt_off:         { s: 'Bluetooth is off. Nothing can leave this phone.', crit: true },
    bt_off_action:  { s: 'Turn on', crit: true },

    // The single piece of teaching in the whole flow. Attached to the user's
    // own first message, at the moment it is the answer to the question they
    // are actually asking.
    first_waiting:  { s: 'Waiting. It goes the moment someone is near. You can lock the screen.', crit: true },
    first_arrived:  { s: 'It reached the channel. If it ever says Waiting, nobody is near yet.', crit: true },

    // --- delivery vocabulary ---------------------------------------------
    // Icon AND word, always. A glyph alone fails the comprehension metric, and
    // a tick mark would be a lie: every messenger has trained people that a
    // tick means delivered.
    st_waiting:      { s: 'Waiting', crit: true },
    st_waiting_sub:  { s: 'still on this phone', crit: true },
    st_carried:      { s: 'Carried', crit: false },
    st_carried_sub:  { s: 'someone is walking it over', crit: false },
    st_arrived:      { s: 'Arrived', crit: false },
    st_arrived_sub:  { s: 'in the channel', crit: false },
    st_read:         { s: 'Read', crit: false },
    st_expired:      { s: 'Expired', crit: false },
    st_expired_sub:  { s: 'never found anyone — send again when you see people', crit: false },

    // --- screen 4: my code (off the critical path) ------------------------
    code_aim:   { s: 'Let them point a camera at this', crit: false },
    code_warn:  { s: 'Anyone who scans it can read this channel.', crit: false },
    code_done:  { s: 'Done', crit: false },

    // --- nickname (off the critical path) ---------------------------------
    name_label: { s: 'Name, if you want one', crit: false },
    name_note:  { s: 'Only people in this channel see it. It’s gone when you close the app.', crit: false },
    name_done:  { s: 'Done', crit: false }
  };

  // The canned pad is message content, not instruction. Counted separately:
  // the user scans it, they do not read it as prose.
  var PAD = ['I’m OK', 'I need help', 'I’m trapped', 'Need water', 'Where are you?', 'On my way'];

  function words(s) {
    if (!s) return 0;
    return String(s).replace(/[—–]/g, ' ').trim().split(/\s+/).filter(function (w) {
      return /[A-Za-z0-9’']/.test(w);
    }).length;
  }

  function wordBudget() {
    var crit = 0, all = 0, keys = Object.keys(COPY);
    for (var i = 0; i < keys.length; i++) {
      var n = words(COPY[keys[i]].s);
      all += n;
      if (COPY[keys[i]].crit) crit += n;
    }
    var pad = PAD.reduce(function (a, s) { return a + words(s); }, 0);
    return { critical: crit, total: all, padContent: pad, strings: keys.length };
  }

  // ------------------------------------------------------- channel codec ---
  // The QR carries the channel key and a human label. The label travels in the
  // QR only; it is never on the wire, where addressing is by a rotating tag
  // derived from the key (gdc-wire ChanTag).
  var URI_PREFIX = 'griddown:1/';

  function formatChannelUri(keyB64, name) {
    return URI_PREFIX + keyB64 + '/' + encodeURIComponent(name);
  }

  // Returns {key, name} or null. Never throws: this parses something a stranger
  // pointed a camera at.
  function parseChannelUri(s) {
    if (typeof s !== 'string') return null;
    if (s.slice(0, URI_PREFIX.length) !== URI_PREFIX) return null;
    var rest = s.slice(URI_PREFIX.length);
    var slash = rest.indexOf('/');
    if (slash < 0) return null;
    var key = rest.slice(0, slash);
    var name = rest.slice(slash + 1);
    if (!/^[A-Za-z0-9_-]{43}$/.test(key)) return null;   // 32 bytes, base64url
    if (name.length > 120) return null;
    var decoded;
    try { decoded = decodeURIComponent(name); } catch (e) { return null; }
    if (!decoded) return null;
    return { key: key, name: decoded.slice(0, 40) };
  }

  // ------------------------------------------------------ delivery ladder ---
  // The honesty engine. Nothing here is driven by "we handed the bytes to the
  // radio" -- which is exactly the signal Bridgefy's send callback reports and
  // which its own documentation admits is not delivery. Each state names the
  // physical fact that produced it.
  var LADDER = {
    LINK_MS:    1200,    // in range -> reached the channel
    CARRY_MS:  12000,    // handed to a walker -> they arrived somewhere
    READ_MS:    5000,    // in the channel -> someone opened it
    TTL_MS:   120000     // prototype expiry, so the expired state is reachable
  };

  function newMessage(id, text, now) {
    return { id: id, text: text, state: 'waiting', stateAt: now, sentAt: now, carried: false, readers: 0 };
  }

  /* Advance one message. Pure: returns a new object if anything changed, or
     the same reference if not. `world` is { peers, now }. */
  function advance(msg, world) {
    var now = world.now, dt = now - msg.stateAt;
    function to(state, extra) {
      var n = {};
      for (var k in msg) if (Object.prototype.hasOwnProperty.call(msg, k)) n[k] = msg[k];
      n.state = state; n.stateAt = now;
      if (extra) for (var k2 in extra) n[k2] = extra[k2];
      return n;
    }
    switch (msg.state) {
      case 'waiting':
        if (world.peers > 0 && dt >= LADDER.LINK_MS) return to('arrived');
        if (msg.carried) return to('carried');
        if (now - msg.sentAt >= LADDER.TTL_MS) return to('expired');
        return msg;
      case 'carried':
        if (world.peers > 0 && dt >= LADDER.LINK_MS) return to('arrived');
        if (dt >= LADDER.CARRY_MS) return to('arrived');
        return msg;
      case 'arrived':
        if (dt >= LADDER.READ_MS) return to('read', { readers: 1 });
        return msg;
      default:
        return msg;
    }
  }

  /* What the user can truthfully say about this message. Used by the
     comprehension check in the harness, and it is the same string the UI
     shows -- there is no second, softer story anywhere. */
  function honestAnswer(state) {
    switch (state) {
      case 'waiting': return 'not sent yet — still on this phone';
      case 'carried': return 'not there yet — someone is carrying it';
      case 'arrived': return 'it is in the channel';
      case 'read':    return 'someone has read it';
      case 'expired': return 'it never got out';
      default:        return 'unknown';
    }
  }

  // ------------------------------------------------------------ metrics ----
  function Metrics(now) {
    this.t0 = now;
    this.taps = 0;
    this.tapLog = [];
    this.screenVisits = [];
    this.firstSendMs = null;
    this.firstSendTaps = null;
    this.firstSendScreens = null;
    this.permissionPrompts = 0;
    this.path = null;            // 'join' | 'create'
  }
  Metrics.prototype.tap = function (label, now) {
    this.taps++;
    this.tapLog.push({ n: this.taps, label: label, atMs: Math.round(now - this.t0) });
  };
  Metrics.prototype.screen = function (id, now) {
    this.screenVisits.push({ id: id, atMs: Math.round(now - this.t0) });
  };
  Metrics.prototype.send = function (now) {
    if (this.firstSendMs != null) return false;
    this.firstSendMs = Math.round(now - this.t0);
    this.firstSendTaps = this.taps;
    this.firstSendScreens = this.uniqueScreens();
    return true;
  };
  Metrics.prototype.uniqueScreens = function () {
    var seen = {}, n = 0;
    for (var i = 0; i < this.screenVisits.length; i++) {
      if (!seen[this.screenVisits[i].id]) { seen[this.screenVisits[i].id] = 1; n++; }
    }
    return n;
  };
  Metrics.prototype.report = function (now) {
    return {
      path: this.path,
      timeToFirstMessageMs: this.firstSendMs,
      tapsToFirstMessage: this.firstSendTaps,
      screensToFirstMessage: this.firstSendScreens,
      screenTransitions: this.screenVisits.length,
      tapsTotal: this.taps,
      permissionPrompts: this.permissionPrompts,
      elapsedMs: Math.round(now - this.t0),
      words: wordBudget(),
      target: { timeToFirstMessageMs: 20000 },
      metTarget: this.firstSendMs != null ? this.firstSendMs < 20000 : null,
      tapLog: this.tapLog,
      screenLog: this.screenVisits
    };
  };

  // ------------------------------------------------------------- naming ----
  // Session identity is ephemeral and costs the user nothing, so we hand them
  // one instead of asking. Two syllables, unambiguous out loud, no gender, no
  // culture, no collision with a real name.
  var NAME_A = ['Rook', 'Ash', 'Wren', 'Fern', 'Pike', 'Vale', 'Elm', 'Hawk', 'Reed', 'Moss'];
  var PLACE  = ['Oak', 'Pine', 'Market', 'River', 'Mill', 'North', 'Cedar', 'Harbor'];
  var PLACE2 = ['Street', 'Block', 'Yard', 'Corner', 'Row', 'Lot'];

  function pick(arr, rnd) { return arr[Math.floor(rnd() * arr.length) % arr.length]; }
  function defaultNickname(rnd) { return pick(NAME_A, rnd) + '-' + (1 + Math.floor(rnd() * 9)); }
  function defaultChannelName(rnd) { return pick(PLACE, rnd) + ' ' + pick(PLACE2, rnd); }

  function randomKeyB64(bytesFn) {
    var b = bytesFn(32), alph = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    var out = '', i;
    for (i = 0; i + 2 < 32; i += 3) {
      var n = (b[i] << 16) | (b[i + 1] << 8) | b[i + 2];
      out += alph[(n >> 18) & 63] + alph[(n >> 12) & 63] + alph[(n >> 6) & 63] + alph[n & 63];
    }
    var n2 = (b[30] << 8) | b[31];                        // 2 bytes left -> 3 chars
    out += alph[(n2 >> 10) & 63] + alph[(n2 >> 4) & 63] + alph[(n2 << 2) & 63];
    return out;                                           // 40 + 3 = 43 chars
  }

  root.GDLogic = {
    COPY: COPY, PAD: PAD, words: words, wordBudget: wordBudget,
    formatChannelUri: formatChannelUri, parseChannelUri: parseChannelUri,
    URI_PREFIX: URI_PREFIX,
    LADDER: LADDER, newMessage: newMessage, advance: advance, honestAnswer: honestAnswer,
    Metrics: Metrics,
    defaultNickname: defaultNickname, defaultChannelName: defaultChannelName,
    randomKeyB64: randomKeyB64
  };
})(typeof module !== 'undefined' && module.exports ? module.exports : (typeof window !== 'undefined' ? window : this));
