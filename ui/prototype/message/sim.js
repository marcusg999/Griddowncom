/* GridDown message screen prototype - simulated world.
 *
 * This file owns everything the UI cannot know on a Linux box with no radios:
 * who is in range, when they arrive and leave, what arrives from them, and how
 * an outbound message actually progresses through the five delivery states.
 *
 * It is deliberately a separate file from the UI so that a critic can read the
 * state machine without reading any rendering code, and so that the honesty of
 * the five states can be checked against the transitions that produce them.
 *
 * TIME IS COMPRESSED. The real stack carries a 2 h expiry and carriers that
 * walk for minutes to hours. Here the carried phase is 12-25 s and expiry is
 * 75 s, so that all five states are reachable inside a scripted task. Every
 * compressed constant is named below and surfaced in the rig, because a demo
 * clock presented as a real one would be exactly the sort of dishonesty this
 * screen exists to avoid.
 */
'use strict';

var GDSim = (function () {

  /* ---- compressed demo clock ---------------------------------------- */
  var HOLD_MS         = 4000;    // undo window; this one is real, not compressed
  var DELIVER_MIN_MS  = 900;     // in-channel peer in range -> arrives
  var DELIVER_MAX_MS  = 2600;
  var CARRY_MIN_MS    = 12000;   // stands in for minutes to hours in the pocket
  var CARRY_MAX_MS    = 25000;
  var EXPIRY_MS       = 75000;   // stands in for the real 2 h TTL
  var READ_MIN_MS     = 2500;
  var READ_MAX_MS     = 11000;
  var COURIER_CHANCE  = 0.22;    // share of sends that leave by courier custody
  var READ_CHANCE     = 0.72;

  var NICKS = ['ANA', 'TOM', 'MIRA', 'DEV', 'JO', 'SAM', 'LEE', 'PRIYA', 'KOFI', 'RUBY'];

  var WORDS = ['river', 'stone', 'copper', 'eight', 'kettle', 'north', 'amber', 'plank',
               'otter', 'cinder', 'lamp', 'salt', 'quiet', 'thread', 'gravel', 'moth'];

  var INBOUND = [
    { canned: 'I am OK.',                                        urgent: false, pin: false },
    { canned: 'Where are you?',                                  urgent: false, pin: false },
    { canned: 'On my way.',                                      urgent: false, pin: true  },
    { canned: 'Danger here. Avoid this place.',                  urgent: true,  pin: true  },
    { canned: 'I am safe here. Come to me.',                     urgent: false, pin: true  },
    { text: 'Water at the school gate until it gets dark.',      urgent: false, pin: false },
    { text: 'Mill Road is under water. Do not try it on foot.',  urgent: true,  pin: true  },
    { text: 'Phone at 11 percent. Going dark to save it.',       urgent: false, pin: false },
    { text: 'Two of us at the pub steps, we can carry someone.', urgent: false, pin: true  },
    { text: 'Has anyone seen a grey van with two kids in it',    urgent: false, pin: false }
  ];

  function mulberry32(a) {
    return function () {
      a |= 0; a = a + 0x6D2B79F5 | 0;
      var t = Math.imul(a ^ a >>> 15, 1 | a);
      t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
      return ((t ^ t >>> 14) >>> 0) / 4294967296;
    };
  }

  function seedFrom(str) {
    var h = 2166136261;
    str = String(str);
    for (var i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 16777619);
    }
    return h >>> 0;
  }

  function Sim(seed) {
    this.constants = {
      HOLD_MS: HOLD_MS, DELIVER_MIN_MS: DELIVER_MIN_MS, DELIVER_MAX_MS: DELIVER_MAX_MS,
      CARRY_MIN_MS: CARRY_MIN_MS, CARRY_MAX_MS: CARRY_MAX_MS, EXPIRY_MS: EXPIRY_MS
    };
    this.reset(seed);
  }

  Sim.prototype.reset = function (seed) {
    this.seed = seed;
    this.rnd = mulberry32(seedFrom(seed));
    this.peers = [];
    this.msgs = [];
    this.nextId = 1;
    this.churn = true;
    this.autoInbound = true;
    this.forceCourierNext = false;
    this.t0 = Date.now();
    this.nextChurnAt = this.t0 + 2500;
    this.nextInboundAt = this.t0 + 9000;
    this.pos = { lat: 51.50740, lon: -0.12780, acc: 38 };
    // Start with one peer present so the first screen is not a dead end, and
    // one absent-channel courier so both early paths are visible.
    this.joinPeer(true);
  };

  Sim.prototype.rint = function (lo, hi) { return lo + Math.floor(this.rnd() * (hi - lo + 1)); };
  Sim.prototype.pick = function (arr) { return arr[Math.floor(this.rnd() * arr.length)]; };

  /* ---- roster ------------------------------------------------------- */

  Sim.prototype.freeNick = function () {
    var used = {}, i;
    for (i = 0; i < this.peers.length; i++) used[this.peers[i].nick] = true;
    var free = NICKS.filter(function (n) { return !used[n]; });
    return free.length ? this.pick(free) : this.pick(NICKS);
  };

  Sim.prototype.words = function () {
    var out = [], pool = WORDS.slice();
    for (var i = 0; i < 4; i++) out.push(pool.splice(Math.floor(this.rnd() * pool.length), 1)[0]);
    return out;
  };

  Sim.prototype.joinPeer = function (forceInChannel, nick) {
    if (this.peers.length >= 7) return null;
    var now = Date.now();
    var p = {
      id: 'p' + (this.nextId++),
      nick: nick || this.freeNick(),
      verified: this.rnd() < 0.45,
      disputed: false,
      inChannel: forceInChannel === true ? true : this.rnd() < 0.6,
      hops: this.rnd() < 0.62 ? 0 : (this.rnd() < 0.7 ? 1 : 2),
      link: this.rnd() < 0.15 ? 'WIFI' : 'BLE',
      lastHeard: now,
      joinedAt: now,
      words: this.words()
    };
    this.peers.push(p);
    return p;
  };

  Sim.prototype.leavePeer = function (id) {
    var i;
    if (id) {
      for (i = 0; i < this.peers.length; i++) if (this.peers[i].id === id) { return this.peers.splice(i, 1)[0]; }
      return null;
    }
    if (!this.peers.length) return null;
    i = Math.floor(this.rnd() * this.peers.length);
    return this.peers.splice(i, 1)[0];
  };

  Sim.prototype.zeroPeers = function () { this.peers = []; };

  Sim.prototype.duplicateNick = function () {
    if (!this.peers.length) this.joinPeer(true);
    var target = this.peers[0];
    var p = this.joinPeer(false, target.nick);
    if (p) p.verified = false;
    return p;
  };

  Sim.prototype.inChannelInRange = function () {
    return this.peers.filter(function (p) { return p.inChannel; });
  };

  /* ---- outbound ----------------------------------------------------- */

  Sim.prototype.send = function (spec) {
    var now = Date.now();
    var m = {
      id: 'm' + (this.nextId++),
      mine: true,
      kind: spec.kind,                 // 'canned' | 'text'
      code: spec.code || 0,
      body: spec.body,
      urgent: !!spec.urgent,
      pin: spec.pin || null,
      tCreated: now,
      state: 'hold',
      holdUntil: now + HOLD_MS,
      tQueued: 0,
      dueAt: 0,
      courier: this.forceCourierNext || this.rnd() < COURIER_CHANCE,
      carriers: [],
      readers: 0,
      nextReadAt: 0,
      history: [{ state: 'hold', t: now }]
    };
    this.forceCourierNext = false;
    this.msgs.push(m);
    return m;
  };

  Sim.prototype.cancel = function (id) {
    for (var i = 0; i < this.msgs.length; i++) {
      if (this.msgs[i].id === id && this.msgs[i].state === 'hold') {
        return this.msgs.splice(i, 1)[0];
      }
    }
    return null;
  };

  Sim.prototype.releaseNow = function (id) {
    for (var i = 0; i < this.msgs.length; i++) {
      if (this.msgs[i].id === id && this.msgs[i].state === 'hold') {
        this.msgs[i].holdUntil = Date.now();
        return this.msgs[i];
      }
    }
    return null;
  };

  Sim.prototype.setState = function (m, s, now) {
    m.state = s;
    m.history.push({ state: s, t: now });
  };

  Sim.prototype.expireOldestQueued = function () {
    var now = Date.now();
    for (var i = 0; i < this.msgs.length; i++) {
      if (this.msgs[i].state === 'queued') { this.setState(this.msgs[i], 'expired', now); return this.msgs[i]; }
    }
    return null;
  };

  /* ---- inbound ------------------------------------------------------ */

  Sim.prototype.inbound = function (opts) {
    opts = opts || {};
    var now = Date.now();
    var src = this.peers.length ? this.pick(this.peers) : this.joinPeer(true);
    var spec = this.pick(INBOUND);
    var carried = !!opts.carried;
    var m = {
      id: 'm' + (this.nextId++),
      mine: false,
      kind: spec.canned ? 'canned' : 'text',
      body: spec.canned || spec.text,
      urgent: spec.urgent,
      pin: spec.pin ? { lat: this.pos.lat + (this.rnd() - 0.5) * 0.01,
                        lon: this.pos.lon + (this.rnd() - 0.5) * 0.01,
                        acc: this.rint(18, 90) } : null,
      fromNick: src.nick,
      fromVerified: src.verified,
      fromHops: src.hops,
      tCreated: now,
      arrivedCarried: carried,
      ageMs: carried ? (opts.ageMs || 23 * 60 * 1000) : 0,
      state: 'in',
      history: [{ state: 'in', t: now }]
    };
    this.msgs.push(m);
    return m;
  };

  /* ---- clock -------------------------------------------------------- */

  /* Returns the list of state changes that happened on this tick, so the UI can
     announce them rather than diffing the whole feed. */
  Sim.prototype.tick = function () {
    var now = Date.now(), changed = [], i, m, p;

    for (i = 0; i < this.peers.length; i++) {
      p = this.peers[i];
      // A present peer is heard again on its beacon interval.
      if (now - p.lastHeard > 4000 && this.rnd() < 0.5) p.lastHeard = now;
    }

    if (this.churn && now >= this.nextChurnAt) {
      this.nextChurnAt = now + this.rint(6000, 15000);
      var n = this.peers.length;
      var pJoin = n === 0 ? 0.85 : (n >= 5 ? 0.2 : 0.55);
      if (this.rnd() < pJoin) { if (this.joinPeer()) changed.push({ kind: 'join' }); }
      else { if (this.leavePeer()) changed.push({ kind: 'leave' }); }
    }

    if (this.autoInbound && now >= this.nextInboundAt) {
      this.nextInboundAt = now + this.rint(11000, 24000);
      if (this.peers.length) {
        var carried = this.rnd() < 0.3;
        changed.push({ kind: 'inbound', msg: this.inbound({ carried: carried, ageMs: this.rint(6, 48) * 60000 }) });
      }
    }

    var inCh = this.inChannelInRange();

    for (i = 0; i < this.msgs.length; i++) {
      m = this.msgs[i];
      if (!m.mine) continue;

      if (m.state === 'hold') {
        if (now >= m.holdUntil) {
          this.setState(m, 'queued', now);
          m.tQueued = now;
          m.dueAt = 0;
          changed.push({ kind: 'state', msg: m });
        }
        continue;
      }

      if (m.state === 'queued') {
        if (m.courier && this.peers.length) {
          // Somebody is physically here and takes custody, in or out of channel.
          var carrier = this.pick(this.peers);
          m.carriers = [carrier.nick];
          m.carryUntil = now + this.rint(CARRY_MIN_MS, CARRY_MAX_MS);
          this.setState(m, 'carried', now);
          changed.push({ kind: 'state', msg: m });
        } else if (!m.courier && inCh.length) {
          if (!m.dueAt) m.dueAt = now + this.rint(DELIVER_MIN_MS, DELIVER_MAX_MS);
          if (now >= m.dueAt) {
            this.setState(m, 'delivered', now);
            m.nextReadAt = this.rnd() < READ_CHANCE ? now + this.rint(READ_MIN_MS, READ_MAX_MS) : 0;
            changed.push({ kind: 'state', msg: m });
          }
        } else {
          m.dueAt = 0;
          if (now - m.tQueued > EXPIRY_MS) {
            this.setState(m, 'expired', now);
            changed.push({ kind: 'state', msg: m });
          }
        }
        continue;
      }

      if (m.state === 'carried') {
        if (now >= m.carryUntil) {
          this.setState(m, 'delivered', now);
          m.nextReadAt = this.rnd() < READ_CHANCE ? now + this.rint(READ_MIN_MS, READ_MAX_MS) : 0;
          changed.push({ kind: 'state', msg: m });
        }
        continue;
      }

      if ((m.state === 'delivered' || m.state === 'read') && m.nextReadAt && now >= m.nextReadAt) {
        m.readers += 1;
        if (m.state !== 'read') { this.setState(m, 'read', now); }
        changed.push({ kind: 'state', msg: m });
        m.nextReadAt = (m.readers < Math.max(1, inCh.length) && this.rnd() < 0.5)
          ? now + this.rint(READ_MIN_MS, READ_MAX_MS) : 0;
      }
    }

    // Position drifts a little, as a real fix does.
    this.pos.lat += (this.rnd() - 0.5) * 0.00004;
    this.pos.lon += (this.rnd() - 0.5) * 0.00004;
    this.pos.acc = Math.max(12, Math.min(95, this.pos.acc + (this.rnd() - 0.5) * 6));

    return changed;
  };

  return {
    create: function (seed) { return new Sim(seed); },
    HOLD_MS: HOLD_MS,
    EXPIRY_MS: EXPIRY_MS
  };
})();
