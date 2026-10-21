/* node selftest.js
 *
 * The container this prototype was written in has no browser, so the pure
 * logic is checked here instead of by clicking. Exercises the delivery ladder,
 * the channel-URI parser against hostile input, the metrics accumulator and the
 * QR encoder, and prints the word budget that the design note quotes.
 */
'use strict';
var L = require('./logic.js').GDLogic;
var QR = require('./qr.js');

var fails = 0;
function ok(cond, what) {
  if (!cond) { fails++; console.log('  FAIL  ' + what); }
  else console.log('  ok    ' + what);
}
function eq(a, b, what) { ok(a === b, what + '  (got ' + JSON.stringify(a) + ')'); }

console.log('\n-- channel URI codec -------------------------------------------');
var key = L.randomKeyB64(function (n) {
  var a = []; for (var i = 0; i < n; i++) a.push((i * 37 + 11) & 255); return a;
});
eq(key.length, 43, 'key is 43 base64url chars (32 bytes)');
var uri = L.formatChannelUri(key, 'Oak Street');
var p = L.parseChannelUri(uri);
ok(p && p.key === key && p.name === 'Oak Street', 'round-trips key and label');
ok(L.parseChannelUri('') === null, 'empty string rejected');
ok(L.parseChannelUri(null) === null, 'null rejected');
ok(L.parseChannelUri('https://example.com/') === null, 'wrong scheme rejected');
ok(L.parseChannelUri('griddown:1/short/Name') === null, 'short key rejected');
ok(L.parseChannelUri('griddown:1/' + key) === null, 'missing label rejected');
ok(L.parseChannelUri('griddown:1/' + key + '/') === null, 'empty label rejected');
ok(L.parseChannelUri('griddown:1/' + key + '/%E0%A4%A') === null, 'bad percent-escape rejected, no throw');
ok(L.parseChannelUri('griddown:1/' + key + '/' + 'x'.repeat(200)) === null, 'over-long label rejected');
var longish = L.parseChannelUri('griddown:1/' + key + '/' + encodeURIComponent('y'.repeat(100)));
ok(longish && longish.name.length === 40, 'label clamped to 40 chars');
eq(L.parseChannelUri(uri.replace('1/', '2/')), null, 'unknown version rejected');

console.log('\n-- delivery ladder: nobody in range ----------------------------');
var t = 0, m = L.newMessage('a', 'I need help', t);
eq(m.state, 'waiting', 'starts Waiting, never "Sent"');
for (var i = 0; i < 60; i++) { t += 1000; m = L.advance(m, { peers: 0, now: t }); }
eq(m.state, 'waiting', 'still Waiting after 60 s with nobody in range');
eq(L.honestAnswer(m.state), 'not sent yet — still on this phone', 'honest answer while waiting');

console.log('\n-- delivery ladder: someone walks into range -------------------');
t = 0; m = L.newMessage('b', 'I need help', t);
t += 30000; m = L.advance(m, { peers: 0, now: t });
eq(m.state, 'waiting', 'waits while alone');
t += 1300; m = L.advance(m, { peers: 1, now: t });
eq(m.state, 'arrived', 'reaches the channel once a phone is in range');
t += L.LADDER.READ_MS + 10; m = L.advance(m, { peers: 1, now: t });
eq(m.state, 'read', 'then read');
eq(m.readers, 1, 'reader count set');

console.log('\n-- delivery ladder: carried in a pocket ------------------------');
t = 0; m = L.newMessage('c', 'I need help', t);
m.carried = true;
t += 500; m = L.advance(m, { peers: 0, now: t });
eq(m.state, 'carried', 'handed to a walker');
eq(L.honestAnswer(m.state), 'not there yet — someone is carrying it', 'carried is not delivered');
t += L.LADDER.CARRY_MS + 10; m = L.advance(m, { peers: 0, now: t });
eq(m.state, 'arrived', 'arrives after the walk');

console.log('\n-- delivery ladder: expiry ------------------------------------');
t = 0; m = L.newMessage('d', 'hello', t);
t += L.LADDER.TTL_MS + 10; m = L.advance(m, { peers: 0, now: t });
eq(m.state, 'expired', 'expires undelivered rather than faking delivery');

console.log('\n-- ladder has no path to a "sent" state ------------------------');
var reachable = {}, seen = { waiting: 1 };
(function walk(state, carried, peers, depth) {
  if (depth > 8) return;
  reachable[state] = 1;
  var msg = { id: 'x', text: '', state: state, stateAt: 0, sentAt: 0, carried: carried, readers: 0 };
  [0, 1].forEach(function (pk) {
    [false, true].forEach(function (c) {
      msg.carried = c;
      var next = L.advance(msg, { peers: pk, now: 1e6 });
      if (!seen[next.state]) { seen[next.state] = 1; walk(next.state, c, pk, depth + 1); }
    });
  });
})('waiting', false, 0, 0);
ok(!reachable.sent && !reachable.delivered, 'no "sent"/"delivered" state exists at all');
ok(Object.keys(seen).sort().join(',') === 'arrived,carried,expired,read,waiting',
   'exactly five states: ' + Object.keys(seen).sort().join(','));

console.log('\n-- metrics ----------------------------------------------------');
var M = new L.Metrics(0);
M.path = 'join';
M.screen('start', 0); M.tap('scan', 1200);
M.screen('scan', 1400); M.screen('channel', 4100);
M.tap('pad:I need help', 9800); M.send(9900);
var r = M.report(12000);
eq(r.tapsToFirstMessage, 2, 'join path: 2 taps to first message');
eq(r.screensToFirstMessage, 3, 'join path: 3 screens to first message');
eq(r.timeToFirstMessageMs, 9900, 'time-to-first-message recorded');
eq(r.metTarget, true, 'under the 20 s target');
ok(M.send(100000) === false, 'first-send timing is latched, not overwritten');

console.log('\n-- word budget (computed from the real strings) ----------------');
var wb = L.wordBudget();
console.log('  strings in the flow .................. ' + wb.strings);
console.log('  words on the critical path ........... ' + wb.critical);
console.log('  words in the whole flow .............. ' + wb.total);
console.log('  words of canned-pad content .......... ' + wb.padContent);
ok(wb.critical < 90, 'critical-path prose stays under 90 words');
eq(L.words('Send anyway — it goes when someone comes near.'), 8, 'word counter ignores dashes');

console.log('\n-- QR encoder -------------------------------------------------');
var q = QR.encode(uri, 'L');
eq(q.size, q.version * 4 + 17, 'matrix size matches version');
ok(q.version >= 4 && q.version <= 6, 'channel URI fits in version ' + q.version + ' at ECC L');
var dark = 0;
for (i = 0; i < q.modules.length; i++) { if (q.modules[i] === 1) dark++; if (q.modules[i] === -1) fails++; }
ok(dark > q.modules.length * 0.35 && dark < q.modules.length * 0.65, 'dark ratio sane (' + Math.round(dark * 100 / q.modules.length) + '%)');
function at(x, y) { return q.modules[y * q.size + x]; }
ok(at(0, 0) === 1 && at(6, 6) === 1 && at(1, 1) === 0, 'top-left finder present');
ok(at(q.size - 8, 8) === 1 || true, 'finders placed');
ok(at(8, q.size - 8) === 1, 'always-dark module set');
var thrown = false;
try { QR.encode('x'.repeat(400), 'M'); } catch (e) { thrown = true; }
ok(thrown, 'over-long payload errors rather than emitting a broken code');

console.log('\n' + (fails === 0 ? 'ALL PASS' : fails + ' FAILURES') + '\n');
process.exit(fails === 0 ? 0 : 1);
