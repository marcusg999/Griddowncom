/* Minimal QR encoder: byte mode, ECC L/M, versions 1-10.
 *
 * Written from the spec rather than pulled from a CDN, because the prototype
 * has to open from the filesystem with no network at all -- the same constraint
 * the product itself lives under.
 *
 * Verified: for versions 1-10, ECC levels L and M and all 8 mask patterns, the
 * module matrix produced here is byte-identical to the `qrcode` 8.2 reference
 * implementation over a corpus of non-numeric payloads (640/640 matrices).
 * Numeric-only payloads differ by design: this encoder is byte-mode only, and
 * the reference switches to numeric mode. Channel payloads are never numeric.
 */
var QR = (function () {
  // --- GF(256), primitive polynomial 0x11d -------------------------------
  var EXP = new Uint8Array(512), LOG = new Uint8Array(256);
  (function () {
    var x = 1, i;
    for (i = 0; i < 255; i++) {
      EXP[i] = x; LOG[x] = i;
      x <<= 1; if (x & 0x100) x ^= 0x11d;
    }
    for (i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
  })();
  function gmul(a, b) { return (a === 0 || b === 0) ? 0 : EXP[LOG[a] + LOG[b]]; }

  function rsGenerator(deg) {
    var poly = [1];
    for (var i = 0; i < deg; i++) {
      var next = new Array(poly.length + 1).fill(0);
      for (var j = 0; j < poly.length; j++) {
        next[j] ^= gmul(poly[j], 1);
        next[j + 1] ^= gmul(poly[j], EXP[i]);
      }
      poly = next;
    }
    return poly;
  }

  function rsRemainder(data, deg) {
    var gen = rsGenerator(deg);
    var res = new Array(deg).fill(0);
    for (var i = 0; i < data.length; i++) {
      var factor = data[i] ^ res[0];
      res.shift(); res.push(0);
      for (var j = 0; j < deg; j++) res[j] ^= gmul(gen[j + 1], factor);
    }
    return res;
  }

  // --- capacity tables: [ecPerBlock, blocks1, dataCw1, blocks2, dataCw2] --
  var BLOCKS = {
    L: [null,
      [7, 1, 19, 0, 0], [10, 1, 34, 0, 0], [15, 1, 55, 0, 0], [20, 1, 80, 0, 0],
      [26, 1, 108, 0, 0], [18, 2, 68, 0, 0], [20, 2, 78, 0, 0], [24, 2, 97, 0, 0],
      [30, 2, 116, 0, 0], [18, 2, 68, 2, 69]],
    M: [null,
      [10, 1, 16, 0, 0], [16, 1, 28, 0, 0], [26, 1, 44, 0, 0], [18, 2, 32, 0, 0],
      [24, 2, 43, 0, 0], [16, 4, 27, 0, 0], [18, 4, 31, 0, 0], [22, 2, 38, 2, 39],
      [22, 3, 36, 2, 37], [26, 4, 43, 1, 44]]
  };
  var ALIGN = [null, [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34],
    [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50]];
  var ECL_BITS = { L: 1, M: 0 };

  function dataCapacityBytes(ver, ecl) {
    var b = BLOCKS[ecl][ver];
    var cw = b[1] * b[2] + b[3] * b[4];
    return Math.floor((cw * 8 - 4 - (ver < 10 ? 8 : 16)) / 8);
  }

  function BitBuf() { this.bits = []; }
  BitBuf.prototype.put = function (val, len) {
    for (var i = len - 1; i >= 0; i--) this.bits.push((val >>> i) & 1);
  };

  function encode(text, ecl, minVersion, forcedMask) {
    ecl = ecl || 'L';
    var bytes = utf8(text);
    var ver = minVersion || 1;
    while (ver <= 10 && dataCapacityBytes(ver, ecl) < bytes.length) ver++;
    if (ver > 10) throw new Error('payload too long for this encoder');

    var spec = BLOCKS[ecl][ver];
    var ecPer = spec[0], nb1 = spec[1], dc1 = spec[2], nb2 = spec[3], dc2 = spec[4];
    var totalData = nb1 * dc1 + nb2 * dc2;
    var i, j, k, b;

    var bb = new BitBuf();
    bb.put(4, 4);                               // byte mode
    bb.put(bytes.length, ver < 10 ? 8 : 16);
    for (i = 0; i < bytes.length; i++) bb.put(bytes[i], 8);
    bb.put(0, Math.min(4, totalData * 8 - bb.bits.length));
    while (bb.bits.length % 8 !== 0) bb.bits.push(0);
    var data = [];
    for (i = 0; i < bb.bits.length; i += 8) {
      var v = 0;
      for (k = 0; k < 8; k++) v = (v << 1) | bb.bits[i + k];
      data.push(v);
    }
    var padBytes = [0xEC, 0x11], p = 0;
    while (data.length < totalData) data.push(padBytes[p++ % 2]);

    var blocks = [], ecblocks = [], off = 0;
    for (i = 0; i < nb1 + nb2; i++) {
      var n = i < nb1 ? dc1 : dc2;
      var blk = data.slice(off, off + n); off += n;
      blocks.push(blk);
      ecblocks.push(rsRemainder(blk, ecPer));
    }
    var final_ = [];
    var maxData = Math.max(dc1, dc2);
    for (i = 0; i < maxData; i++)
      for (b = 0; b < blocks.length; b++)
        if (i < blocks[b].length) final_.push(blocks[b][i]);
    for (i = 0; i < ecPer; i++)
      for (b = 0; b < ecblocks.length; b++) final_.push(ecblocks[b][i]);

    var size = ver * 4 + 17;
    var mods = new Int8Array(size * size).fill(-1);
    var fn = new Uint8Array(size * size);
    function set(x, y, val, isFn) {
      if (x < 0 || y < 0 || x >= size || y >= size) return;
      mods[y * size + x] = val ? 1 : 0;
      if (isFn) fn[y * size + x] = 1;
    }
    function finder(cx, cy) {
      for (var dy = -4; dy <= 4; dy++) for (var dx = -4; dx <= 4; dx++) {
        var d = Math.max(Math.abs(dx), Math.abs(dy));
        set(cx + dx, cy + dy, d !== 2 && d !== 4, true);
      }
    }
    finder(3, 3); finder(size - 4, 3); finder(3, size - 4);
    for (i = 8; i < size - 8; i++) { set(6, i, i % 2 === 0, true); set(i, 6, i % 2 === 0, true); }
    var ac = ALIGN[ver];
    for (i = 0; i < ac.length; i++) for (j = 0; j < ac.length; j++) {
      if ((i === 0 && j === 0) || (i === 0 && j === ac.length - 1) ||
          (i === ac.length - 1 && j === 0)) continue;
      for (var dy2 = -2; dy2 <= 2; dy2++) for (var dx2 = -2; dx2 <= 2; dx2++)
        set(ac[j] + dx2, ac[i] + dy2, Math.max(Math.abs(dx2), Math.abs(dy2)) !== 1, true);
    }
    for (i = 0; i <= 8; i++) if (i !== 6) { set(i, 8, 0, true); set(8, i, 0, true); }
    for (i = 0; i < 8; i++) { set(size - 1 - i, 8, 0, true); set(8, size - 1 - i, 0, true); }
    set(8, size - 8, 1, true);
    if (ver >= 7) {
      var rem = ver;
      for (i = 0; i < 12; i++) rem = (rem << 1) ^ (((rem >>> 11) & 1) * 0x1f25);
      var vinfo = ((ver << 12) | (rem & 0xfff)) >>> 0;
      for (i = 0; i < 18; i++) {
        var bit = (vinfo >>> i) & 1;
        set(Math.floor(i / 3), size - 11 + (i % 3), bit, true);
        set(size - 11 + (i % 3), Math.floor(i / 3), bit, true);
      }
    }

    var bitIdx = 0;
    function nextBit() {
      if (bitIdx >= final_.length * 8) return 0;
      var byteI = bitIdx >> 3, bitI = 7 - (bitIdx & 7);
      bitIdx++;
      return (final_[byteI] >>> bitI) & 1;
    }
    var upward = true;
    for (var col = size - 1; col >= 1; col -= 2) {
      if (col === 6) col = 5;
      for (var row = 0; row < size; row++) {
        var y2 = upward ? size - 1 - row : row;
        for (var c = 0; c < 2; c++) {
          var x2 = col - c;
          if (fn[y2 * size + x2]) continue;
          mods[y2 * size + x2] = nextBit();
        }
      }
      upward = !upward;
    }

    var best = null, bestPen = Infinity, bestMask = 0;
    var mFrom = (forcedMask == null ? 0 : forcedMask);
    var mTo = (forcedMask == null ? 8 : forcedMask + 1);
    for (var m = mFrom; m < mTo; m++) {
      var cand = Int8Array.from(mods);
      applyMask(cand, fn, size, m);
      drawFormat(cand, size, ecl, m);
      var pen = penalty(cand, size);
      if (pen < bestPen) { bestPen = pen; best = cand; bestMask = m; }
    }
    return { size: size, modules: best, version: ver, mask: bestMask, ecl: ecl };
  }

  function maskFn(m, x, y) {
    switch (m) {
      case 0: return (x + y) % 2 === 0;
      case 1: return y % 2 === 0;
      case 2: return x % 3 === 0;
      case 3: return (x + y) % 3 === 0;
      case 4: return (Math.floor(y / 2) + Math.floor(x / 3)) % 2 === 0;
      case 5: return (x * y) % 2 + (x * y) % 3 === 0;
      case 6: return ((x * y) % 2 + (x * y) % 3) % 2 === 0;
      default: return ((x + y) % 2 + (x * y) % 3) % 2 === 0;
    }
  }
  function applyMask(mods, fn, size, m) {
    for (var y = 0; y < size; y++) for (var x = 0; x < size; x++)
      if (!fn[y * size + x] && maskFn(m, x, y)) mods[y * size + x] ^= 1;
  }
  function drawFormat(mods, size, ecl, mask) {
    var d = (ECL_BITS[ecl] << 3) | mask, rem = d, i;
    for (i = 0; i < 10; i++) rem = (rem << 1) ^ (((rem >>> 9) & 1) * 0x537);
    var bits = (((d << 10) | (rem & 0x3ff)) ^ 0x5412) >>> 0;
    for (i = 0; i < 15; i++) {                       // vertical, column 8
      var b = (bits >>> i) & 1;
      if (i < 6) mods[i * size + 8] = b;
      else if (i < 8) mods[(i + 1) * size + 8] = b;
      else mods[(size - 15 + i) * size + 8] = b;
    }
    for (i = 0; i < 15; i++) {                       // horizontal, row 8
      var b2 = (bits >>> i) & 1;
      if (i < 8) mods[8 * size + (size - 1 - i)] = b2;
      else if (i < 9) mods[8 * size + 7] = b2;
      else mods[8 * size + (14 - i)] = b2;
    }
    mods[(size - 8) * size + 8] = 1;                 // always-dark module
  }

  function penalty(mods, size) {
    var pen = 0, x, y, i, run;
    function at(x, y) { return mods[y * size + x]; }
    for (y = 0; y < size; y++) {
      run = 1;
      for (x = 1; x < size; x++) {
        if (at(x, y) === at(x - 1, y)) { run++; if (run === 5) pen += 3; else if (run > 5) pen += 1; }
        else run = 1;
      }
    }
    for (x = 0; x < size; x++) {
      run = 1;
      for (y = 1; y < size; y++) {
        if (at(x, y) === at(x, y - 1)) { run++; if (run === 5) pen += 3; else if (run > 5) pen += 1; }
        else run = 1;
      }
    }
    for (y = 0; y < size - 1; y++) for (x = 0; x < size - 1; x++) {
      var v = at(x, y);
      if (v === at(x + 1, y) && v === at(x, y + 1) && v === at(x + 1, y + 1)) pen += 3;
    }
    var P1 = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0];
    var P2 = [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1];
    for (y = 0; y < size; y++) for (x = 0; x + 11 <= size; x++) {
      var m1 = true, m2 = true;
      for (i = 0; i < 11; i++) {
        var v3 = at(x + i, y);
        if (v3 !== P1[i]) m1 = false;
        if (v3 !== P2[i]) m2 = false;
      }
      if (m1) pen += 40;
      if (m2) pen += 40;
    }
    for (x = 0; x < size; x++) for (y = 0; y + 11 <= size; y++) {
      var n1 = true, n2 = true;
      for (i = 0; i < 11; i++) {
        var v4 = at(x, y + i);
        if (v4 !== P1[i]) n1 = false;
        if (v4 !== P2[i]) n2 = false;
      }
      if (n1) pen += 40;
      if (n2) pen += 40;
    }
    var dark = 0;
    for (i = 0; i < size * size; i++) if (mods[i] === 1) dark++;
    pen += Math.floor(Math.abs(dark * 100 / (size * size) - 50) / 5) * 10;
    return pen;
  }

  function utf8(s) {
    var out = [];
    for (var i = 0; i < s.length; i++) {
      var c = s.charCodeAt(i);
      if (c < 0x80) out.push(c);
      else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
      else out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    }
    return out;
  }

  /* Paint onto a canvas. quiet = modules of light margin (spec minimum 4). */
  function draw(canvas, text, opts) {
    opts = opts || {};
    var r = encode(text, opts.ecl || 'L');
    var quiet = opts.quiet == null ? 4 : opts.quiet;
    var total = r.size + quiet * 2;
    var px = Math.max(1, Math.floor((opts.px || 240) / total));
    var side = px * total;
    var dpr = (window.devicePixelRatio || 1);
    canvas.width = side * dpr; canvas.height = side * dpr;
    canvas.style.width = side + 'px'; canvas.style.height = side + 'px';
    var g = canvas.getContext('2d');
    g.setTransform(dpr, 0, 0, dpr, 0, 0);
    g.fillStyle = opts.light || '#ffffff';
    g.fillRect(0, 0, side, side);
    g.fillStyle = opts.dark || '#000000';
    for (var y = 0; y < r.size; y++) for (var x = 0; x < r.size; x++)
      if (r.modules[y * r.size + x] === 1)
        g.fillRect((x + quiet) * px, (y + quiet) * px, px, px);
    return r;
  }

  return { encode: encode, draw: draw };
})();
if (typeof module !== 'undefined') module.exports = QR;
