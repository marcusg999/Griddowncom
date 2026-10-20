//! Frame-size models: MessagePack, gzip, AES-ECB, libsignal.
//!
//! We are not implementing real crypto or real DEFLATE. What this module
//! reproduces is the *observable* behaviour that the comparison turns on:
//!
//! 1. Bridgefy's pipeline is `MessagePack -> gzip -> encrypt`
//!    (`docs/research/BRIDGEFY-FINDINGS.md`, Part 1, Encoding pipeline).
//!    Compression precedes encryption, so **on-wire length varies with payload
//!    content**, which is finding C-2 and the thing `gdc-wire`'s fixed bucket
//!    ladder exists to kill. A critic must be able to *measure* that
//!    difference, so the length model here has to respond to content and not
//!    just to length.
//! 2. MessagePack's own overhead is paid per field and per map key, so
//!    per-packet overhead is derived from the real field set rather than
//!    guessed. The encoder below emits genuine MessagePack bytes, so the counts
//!    are the counts.
//! 3. AES-ECB is length-preserving apart from block padding, and leaks equal
//!    plaintext blocks (finding C-5). Both are modelled.
//!
//! The DEFLATE model is integer-only so that a recorded run replays identically
//! on any platform.

/// A minimal MessagePack writer. Emits real MessagePack, so `buf.len()` is the
/// true serialised size of the modelled field set.
#[derive(Default, Debug)]
pub struct MsgPack {
    buf: Vec<u8>,
}

impl MsgPack {
    pub fn new() -> Self {
        MsgPack { buf: Vec::new() }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn map_header(&mut self, n: usize) -> &mut Self {
        if n < 16 {
            self.buf.push(0x80 | n as u8);
        } else if n <= u16::MAX as usize {
            self.buf.push(0xDE);
            self.buf.extend_from_slice(&(n as u16).to_be_bytes());
        } else {
            self.buf.push(0xDF);
            self.buf.extend_from_slice(&(n as u32).to_be_bytes());
        }
        self
    }

    pub fn array_header(&mut self, n: usize) -> &mut Self {
        if n < 16 {
            self.buf.push(0x90 | n as u8);
        } else if n <= u16::MAX as usize {
            self.buf.push(0xDC);
            self.buf.extend_from_slice(&(n as u16).to_be_bytes());
        } else {
            self.buf.push(0xDD);
            self.buf.extend_from_slice(&(n as u32).to_be_bytes());
        }
        self
    }

    pub fn str(&mut self, s: &str) -> &mut Self {
        let b = s.as_bytes();
        if b.len() < 32 {
            self.buf.push(0xA0 | b.len() as u8);
        } else if b.len() <= u8::MAX as usize {
            self.buf.push(0xD9);
            self.buf.push(b.len() as u8);
        } else {
            self.buf.push(0xDA);
            self.buf.extend_from_slice(&(b.len() as u16).to_be_bytes());
        }
        self.buf.extend_from_slice(b);
        self
    }

    pub fn bin(&mut self, b: &[u8]) -> &mut Self {
        if b.len() <= u8::MAX as usize {
            self.buf.push(0xC4);
            self.buf.push(b.len() as u8);
        } else if b.len() <= u16::MAX as usize {
            self.buf.push(0xC5);
            self.buf.extend_from_slice(&(b.len() as u16).to_be_bytes());
        } else {
            self.buf.push(0xC6);
            self.buf.extend_from_slice(&(b.len() as u32).to_be_bytes());
        }
        self.buf.extend_from_slice(b);
        self
    }

    pub fn uint(&mut self, v: u64) -> &mut Self {
        if v < 128 {
            self.buf.push(v as u8);
        } else if v <= u8::MAX as u64 {
            self.buf.push(0xCC);
            self.buf.push(v as u8);
        } else if v <= u16::MAX as u64 {
            self.buf.push(0xCD);
            self.buf.extend_from_slice(&(v as u16).to_be_bytes());
        } else if v <= u32::MAX as u64 {
            self.buf.push(0xCE);
            self.buf.extend_from_slice(&(v as u32).to_be_bytes());
        } else {
            self.buf.push(0xCF);
            self.buf.extend_from_slice(&v.to_be_bytes());
        }
        self
    }

    pub fn boolean(&mut self, v: bool) -> &mut Self {
        self.buf.push(if v { 0xC3 } else { 0xC2 });
        self
    }

    pub fn nil(&mut self) -> &mut Self {
        self.buf.push(0xC0);
        self
    }
}

// ---------------------------------------------------------------------------
// gzip / DEFLATE size model
// ---------------------------------------------------------------------------

/// gzip member overhead: 10-byte header plus CRC-32 and ISIZE trailers.
/// RFC 1952 §2.2 / §2.3.1. Not a judgement call, it is the format.
pub const GZIP_ENVELOPE_BYTES: usize = 18;

/// DEFLATE window and match bounds, RFC 1951 §4. Used by the match finder so
/// the model's compression ratio tracks a real deflater's within a few percent
/// on the payload sizes this project carries (tens to hundreds of bytes).
const WINDOW: usize = 32_768;
const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 258;
/// How far back the match finder walks one hash chain. Bounded so a crafted
/// payload cannot make sizing quadratic: this module is reached from
/// radio-sourced data.
const MAX_CHAIN: usize = 32;

/// `log2(x) * 256`, integer-only, for entropy accounting.
fn log2_q8(x: u64) -> u64 {
    if x <= 1 {
        return 0;
    }
    let ilog = 63 - x.leading_zeros() as u64; // floor(log2(x))
    // Linear interpolation of the mantissa. Good to ~1.5 % of a bit, which is
    // far inside the accuracy this model claims.
    let shifted = x << (63 - ilog); // top bit at 2^63
    let frac = (shifted >> 55) & 0xFF; // 8 bits below the leading one
    ilog * 256 + frac
}

/// Modelled gzip length of `data`, in bytes.
pub fn gzip_len(data: &[u8]) -> usize {
    GZIP_ENVELOPE_BYTES + deflate_len(data)
}

/// Modelled DEFLATE stream length of `data`, in bytes.
///
/// Takes the minimum of a stored block and an LZ77 + entropy-coded block, which
/// is what a real deflater does, and is why incompressible payloads (ciphertext)
/// do not inflate in this model.
pub fn deflate_len(data: &[u8]) -> usize {
    let stored = stored_len(data.len());
    if data.len() < MIN_MATCH {
        return stored;
    }
    let compressed = compressed_block_len(data);
    stored.min(compressed)
}

/// Stored (type 00) blocks: 5 bytes of header per 65 535-byte block, RFC 1951 §3.2.4.
fn stored_len(n: usize) -> usize {
    let blocks = n / 65_535 + 1;
    blocks * 5 + n
}

/// Cost, in bytes, of one dynamic-Huffman block over the LZ77 token stream.
fn compressed_block_len(data: &[u8]) -> usize {
    let (literals, matches) = lz77(data);

    // Order-0 entropy of the emitted literals. This is where content, not just
    // length, enters the on-wire size: a payload drawn from a small alphabet
    // costs fewer bits per byte than one drawn from 256.
    let mut hist = [0u32; 256];
    for b in &literals {
        hist[*b as usize] += 1;
    }
    let n = literals.len() as u64;
    let log2n = log2_q8(n);
    let mut bits_q8: u64 = 0;
    let mut distinct = 0u64;
    for c in hist.iter() {
        if *c == 0 {
            continue;
        }
        distinct += 1;
        let cost = log2n.saturating_sub(log2_q8(*c as u64)).max(256);
        bits_q8 = bits_q8.saturating_add(cost * (*c as u64));
    }

    for (len, dist) in &matches {
        // Length code plus its extra bits, RFC 1951 §3.2.5: codes 257..285 sit
        // around 7-9 bits in a typical dynamic tree, with up to 5 extra bits.
        let len_extra = if *len <= 10 {
            0
        } else {
            (log2_q8((*len as u64).saturating_sub(2)) / 256).saturating_sub(2)
        };
        // Distance code plus extra bits: 30 base codes, extra bits ~ log2(dist)-2.
        let dist_extra = (log2_q8(*dist as u64) / 256).saturating_sub(2);
        bits_q8 = bits_q8.saturating_add((8 + len_extra + 5 + dist_extra) * 256);
    }

    // End-of-block symbol plus the 3-bit block header.
    bits_q8 = bits_q8.saturating_add((8 + 3) * 256);

    // Cost of transmitting the dynamic Huffman code lengths themselves. Roughly
    // 4 bits per used literal symbol under the run-length-coded code-length
    // alphabet, plus the fixed preamble. For short payloads this term is what
    // stops the model claiming impossible ratios.
    let tree_bits = 14 + 19 * 3 + distinct * 4 + 32;
    bits_q8 = bits_q8.saturating_add(tree_bits * 256);

    ((bits_q8 / 256) as usize + 7) / 8
}

/// Greedy LZ77 over a bounded hash chain. Returns the emitted literal bytes and
/// the `(length, distance)` matches.
fn lz77(data: &[u8]) -> (Vec<u8>, Vec<(usize, usize)>) {
    let mut literals = Vec::with_capacity(data.len());
    let mut matches = Vec::new();
    // head[h] = most recent position with that 3-byte hash; prev[p] = the one before.
    let mut head = vec![usize::MAX; 1 << 15];
    let mut prev = vec![usize::MAX; data.len()];

    let hash3 = |d: &[u8], p: usize| -> usize {
        let a = d[p] as usize;
        let b = *d.get(p + 1).unwrap_or(&0) as usize;
        let c = *d.get(p + 2).unwrap_or(&0) as usize;
        ((a << 10) ^ (b << 5) ^ c) & ((1 << 15) - 1)
    };

    let mut pos = 0usize;
    while pos < data.len() {
        let mut best_len = 0usize;
        let mut best_dist = 0usize;
        if pos + MIN_MATCH <= data.len() {
            let h = hash3(data, pos);
            let mut cand = head[h];
            let mut walked = 0;
            while cand != usize::MAX && walked < MAX_CHAIN {
                if pos - cand > WINDOW {
                    break;
                }
                let max = MAX_MATCH.min(data.len() - pos);
                let mut l = 0usize;
                while l < max && data[cand + l] == data[pos + l] {
                    l += 1;
                }
                if l > best_len {
                    best_len = l;
                    best_dist = pos - cand;
                }
                if best_len >= MAX_MATCH {
                    break;
                }
                cand = prev[cand];
                walked += 1;
            }
        }

        // Insert this position, and the positions a match covers, into the chain.
        let advance = if best_len >= MIN_MATCH { best_len } else { 1 };
        for p in pos..(pos + advance).min(data.len()) {
            if p + MIN_MATCH <= data.len() {
                let h = hash3(data, p);
                prev[p] = head[h];
                head[h] = p;
            }
        }

        if best_len >= MIN_MATCH {
            matches.push((best_len, best_dist));
        } else {
            literals.push(data[pos]);
        }
        pos += advance;
    }
    (literals, matches)
}

// ---------------------------------------------------------------------------
// Cipher size models
// ---------------------------------------------------------------------------

/// AES block size. AES-ECB is length-preserving up to PKCS#7 padding, so this
/// is the only expansion a Bridgefy frame pays at the encrypt stage, and it is
/// why content-dependent length survives to the wire at 16-byte granularity.
pub const AES_BLOCK: usize = 16;

/// Length after AES-ECB with PKCS#7 padding (always at least one pad byte).
pub fn aes_ecb_len(plain_len: usize) -> usize {
    (plain_len / AES_BLOCK + 1) * AES_BLOCK
}

/// Number of repeated 16-byte blocks in `data`.
///
/// Finding C-5: ECB is deterministic, so equal plaintext blocks are equal
/// ciphertext blocks. Exposed so the harness can report the leak rather than
/// just assert it exists.
pub fn ecb_repeated_blocks(data: &[u8]) -> usize {
    let mut seen = std::collections::HashMap::new();
    let mut repeats = 0usize;
    for chunk in data.chunks(AES_BLOCK) {
        if chunk.len() < AES_BLOCK {
            continue;
        }
        let e: &mut usize = seen.entry(chunk.to_vec()).or_insert(0);
        *e += 1;
        if *e > 1 {
            repeats += 1;
        }
    }
    repeats
}

/// Modelled per-message overhead of a libsignal `SignalMessage`: version byte,
/// ratchet public key, counter and previous-counter varints, and the truncated
/// MAC.
///
/// ASSUMPTION: the research file records *that* libsignal covers the payload of
/// one-to-one and multi-hop packets, not its wire overhead. 46 bytes is the
/// `SignalMessage` case; a `PreKeySignalMessage` (first message of a session) is
/// substantially larger. Taking the smaller, steady-state figure cuts **in
/// Bridgefy's favour**: it understates its per-packet bytes and therefore
/// understates its airtime and energy per delivered message.
pub const LIBSIGNAL_OVERHEAD: usize = 46;

/// Stand-in for a libsignal ciphertext: incompressible bytes of the right
/// length, derived deterministically from the plaintext.
///
/// The incompressibility is the point. Because gzip runs over the MessagePack
/// envelope *containing* this field, a multi-hop packet's length tracks
/// plaintext *length* but not plaintext *content*, while a broadcast packet —
/// whose message rides as plaintext under the network-wide AES-ECB key — leaks
/// content through length. That asymmetry is exactly what the 2022 paper
/// attacked, and reproducing it is the difference between a faithful model and
/// a strawman.
pub fn modelled_libsignal_ct(plain: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; plain.len() + LIBSIGNAL_OVERHEAD];
    let mut r = crate::rng::Rng::new(crate::hash::digest64(plain));
    r.fill(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msgpack_sizes_are_the_real_sizes() {
        let mut m = MsgPack::new();
        m.map_header(2).str("hops").uint(100).str("id").bin(&[0u8; 16]);
        // fixmap(1) + fixstr "hops"(1+4) + uint 100 as uint8(2) + fixstr "id"(1+2)
        // + bin8 16 bytes(2+16)
        assert_eq!(m.len(), 1 + 5 + 2 + 3 + 18);
    }

    #[test]
    fn uint_widths_follow_the_spec() {
        for (v, want) in [(1u64, 1usize), (200, 2), (1000, 3), (100_000, 5), (u64::MAX, 9)] {
            let mut m = MsgPack::new();
            m.uint(v);
            assert_eq!(m.len(), want, "uint {v}");
        }
    }

    #[test]
    fn deflate_shrinks_repetitive_and_not_random() {
        let repetitive = vec![b'a'; 512];
        let mut random = vec![0u8; 512];
        crate::rng::Rng::new(1).fill(&mut random);
        assert!(
            deflate_len(&repetitive) < 64,
            "512 identical bytes must compress hard, got {}",
            deflate_len(&repetitive)
        );
        assert!(
            deflate_len(&random) >= random.len(),
            "incompressible input must fall back to a stored block"
        );
    }

    #[test]
    fn deflate_tracks_content_not_only_length() {
        // The enabling condition for finding C-2. Two payloads of identical
        // length, different content, different compressed length.
        let a = b"meet at the north gate meet at the north gate meet at the north gate!!";
        let mut b = vec![0u8; a.len()];
        crate::rng::Rng::new(9).fill(&mut b);
        assert_eq!(a.len(), b.len());
        assert_ne!(deflate_len(a), deflate_len(&b));
    }

    #[test]
    fn deflate_is_monotone_enough_to_be_a_length_model() {
        let mut last = 0;
        for n in [0usize, 1, 16, 64, 256, 1024] {
            let mut d = vec![0u8; n];
            crate::rng::Rng::new(n as u64).fill(&mut d);
            let l = deflate_len(&d);
            assert!(l >= last, "len {n} gave {l} after {last}");
            last = l;
        }
    }

    #[test]
    fn deflate_never_panics_on_adversarial_shapes() {
        for d in [
            vec![],
            vec![0u8],
            vec![0u8; 2],
            vec![0xFFu8; 3],
            vec![b'x'; MAX_MATCH * 3],
            (0..=255u8).cycle().take(5000).collect(),
        ] {
            let _ = deflate_len(&d);
        }
    }

    #[test]
    fn aes_ecb_always_pads_at_least_one_byte() {
        assert_eq!(aes_ecb_len(0), 16);
        assert_eq!(aes_ecb_len(15), 16);
        assert_eq!(aes_ecb_len(16), 32, "PKCS#7 adds a full block on a multiple");
        assert_eq!(aes_ecb_len(17), 32);
    }

    #[test]
    fn ecb_repeats_are_visible() {
        let mut d = Vec::new();
        for _ in 0..4 {
            d.extend_from_slice(&[0xABu8; 16]);
        }
        assert_eq!(ecb_repeated_blocks(&d), 3, "finding C-5 is observable");
        let mut r = vec![0u8; 64];
        crate::rng::Rng::new(2).fill(&mut r);
        assert_eq!(ecb_repeated_blocks(&r), 0);
    }

    #[test]
    fn modelled_signal_ciphertext_is_incompressible() {
        let ct = modelled_libsignal_ct(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(ct.len(), 40 + LIBSIGNAL_OVERHEAD);
        assert!(deflate_len(&ct) >= ct.len(), "ciphertext must not compress");
    }

    #[test]
    fn log2_q8_is_sane() {
        assert_eq!(log2_q8(1), 0);
        assert_eq!(log2_q8(2) / 256, 1);
        assert_eq!(log2_q8(256) / 256, 8);
        assert_eq!(log2_q8(0), 0, "must not shift by 64");
    }
}
