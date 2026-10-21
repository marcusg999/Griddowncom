//! Hashes the two baselines need, implemented locally so the crate stays
//! dependency-free and byte-for-byte reproducible.
//!
//! * [`crc32`] is the real IEEE 802.3 CRC-32, because Bridgefy's `track` list
//!   is specified as "CRC-32 of last n relay userIds"
//!   (`docs/research/BRIDGEFY-FINDINGS.md`, Part 1, Packet structure). The
//!   exact function matters there: `track` entries are what a critic will count
//!   bytes for, and collision behaviour is what makes the list useless even if
//!   someone did consult it.
//! * [`digest64`] stands in for the SHA-256 payload digest in bitchat's
//!   de-duplication key (bitchat WHITEPAPER.md v2.0, §4.2 Deduplication). We
//!   are not implementing real crypto, and the seen-set only needs a
//!   collision-resistant-enough key; the modelled digest is noted as such.
//! * [`day_tag16`] stands in for bitchat's 16-byte rotating courier tag, "an
//!   HMAC of the recipient's static key and the UTC day" (§6.2 Opaque
//!   addressing). It reproduces the *behaviour* that matters — same key and day
//!   give the same tag, a different day gives an uncorrelated one, the tag is
//!   16 bytes on the wire — and nothing else. It is NOT an HMAC and must never
//!   be used for anything but this model.

/// IEEE 802.3 CRC-32, reflected, init 0xFFFFFFFF, final xor 0xFFFFFFFF.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for b in data {
        crc ^= *b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// FNV-1a 64. Modelled stand-in for a truncated SHA-256 payload digest.
pub fn digest64(data: &[u8]) -> u64 {
    let mut h = 0xCBF2_9CE4_8422_2325u64;
    for b in data {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    }
    h
}

/// Mix two 64-bit values into one. Used to build composite keys.
pub fn mix64(a: u64, b: u64) -> u64 {
    let mut z = a ^ b.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Modelled 16-byte daily-rotating recipient tag: `f(static_key, utc_day)`.
///
/// bitchat WHITEPAPER.md v2.0 §6.2: "a 16-byte rotating recipient tag — an HMAC
/// of the recipient's static key and the UTC day — computable solely by parties
/// who already know that key ... tags do not correlate across days."
pub fn day_tag16(static_key: &[u8], utc_day: u64) -> [u8; 16] {
    let a = mix64(digest64(static_key), utc_day ^ 0x5BF0_3635_1A48_9C77);
    let b = mix64(a, digest64(static_key).rotate_left(29) ^ utc_day);
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&a.to_le_bytes());
    out[8..].copy_from_slice(&b.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_known_vectors() {
        // Standard check values for IEEE CRC-32.
        assert_eq!(crc32(b""), 0x0000_0000);
        assert_eq!(crc32(b"a"), 0xE8B7_BE43);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b"The quick brown fox jumps over the lazy dog"), 0x414F_A339);
    }

    #[test]
    fn day_tag_rotates_and_is_sixteen_bytes() {
        let key = b"static-key-of-bob";
        let d1 = day_tag16(key, 20_380);
        let d2 = day_tag16(key, 20_381);
        assert_eq!(d1.len(), 16);
        assert_ne!(d1, d2, "tags must not correlate across days (§6.2)");
        assert_eq!(d1, day_tag16(key, 20_380), "same day must be stable");
        assert_ne!(d1, day_tag16(b"static-key-of-eve", 20_380));
    }

    #[test]
    fn digest64_separates_payloads() {
        assert_ne!(digest64(b"help, trapped on 4th"), digest64(b"help, trapped on 5th"));
        assert_eq!(digest64(b"same"), digest64(b"same"));
    }
}
