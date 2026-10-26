//! RFC 6238 time-based one-time passwords for operator two-factor login.
//! Uses the parameters every common authenticator app supports: HMAC-SHA1,
//! six digits and a 30-second step.
use ring::hmac;

pub const STEP_SECONDS: u64 = 30;
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32 without padding, the secret format authenticator apps expect.
pub fn base32(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(5) {
        let mut buf = [0u8; 5];
        buf[..chunk.len()].copy_from_slice(chunk);
        let bits = u64::from_be_bytes([0, 0, 0, buf[0], buf[1], buf[2], buf[3], buf[4]]);
        for i in 0..(chunk.len() * 8).div_ceil(5) {
            out.push(ALPHABET[(bits >> (35 - i * 5)) as usize & 31] as char);
        }
    }
    out
}
pub fn decode_base32(text: &str) -> Option<Vec<u8>> {
    let (mut bits, mut width, mut out) = (0u64, 0u32, Vec::new());
    for c in text.bytes() {
        let value = ALPHABET.iter().position(|&a| a == c.to_ascii_uppercase())?;
        bits = (bits << 5) | value as u64;
        width += 5;
        if width >= 8 {
            width -= 8;
            out.push((bits >> width) as u8);
        }
    }
    Some(out)
}

pub fn code(secret: &[u8], step: u64) -> u32 {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let digest = hmac::sign(&key, &step.to_be_bytes());
    let d = digest.as_ref();
    let offset = (d[19] & 0x0f) as usize;
    let binary = u32::from_be_bytes([
        d[offset] & 0x7f,
        d[offset + 1],
        d[offset + 2],
        d[offset + 3],
    ]);
    binary % 1_000_000
}

/// Accepts a six-digit code within one step of clock skew. Steps at or before
/// `used_through` were already accepted once and cannot be replayed.
pub fn verify(
    secret: &[u8],
    input: &str,
    unix_seconds: u64,
    used_through: Option<u64>,
) -> Option<u64> {
    if input.len() != 6 || !input.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let value: u32 = input.parse().ok()?;
    let now = unix_seconds / STEP_SECONDS;
    (now.saturating_sub(1)..=now + 1)
        .filter(|step| used_through.is_none_or(|used| *step > used))
        .find(|step| code(secret, *step) == value)
}

pub fn provisioning_uri(issuer: &str, account: &str, secret: &str) -> String {
    format!(
        "otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period={STEP_SECONDS}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn matches_rfc_6238_sha1_vectors() {
        // RFC 6238 appendix B lists eight-digit values; six digits keep the low-order part.
        for (time, expected) in [
            (59, 287_082),
            (1_111_111_109, 81_804),
            (1_111_111_111, 50_471),
            (1_234_567_890, 5_924),
            (2_000_000_000, 279_037),
            (20_000_000_000, 353_130),
        ] {
            assert_eq!(code(RFC_SECRET, time / STEP_SECONDS), expected, "T={time}");
        }
    }

    #[test]
    fn base32_matches_rfc_4648_and_round_trips() {
        assert_eq!(base32(RFC_SECRET), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
        assert_eq!(decode_base32("mzxw6ytboi").unwrap(), b"foobar");
        assert!(decode_base32("MZXW1").is_none());
    }

    #[test]
    fn verification_allows_one_step_of_skew_and_rejects_replay() {
        let now = 1_111_111_111;
        let previous = format!("{:06}", code(RFC_SECRET, now / 30 - 1));
        let stale = format!("{:06}", code(RFC_SECRET, now / 30 - 2));
        assert_eq!(verify(RFC_SECRET, "050471", now, None), Some(now / 30));
        assert_eq!(verify(RFC_SECRET, &previous, now, None), Some(now / 30 - 1));
        assert_eq!(verify(RFC_SECRET, &stale, now, None), None);
        assert_eq!(verify(RFC_SECRET, "050471", now, Some(now / 30)), None);
        assert_eq!(verify(RFC_SECRET, &previous, now, Some(now / 30 - 1)), None);
        assert_eq!(verify(RFC_SECRET, "50471", now, None), None);
        assert_eq!(verify(RFC_SECRET, "05047a", now, None), None);
    }
}
