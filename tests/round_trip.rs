
use bytes::{BytesMut, BufMut};

use srtp::{Srtp, CryptoPolicy, SsrcType};

#[derive(Debug, Clone, Copy)]
struct Header {
    header_ext: bool,
    padding: bool,
    payload_type: u8,
    marker: bool,
    sequence: u16,
    timestamp: u32,
    ssrc: u32,
}

const HEADER_SIZE: usize = 12;
const MAX_TRAILER_SIZE: usize = 144;

impl Header {
    fn to_bytes(&self, payload_size: usize) -> BytesMut {
        let mut bytes = BytesMut::with_capacity(HEADER_SIZE + payload_size + MAX_TRAILER_SIZE);

        let mut b1 = 0b10000000u8;;
        b1 |= (self.padding as u8) << 5;
        b1 |= (self.header_ext as u8) << 4;

        let mut b2 = 0u8;
        b2 |= (self.marker as u8) << 7;
        b2 |= self.payload_type & 0x7F;

        bytes.put_u8(b1);
        bytes.put_u8(b2);
        bytes.put_u16_be(self.sequence);
        bytes.put_u32_be(self.timestamp);

        for _ in 0..payload_size {
            bytes.put_u8(0xAB);
        }

        bytes
    }
}

fn round_trip(policy: CryptoPolicy) {
    let key: Vec<_> = (0u8..50).collect();

    let mut inbound = Srtp::new(SsrcType::AnyInbound, policy, policy, &key).unwrap();
    let mut outbound = Srtp::new(SsrcType::AnyOutbound, policy, policy, &key).unwrap();

    for sequence in 0x1234..0x1434 {
        let input = Header {
            header_ext: false,
            padding: false,
            payload_type: 96,
            marker: false,
            sequence,
            timestamp: 0xDECAFBAD + (sequence as u32 / 10) * 3000,
            ssrc: 0xDEADBEEF,
        }.to_bytes(1000);
        let mut output = input.clone();

        outbound.protect(&mut output).unwrap();
        if policy != CryptoPolicy::NullCipherHmacNull {
            assert_ne!(input, output);
        }
        inbound.unprotect(&mut output).unwrap();
        assert_eq!(input, output);
    }
}

#[test]
fn round_trip_aes_cm_128_null_auth() {
    round_trip(CryptoPolicy::AesCm128NullAuth)
}

#[test]
fn round_trip_aes_cm_256_null_auth() {
    round_trip(CryptoPolicy::AesCm256NullAuth)
}

#[test]
fn round_trip_aes_cm_128_hmac_sha1_32() {
    round_trip(CryptoPolicy::AesCm128HmacSha1Bit32)
}

#[test]
fn round_trip_aes_cm_128_hmac_sha1_80() {
    round_trip(CryptoPolicy::AesCm128HmacSha1Bit80)
}

#[test]
fn round_trip_aes_cm_256_hmac_sha1_32() {
    round_trip(CryptoPolicy::AesCm256HmacSha1Bit32)
}

#[test]
fn round_trip_aes_cm_256_hmac_sha1_80() {
    round_trip(CryptoPolicy::AesCm256HmacSha1Bit80)
}

#[test]
fn round_trip_null_cipher_hmac_null() {
    round_trip(CryptoPolicy::NullCipherHmacNull)
}

#[test]
fn round_trip_null_cipher_hmac_sha1_80() {
    round_trip(CryptoPolicy::NullCipherHmacSha1Bit80)
}
