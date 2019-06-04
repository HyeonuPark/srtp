
use bytes::{BytesMut, BufMut};

use srtp::{Builder, CryptoPolicy, SsrcType};

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
    fn to_bytes(self, payload_size: usize) -> BytesMut {
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

#[test]
fn round_trip() {
    let key: Vec<_> = (0u8..30).collect();

    let mut inbound = Builder::new()
        .rtp_crypto_policy(CryptoPolicy::AesCm128HmacSha1Bit80)
        .rtcp_crypto_policy(CryptoPolicy::AesCm128HmacSha1Bit80)
        .ssrc_type(SsrcType::AnyInbound)
        .create(&key)
        .unwrap();
    let mut outbound = Builder::new()
        .rtp_crypto_policy(CryptoPolicy::AesCm128HmacSha1Bit80)
        .rtcp_crypto_policy(CryptoPolicy::AesCm128HmacSha1Bit80)
        .ssrc_type(SsrcType::AnyOutbound)
        .create(&key)
        .unwrap();

    let mut packet = Header {
        header_ext: false,
        padding: false,
        payload_type: 0xF,
        marker: false,
        sequence: 0x1234,
        timestamp: 0xDECAFBAD,
        ssrc: 0xDEADBEEF,
    }.to_bytes(1000);
    let packet2 = packet.clone();

    outbound.protect(&mut packet).unwrap();
    assert_ne!(packet, packet2);
    inbound.unprotect(&mut packet).unwrap();
    assert_eq!(packet, packet2);
}
