
extern crate srtp2_sys as sys;

use bytes::{BytesMut};

#[derive(Debug)]
pub struct Srtp {
    inner: sys::srtp_t,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoPolicy {
    AesCm128NullAuth,
    AesCm256NullAuth,
    AesCm128HmacSha1Bit32,
    AesCm128HmacSha1Bit80,
    AesCm256HmacSha1Bit32,
    AesCm256HmacSha1Bit80,
    NullCipherHmacNull,
    NullCipherHmacSha1Bit80,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsrcType {
    AnyInbound,
    AnyOutbound,
    Specific(u32),
    Undefined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    AlgoFail,
    AllocFail,
    AuthFail,
    BadMki,
    BadParam,
    CantCheck,
    CipherFail,
    DeallocFail,
    EncodeErr,
    Fail,
    InitFail,
    KeyExpired,
    NoCtx,
    NoSuchOp,
    NonceBad,
    ParseErr,
    PfkeyErr,
    PktIdxAdv,
    PktIdxOld,
    ReadFail,
    ReplayFail,
    ReplayOld,
    SemaphoreErr,
    SignalErr,
    SocketErr,
    Terminus,
    WriteFail,
    Unknown(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyPair<'a> {
    pub client: &'a [u8],
    pub server: &'a [u8],
}

const MAX_TAG_LEN: usize = 16;
const MAX_MKI_LEN: usize = 128;
const MAX_TRAILER_LEN: usize = MAX_TAG_LEN + MAX_MKI_LEN;

impl Srtp {
    pub fn new(
        ssrc_type: SsrcType,
        rtp_policy: CryptoPolicy,
        rtcp_policy: CryptoPolicy,
        key: &[u8],
    ) -> Result<Self, Error> {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| unsafe { check(sys::srtp_init()).unwrap() });

        let rtp_keylen = rtp_policy.master_len();
        let rtcp_keylen = rtcp_policy.master_len();

        if key.len() < rtp_keylen.max(rtcp_keylen) {
            Err(Error::BadParam)?
        }

        unsafe {
            let mut policy: sys::srtp_policy_t = std::mem::zeroed();

            init_crypto_policy(&mut policy.rtp, rtp_policy);
            init_crypto_policy(&mut policy.rtcp, rtcp_policy);
            match ssrc_type {
                SsrcType::AnyInbound => {
                    policy.ssrc.type_ = sys::srtp_ssrc_type_t_ssrc_any_inbound
                }
                SsrcType::AnyOutbound => {
                    policy.ssrc.type_ = sys::srtp_ssrc_type_t_ssrc_any_outbound
                }
                SsrcType::Specific(value) => {
                    policy.ssrc.type_ = sys::srtp_ssrc_type_t_ssrc_specific;
                    policy.ssrc.value = value;
                }
                SsrcType::Undefined => {
                    policy.ssrc.type_ = sys::srtp_ssrc_type_t_ssrc_undefined
                }
            }

            policy.key = key.as_ptr() as *mut _;
            let mut inner = std::ptr::null_mut();

            check(sys::srtp_create(&mut inner, &policy)).map(|_| Srtp { inner })
        }
    }

    pub fn protect(&mut self, data: &mut BytesMut) -> Result<(), Error> {
        unsafe {
            data.reserve(MAX_TRAILER_LEN);
            let mut len = data.len() as _;
            check(sys::srtp_protect(self.inner, data.as_mut_ptr() as *mut _, &mut len))?;
            data.set_len(len as usize);
        }
        Ok(())
    }

    pub fn protect_rtcp(&mut self, data: &mut BytesMut) -> Result<(), Error> {
        unsafe {
            data.reserve(MAX_TRAILER_LEN);
            let mut len = data.len() as _;
            check(sys::srtp_protect_rtcp(self.inner, data.as_mut_ptr() as *mut _, &mut len))?;
            data.set_len(len as usize);
        }
        Ok(())
    }

    pub fn unprotect(&mut self, data: &mut BytesMut) -> Result<(), Error> {
        unsafe {
            let mut len = data.len() as _;
            check(sys::srtp_unprotect(self.inner, data.as_mut_ptr() as *mut _, &mut len))?;
            data.set_len(len as usize);
        }
        Ok(())
    }

    pub fn unprotect_rtcp(&mut self, data: &mut BytesMut) -> Result<(), Error> {
        unsafe {
            let mut len = data.len() as _;
            check(sys::srtp_unprotect_rtcp(self.inner, data.as_mut_ptr() as *mut _, &mut len))?;
            data.set_len(len as usize);
        }
        Ok(())
    }
}

impl std::ops::Drop for Srtp {
    fn drop(&mut self) {
        unsafe {
            check(sys::srtp_dealloc(self.inner)).unwrap()
        }
    }
}

unsafe impl Send for Srtp {}

impl CryptoPolicy {
    pub const MASTER_KEY_LEN_128: usize = 16;
    pub const MASTER_KEY_LEN_256: usize = 32;
    pub const MASTER_SALT_LEN: usize = 14;
    pub const MAX_MASTER_LEN: usize =
        CryptoPolicy::MASTER_KEY_LEN_256 + CryptoPolicy::MASTER_SALT_LEN;

    pub fn master_key_len(self) -> usize {
        use CryptoPolicy::*;

        match self {
            AesCm128NullAuth |
            AesCm128HmacSha1Bit32 |
            AesCm128HmacSha1Bit80 |
            AesCm256HmacSha1Bit80 |
            NullCipherHmacNull |
            NullCipherHmacSha1Bit80 => CryptoPolicy::MASTER_KEY_LEN_128,
            AesCm256NullAuth |
            AesCm256HmacSha1Bit32 => CryptoPolicy::MASTER_KEY_LEN_256,
        }
    }

    pub fn master_salt_len(self) -> usize {
        CryptoPolicy::MASTER_SALT_LEN
    }

    pub fn master_len(self) -> usize {
        self.master_key_len() + self.master_salt_len()
    }

    /// # Panics
    /// Panics if given `buf` is shorter than `2 * self.master_len()`
    pub fn extract_keying_material(self, buf: &mut [u8]) -> KeyPair {
        assert!(buf.len() >= 2 * self.master_len());

        let rot_start = self.master_key_len();
        let rot_end = 2 * self.master_key_len() + self.master_salt_len();

        buf[rot_start..rot_end].rotate_left(self.master_key_len());

        KeyPair {
            client: &buf[..self.master_len()],
            server: &buf[self.master_len()..(2 * self.master_len())],
        }
    }
}

impl Default for CryptoPolicy {
    fn default() -> Self {
        CryptoPolicy::AesCm128HmacSha1Bit80
    }
}

unsafe fn init_crypto_policy(ctx: &mut sys::srtp_crypto_policy_t, policy: CryptoPolicy) {
    use CryptoPolicy::*;

    match policy {
        AesCm128NullAuth        => sys::srtp_crypto_policy_set_aes_cm_128_null_auth(ctx),
        AesCm256NullAuth        => sys::srtp_crypto_policy_set_aes_cm_256_null_auth(ctx),
        AesCm128HmacSha1Bit32   => sys::srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(ctx),
        AesCm128HmacSha1Bit80   => sys::srtp_crypto_policy_set_rtp_default(ctx),
        AesCm256HmacSha1Bit32   => sys::srtp_crypto_policy_set_aes_cm_256_hmac_sha1_32(ctx),
        AesCm256HmacSha1Bit80   => sys::srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80(ctx),
        NullCipherHmacNull      => sys::srtp_crypto_policy_set_null_cipher_hmac_null(ctx),
        NullCipherHmacSha1Bit80 => sys::srtp_crypto_policy_set_null_cipher_hmac_sha1_80(ctx),
    }
}

fn check(maybe_error: sys::srtp_err_status_t) -> Result<(), Error> {
    use Error::*;

    Err(match maybe_error {
        sys::srtp_err_status_t_srtp_err_status_ok => return Ok(()),
        sys::srtp_err_status_t_srtp_err_status_algo_fail => AlgoFail,
        sys::srtp_err_status_t_srtp_err_status_alloc_fail => AllocFail,
        sys::srtp_err_status_t_srtp_err_status_auth_fail => AuthFail,
        sys::srtp_err_status_t_srtp_err_status_bad_mki => BadMki,
        sys::srtp_err_status_t_srtp_err_status_bad_param => BadParam,
        sys::srtp_err_status_t_srtp_err_status_cant_check => CantCheck,
        sys::srtp_err_status_t_srtp_err_status_cipher_fail => CipherFail,
        sys::srtp_err_status_t_srtp_err_status_dealloc_fail => DeallocFail,
        sys::srtp_err_status_t_srtp_err_status_encode_err => EncodeErr,
        sys::srtp_err_status_t_srtp_err_status_fail => Fail,
        sys::srtp_err_status_t_srtp_err_status_init_fail => InitFail,
        sys::srtp_err_status_t_srtp_err_status_key_expired => KeyExpired,
        sys::srtp_err_status_t_srtp_err_status_no_ctx => NoCtx,
        sys::srtp_err_status_t_srtp_err_status_no_such_op => NoSuchOp,
        sys::srtp_err_status_t_srtp_err_status_nonce_bad => NonceBad,
        sys::srtp_err_status_t_srtp_err_status_parse_err => ParseErr,
        sys::srtp_err_status_t_srtp_err_status_pfkey_err => PfkeyErr,
        sys::srtp_err_status_t_srtp_err_status_pkt_idx_adv => PktIdxAdv,
        sys::srtp_err_status_t_srtp_err_status_pkt_idx_old => PktIdxOld,
        sys::srtp_err_status_t_srtp_err_status_read_fail => ReadFail,
        sys::srtp_err_status_t_srtp_err_status_replay_fail => ReplayFail,
        sys::srtp_err_status_t_srtp_err_status_replay_old => ReplayOld,
        sys::srtp_err_status_t_srtp_err_status_semaphore_err => SemaphoreErr,
        sys::srtp_err_status_t_srtp_err_status_signal_err => SignalErr,
        sys::srtp_err_status_t_srtp_err_status_socket_err => SocketErr,
        sys::srtp_err_status_t_srtp_err_status_terminus => Terminus,
        sys::srtp_err_status_t_srtp_err_status_write_fail => WriteFail,
        _ => Unknown(maybe_error),
    })
}
