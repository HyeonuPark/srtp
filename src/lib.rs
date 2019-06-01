
extern crate srtp2_sys as sys;

use bytes::{BytesMut};

#[derive(Debug)]
pub struct Srtp {
    inner: sys::srtp_t,
}

#[derive(Debug)]
pub struct Builder {
    rtp_policy: Option<CryptoPolicy>,
    rtcp_policy: Option<CryptoPolicy>,
    ssrc_type: SsrcType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoPolicy {
    AesCm128NullAuth,
    AesCm192NullAuth,
    AesCm256NullAuth,
    AesCm128HmacSha1Bit32,
    AesCm128HmacSha1Bit80,
    AesCm192HmacSha1Bit32,
    AesCm192HmacSha1Bit80,
    AesCm256HmacSha1Bit32,
    AesCm256HmacSha1Bit80,
    AesGcm128Bit8Auth,
    AesGcm128Bit8OnlyAuth,
    AesGcm128Bit16Auth,
    AesGcm256Bit8Auth,
    AesGcm256Bit8OnlyAuth,
    AesGcm256Bit16Auth,
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
    Unknown,
}

impl Srtp {
    pub fn protect(&mut self, data: &mut BytesMut) -> Result<(), Error> {
        let trailer_length = unsafe {
            let mut len = 0u32;
            check(sys::srtp_get_protect_trailer_length(self.inner, 0, 0, &mut len))?;
            len
        };
        data.reserve(trailer_length as usize);
        unsafe {
            let mut len = data.len() as _;
            check(sys::srtp_protect(self.inner, data.as_mut_ptr() as *mut _, &mut len))?;
            data.set_len(len as usize);
        }
        Ok(())
    }

    pub fn protect_rtcp(&mut self, data: &mut BytesMut) -> Result<(), Error> {
        let trailer_length = unsafe {
            let mut len = 0u32;
            check(sys::srtp_get_protect_rtcp_trailer_length(self.inner, 0, 0, &mut len))?;
            len
        };
        data.reserve(trailer_length as usize);
        unsafe {
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

impl Builder {
    pub fn new() -> Self {
        Builder {
            rtp_policy: None,
            rtcp_policy: None,
            ssrc_type: SsrcType::Undefined,
        }
    }

    pub fn rtp_crypto_policy(&mut self, policy: CryptoPolicy) -> &mut Self {
        self.rtp_policy = Some(policy);
        self
    }

    pub fn rtcp_crypto_policy(&mut self, policy: CryptoPolicy) -> &mut Self {
        self.rtcp_policy = Some(policy);
        self
    }

    pub fn ssrc_type(&mut self, ssrc: SsrcType) -> &mut Self {
        self.ssrc_type = ssrc;
        self
    }

    pub fn create(&self, key: &[u8]) -> Result<Srtp, Error> {
        unsafe {
            let mut policy: sys::srtp_policy_t = std::mem::zeroed();

            match self.rtp_policy {
                Some(crypto) => init_crypto_policy(&mut policy.rtp, crypto),
                None => sys::srtp_crypto_policy_set_rtp_default(&mut policy.rtp),
            }
            match self.rtcp_policy {
                Some(crypto) => init_crypto_policy(&mut policy.rtcp, crypto),
                None => sys::srtp_crypto_policy_set_rtcp_default(&mut policy.rtcp),
            }
            match self.ssrc_type {
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
            let mut res = Srtp { inner: std::mem::zeroed() };

            check(sys::srtp_create(&mut res.inner, &policy)).map(|_| res)
        }
    }
}

unsafe fn init_crypto_policy(ctx: &mut sys::srtp_crypto_policy_t, policy: CryptoPolicy) {
    use CryptoPolicy::*;

    match policy {
        AesCm128NullAuth        => sys::srtp_crypto_policy_set_aes_cm_128_null_auth(ctx),
        AesCm192NullAuth        => sys::srtp_crypto_policy_set_aes_cm_192_null_auth(ctx),
        AesCm256NullAuth        => sys::srtp_crypto_policy_set_aes_cm_256_null_auth(ctx),
        AesCm128HmacSha1Bit32   => sys::srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(ctx),
        AesCm128HmacSha1Bit80   => sys::srtp_crypto_policy_set_rtp_default(ctx),
        AesCm192HmacSha1Bit32   => sys::srtp_crypto_policy_set_aes_cm_192_hmac_sha1_32(ctx),
        AesCm192HmacSha1Bit80   => sys::srtp_crypto_policy_set_aes_cm_192_hmac_sha1_80(ctx),
        AesCm256HmacSha1Bit32   => sys::srtp_crypto_policy_set_aes_cm_256_hmac_sha1_32(ctx),
        AesCm256HmacSha1Bit80   => sys::srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80(ctx),
        AesGcm128Bit8Auth       => sys::srtp_crypto_policy_set_aes_gcm_128_8_auth(ctx),
        AesGcm128Bit8OnlyAuth   => sys::srtp_crypto_policy_set_aes_gcm_128_8_only_auth(ctx),
        AesGcm128Bit16Auth      => sys::srtp_crypto_policy_set_aes_gcm_128_16_auth(ctx),
        AesGcm256Bit8Auth       => sys::srtp_crypto_policy_set_aes_gcm_256_8_auth(ctx),
        AesGcm256Bit8OnlyAuth   => sys::srtp_crypto_policy_set_aes_gcm_256_8_only_auth(ctx),
        AesGcm256Bit16Auth      => sys::srtp_crypto_policy_set_aes_gcm_256_16_auth(ctx),
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
        _ => Unknown,
    })
}
