//! DTLS-SRTP implementation using OpenSSL

use std::mem::MaybeUninit;

use openssl::ssl::{self, SslRef};
use srtp2_sys as sys;

use crate::crypto_policy::CryptoPolicy;
use crate::error::Error as SrtpError;
use crate::session::{Session, StreamPolicy};
use crate::vec_like::VecLike;

type SrtpResult = Result<(), SrtpError>;

/// SRTP session to convert inbound SRTP packets into RTP.
#[derive(Debug)]
pub struct InboundSession {
    session: Session,
}

/// SRTP session to convert outbound RTP packets into SRTP.
#[derive(Debug)]
pub struct OutboundSession {
    session: Session,
}

/// SRTP session configs not supplied by the openssl.
#[derive(Debug, Default)]
pub struct Config<'a> {
    /// The window size to use for replay protection.
    ///
    /// Pass 0 to use the default value.
    pub window_size: u64,
    /// Whether retransmission of packets with the same sequence number are allowed.
    ///
    /// Note that such repeated transmission must have the same RTP payload,
    /// or a severe security weakness is introduced!
    pub allow_repeat_tx: bool,
    /// List of header ids to encrypt.
    pub encrypt_extension_headers: &'a [i32],
}

/// Errors that can be thrown during DTLS-SRTP using openssl.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[allow(missing_docs)]
    #[error("SRTP error: {0}")]
    Srtp(#[from] SrtpError),
    #[allow(missing_docs)]
    #[error("OpenSSL error: {0}")]
    Ssl(#[from] ssl::Error),
    /// SSL context doesn't have SRTP profile.
    #[error("SSL context missing SRTP profile")]
    MissingSrtpProfile,
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(e: openssl::error::ErrorStack) -> Self {
        Error::Ssl(e.into())
    }
}

/// Create bi-directional SRTP session pair from the SSL context.
pub fn session_pair(
    ssl: &SslRef,
    config: Config<'_>,
) -> Result<(InboundSession, OutboundSession), Error> {
    let profile = ssl
        .selected_srtp_profile()
        .ok_or(Error::MissingSrtpProfile)?;
    let profile_id = profile.id().as_raw() as sys::srtp_profile_t;

    let (rtp_policy, rtcp_policy) = unsafe {
        let mut rtp_policy = MaybeUninit::uninit();
        let mut rtcp_policy = MaybeUninit::uninit();

        SrtpError::check(sys::srtp_crypto_policy_set_from_profile_for_rtp(
            rtp_policy.as_mut_ptr(),
            profile_id,
        ))?;
        SrtpError::check(sys::srtp_crypto_policy_set_from_profile_for_rtcp(
            rtcp_policy.as_mut_ptr(),
            profile_id,
        ))?;

        (
            CryptoPolicy::from_raw(rtp_policy.assume_init()),
            CryptoPolicy::from_raw(rtcp_policy.assume_init()),
        )
    };

    let mut material = [0u8; sys::SRTP_MAX_KEY_LEN as usize * 2];
    ssl.export_keying_material(&mut material, "EXTRACTOR-dtls_srtp", None)?;

    let (client_key, server_key) = unsafe {
        let master_key_len = sys::srtp_profile_get_master_key_length(profile_id) as usize;
        let master_salt_len = sys::srtp_profile_get_master_salt_length(profile_id) as usize;
        let master_len = master_key_len + master_salt_len;

        let rot_start = master_key_len;
        let rot_end = rot_start + master_len;

        material[rot_start..rot_end].rotate_left(master_key_len);

        (
            &material[..master_len],
            &material[master_len..(2 * master_len)],
        )
    };

    let (inbound_key, outbound_key) = if ssl.is_server() {
        (client_key, server_key)
    } else {
        (server_key, client_key)
    };

    let inbound = InboundSession {
        session: Session::with_inbound_template(StreamPolicy {
            rtp: rtp_policy,
            rtcp: rtcp_policy,
            key: inbound_key,
            window_size: config.window_size,
            allow_repeat_tx: config.allow_repeat_tx,
            encrypt_extension_headers: config.encrypt_extension_headers,
        })?,
    };

    let outbound = OutboundSession {
        session: Session::with_outbound_template(StreamPolicy {
            rtp: rtp_policy,
            rtcp: rtcp_policy,
            key: outbound_key,
            window_size: config.window_size,
            allow_repeat_tx: config.allow_repeat_tx,
            encrypt_extension_headers: config.encrypt_extension_headers,
        })?,
    };

    Ok((inbound, outbound))
}

impl InboundSession {
    /// Convert SRTP packet stored in the `buf` into RTP in-place
    pub fn unprotect<T: VecLike>(&mut self, buf: &mut T) -> SrtpResult {
        self.session.unprotect(buf)
    }

    /// Convert SRTCP packet stored in the `buf` into RTCP in-place
    pub fn unprotect_rtcp<T: VecLike>(&mut self, buf: &mut T) -> SrtpResult {
        self.session.unprotect_rtcp(buf)
    }

    /// Get a reference to the Session.
    pub fn session(&mut self) -> &mut Session {
        &mut self.session
    }

    /// Convert self into the Session.
    pub fn into_session(self) -> Session {
        self.session
    }
}

impl OutboundSession {
    /// Convert RTP packet stored in the `buf` into SRTP in-place
    pub fn protect<T: VecLike>(&mut self, buf: &mut T) -> SrtpResult {
        self.session.protect(buf)
    }

    /// Convert RTCP packet stored in the `buf` into SRTCP in-place
    pub fn protect_rtcp<T: VecLike>(&mut self, buf: &mut T) -> SrtpResult {
        self.session.protect_rtcp(buf)
    }

    /// Get a reference to the Session.
    pub fn session(&mut self) -> &mut Session {
        &mut self.session
    }

    /// Convert self into the Session.
    pub fn into_session(self) -> Session {
        self.session
    }
}
