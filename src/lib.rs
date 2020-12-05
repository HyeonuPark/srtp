//! Bindings to libsrtp2
//!
//! This crate provides a safe interface to the libsrtp2 library.
//!
//! # DTLS-SRTP using OpenSSL
//!
//! ```rust
//! # use std::net::{TcpListener, TcpStream};
//! # type AppResult = Result<(), Box<dyn std::error::Error + Send + Sync + 'static>>;
//! # fn main() -> AppResult {
//! #     let server_pkey = include_bytes!("../tests/keys/pkey1.pem");
//! #     let server_cert = include_bytes!("../tests/keys/cert1.pem");
//! #     let client_pkey = include_bytes!("../tests/keys/pkey2.pem");
//! #     let client_cert = include_bytes!("../tests/keys/cert2.pem");
//! #
//! #     let listener = TcpListener::bind("127.0.0.1:0")?;
//! #     let port = listener.local_addr()?.port();
//! #     let server_thread = std::thread::spawn(move || -> AppResult {
//! #         let (stream, _) = listener.accept()?;
//! #         dtls_srtp(server_pkey, server_cert, stream, true)?;
//! #         Ok(())
//! #     });
//! #     let client_thread = std::thread::spawn(move || -> AppResult {
//! #         let stream = TcpStream::connect(format!("127.0.0.1:{}", port))?;
//! #         dtls_srtp(client_pkey, client_cert, stream, false)?;
//! #         Ok(())
//! #     });
//! #
//! #     server_thread.join().unwrap()?;
//! #     client_thread.join().unwrap()?;
//! #     Ok(())
//! # }
//! # fn dtls_srtp(pkey: &[u8], cert: &[u8], stream: TcpStream, is_server: bool) -> AppResult {
//! use openssl::pkey::PKey;
//! use openssl::ssl::{Ssl, SslAcceptor, SslMethod};
//! use openssl::x509::X509;
//!
//! openssl::init();
//!
//! let mut ctx = SslAcceptor::mozilla_modern(SslMethod::dtls())?;
//! ctx.set_tlsext_use_srtp(srtp::openssl::SRTP_PROFILE_NAMES)?;
//! let pkey = PKey::private_key_from_pem(pkey)?;
//! let cert = X509::from_pem(cert)?;
//! ctx.set_private_key(&*pkey)?;
//! ctx.set_certificate(&*cert)?;
//! ctx.check_private_key()?;
//! let ctx = ctx.build().into_context();
//!
//! let mut ssl = Ssl::new(&ctx)?;
//! ssl.set_mtu(1200)?;
//! let stream = if is_server {
//!     ssl.accept(stream)?
//! } else {
//!     ssl.connect(stream)?
//! };
//!
//! let (mut inbound, mut outbound) =
//!     srtp::openssl::session_pair(stream.ssl(), Default::default())?;
//!
//! let mut pkt = b"not a valid SRTP packet".to_vec();
//! if let Err(err) = inbound.unprotect(&mut pkt) {
//!     println!("Failed to unprotect inbound SRTP packet: {}", err);
//! }
//!
//! let mut pkt = b"not a valid RTP packet".to_vec();
//! if let Err(err) = outbound.protect(&mut pkt) {
//!     println!("Failed to protect outbound RTP packet: {}", err);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Standalone usage
//!
//! Create a [`Session`](self::session::Session) to decrypt every incoming SRTP packets.
//!
//! ```rust
//! let key = &[0u8; 30][..]; // DO NOT USE IT ON PRODUCTION
//! let mut packet = b"not a valid SRTP packet".to_vec();
//!
//! let mut session = srtp::Session::with_inbound_template(srtp::StreamPolicy {
//!     key,
//!     rtp: srtp::CryptoPolicy::aes_cm_128_hmac_sha1_80(),
//!     rtcp: srtp::CryptoPolicy::aes_cm_128_hmac_sha1_80(),
//!     ..Default::default()
//! }).unwrap();
//!
//! match session.unprotect(&mut packet) {
//!     Ok(()) => println!("SRTP packet unprotected"),
//!     Err(err) => println!("Error unprotecting SRTP packet: {}", err),
//! };
//! ```

#![deny(missing_docs)]
#![cfg_attr(feature = "skip-linking", feature(doc_cfg))]

#[cfg(feature = "log")]
#[macro_use]
extern crate log;

#[cfg(not(feature = "log"))]
#[macro_use]
mod log_macros {
    #[doc(hidden)]
    #[macro_export]
    macro_rules! error {
        ($format:literal, $($t:tt)*) => {
            eprintln!(concat!("SRTP ERR: ", $format), $($t)*)
        };
        ($format:literal) => {
            eprintln!(concat!("SRTP ERR: ", $format))
        };
    }

    #[doc(hidden)]
    #[macro_export]
    macro_rules! warn {
        ($format:literal, $($t:tt)*) => {
            eprintln!(concat!("SRTP WARN: ", $format), $($t)*)
        };
        ($format:literal) => {
            eprintln!(concat!("SRTP WARN: ", $format))
        };
    }
}

mod crypto_policy;
mod error;
#[cfg(feature = "openssl")]
pub mod openssl;
pub mod session;
pub mod vec_like;

pub use srtp2_sys as sys;

pub use crypto_policy::CryptoPolicy;
pub use error::Error;
pub use session::{Session, StreamPolicy};

/// Initialize the libsrtp eagerly.
///
/// If not called manually, the libsrtp library will be initialized
/// lazily just before the first operation.
pub fn ensure_init() {
    use std::sync::Once;

    static ONCE: Once = Once::new();

    ONCE.call_once(|| unsafe {
        Error::check(sys::srtp_init()).expect("Failed to initialize the libsrtp");

        Error::check(sys::srtp_install_event_handler(Some(handle_event)))
            .expect("Failed to install global event handler to the libsrtp");

        #[cfg(feature = "log")]
        Error::check(sys::srtp_install_log_handler(
            Some(handle_log),
            std::ptr::null_mut(),
        ))
        .expect("Failed to install log handler to the libsrtp")
    })
}

/// Returns the numeric representation of the libsrtp version.
///
/// Major and minor version number takes single byte,
/// and the micro takes remaining two.
///
/// For example, version 2.3.0 yields `0x02_03_0000`
pub fn get_version() -> u32 {
    ensure_init();
    unsafe { sys::srtp_get_version() }
}

/// Returns the version string of the libsrtp.
pub fn get_version_string() -> &'static str {
    ensure_init();
    unsafe {
        let version_ptr = sys::srtp_get_version_string();
        std::ffi::CStr::from_ptr(version_ptr)
            .to_str()
            .expect("libsrtp returns version string which is not a valid UTF-8 sequence")
    }
}

unsafe extern "C" fn handle_event(data: *mut sys::srtp_event_data_t) {
    use foreign_types::ForeignTypeRef;

    let sys::srtp_event_data_t {
        session,
        ssrc,
        event,
    } = *data;

    match event {
        sys::srtp_event_t_event_ssrc_collision => warn!(
            "SSRC collision event, session: {:p}, ssrc: {}",
            session, ssrc
        ),
        sys::srtp_event_t_event_key_hard_limit => warn!(
            "key hard limit event, session: {:p}, ssrc: {}",
            session, ssrc
        ),
        sys::srtp_event_t_event_key_soft_limit => warn!(
            "key soft limit event, session: {:p}, ssrc: {}",
            session, ssrc
        ),
        _ => {
            warn!(
                "Unknown event detected. \
                Please report this log line to this crate's repository. \
                event: {}, session: {:p}, ssrc: {}",
                event, session, ssrc
            );
            return;
        }
    }

    let session = session::SessionRef::from_ptr_mut((*data).session);
    let wrapper = session.user_data_wrapper();
    let mut user_data = wrapper.user_data.take();
    let mut handler = match wrapper.event_handler(event).take() {
        Some(handler) => handler,
        None => return,
    };

    handler(session, ssrc, user_data.as_deref_mut());

    let wrapper = session.user_data_wrapper();
    wrapper.user_data = user_data;
    *wrapper.event_handler(event) = Some(handler);
}

#[cfg(feature = "log")]
unsafe extern "C" fn handle_log(
    level: sys::srtp_log_level_t,
    msg: *const std::os::raw::c_char,
    _: *mut std::ffi::c_void,
) {
    let msg = std::ffi::CStr::from_ptr(msg).to_string_lossy();

    match level {
        sys::srtp_log_level_t_srtp_log_level_debug => log::debug!("LOG: {}", msg),
        sys::srtp_log_level_t_srtp_log_level_info => log::info!("LOG: {}", msg),
        sys::srtp_log_level_t_srtp_log_level_warning => log::warn!("LOG: {}", msg),
        sys::srtp_log_level_t_srtp_log_level_error => log::error!("LOG: {}", msg),
        other => log::error!("UNKNOWN LEVEL {}: {}", other, msg),
    };
}
