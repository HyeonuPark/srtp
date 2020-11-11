mod error;
mod vec_like;

pub use srtp2_sys as sys;

pub use error::Error;
pub use vec_like::VecLike;

/// Initialize the libsrtp eagerly.
///
/// If not called manually, the libsrtp library will be initialized
/// lazily just before the first operation.
pub fn ensure_init() {
    use std::sync::Once;

    static ONCE: Once = Once::new();

    ONCE.call_once(|| unsafe {
        Error::check(sys::srtp_init()).expect("Failed to initialize the libsrtp");

        #[cfg(feature = "log")]
        Error::check(sys::srtp_install_log_handler(
            Some(handle_log),
            std::ptr::null_mut(),
        ))
        .expect("Failed to install log handler to the libsrtp")
    })
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
