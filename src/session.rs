//! SRTP session and its core functionalities

use std::any::Any;
use std::convert::TryInto;
use std::ffi::c_void;
use std::fmt;
use std::mem::MaybeUninit;
use std::os::raw::c_int;
use std::ptr;

use foreign_types::{ForeignType, ForeignTypeRef};
use srtp2_sys as sys;

use crate::crypto_policy::CryptoPolicy;
use crate::error::{Error, Result};
use crate::vec_like::VecLike;

foreign_types::foreign_type! {
    /// SRTP session
    ///
    /// An SRTP session consists of all of the traffic sent to the RTP and
    /// RTCP destination transport addresses, using the RTP/SAVP (Secure
    /// Audio/Video Profile).  A session can be viewed as a set of SRTP
    /// streams, each of which originates with a different participant.
    pub unsafe type Session: Send + Sync {
        type CType = sys::srtp_ctx_t;
        fn drop = sys::srtp_dealloc;
    }
}

/// SRTP stream policy
#[derive(Debug, Default, Clone, Copy)]
pub struct StreamPolicy<'a> {
    /// SRTP crypto policy.
    pub rtp: CryptoPolicy,
    /// SRTCP crypto policy.
    pub rtcp: CryptoPolicy,
    /// Master key for this stream.
    pub key: &'a [u8],
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

type EventHandler = Option<
    Box<dyn FnMut(&mut SessionRef, u32, Option<&mut (dyn Any + Send + 'static)>) + Send + 'static>,
>;

#[derive(Default)]
pub(crate) struct UserDataWrapper {
    pub(crate) user_data: Option<Box<dyn Any + Send + 'static>>,
    on_ssrc_collision: EventHandler,
    on_key_hard_limit: EventHandler,
    on_key_soft_limit: EventHandler,
}

impl Session {
    /// Allocate and initialize an SRTP session context.
    ///
    /// To use it, streams should be added using `add_stream()` method.
    pub fn new() -> Result<Self> {
        crate::ensure_init();

        let mut session: MaybeUninit<sys::srtp_t> = MaybeUninit::uninit();

        unsafe {
            Error::check(sys::srtp_create(session.as_mut_ptr(), ptr::null_mut()))?;
            Ok(Session::from_ptr(session.assume_init()))
        }
    }

    /// Allocate and initialize an SRTP session context,
    /// with the given inbound stream policy template.
    ///
    /// Any inbound streams which is not explicitely added by `add_stream()` method
    /// will generated with the given template policy.
    pub fn with_inbound_template(policy: StreamPolicy<'_>) -> Result<Self> {
        crate::ensure_init();

        let mut session: MaybeUninit<sys::srtp_t> = MaybeUninit::uninit();
        let mut policy = policy.sys_policy()?;
        policy.ssrc.type_ = sys::srtp_ssrc_type_t_ssrc_any_inbound;

        unsafe {
            Error::check(sys::srtp_create(session.as_mut_ptr(), &policy))?;
            Ok(Session::from_ptr(session.assume_init()))
        }
    }

    /// Allocate and initialize an SRTP session context,
    /// with the given outbound stream policy template.
    ///
    /// Any outbound streams which is not explicitely added by `add_stream()` method
    /// will generated with the given template policy.
    pub fn with_outbound_template(policy: StreamPolicy<'_>) -> Result<Self> {
        crate::ensure_init();

        let mut session: MaybeUninit<sys::srtp_t> = MaybeUninit::uninit();
        let mut policy = policy.sys_policy()?;
        policy.ssrc.type_ = sys::srtp_ssrc_type_t_ssrc_any_outbound;

        unsafe {
            Error::check(sys::srtp_create(session.as_mut_ptr(), &policy))?;
            Ok(Session::from_ptr(session.assume_init()))
        }
    }
}

impl SessionRef {
    unsafe fn overwrite<T: VecLike>(
        &mut self,
        buf: &mut T,
        reserve: bool,
        func: unsafe extern "C" fn(sys::srtp_t, *mut c_void, *mut c_int) -> sys::srtp_err_status_t,
    ) -> Result<()> {
        if reserve {
            if let Err(err) = buf.reserve(sys::SRTP_MAX_TRAILER_LEN as usize) {
                error!("`buf.reserve()` failed: {}", err);
                return Err(Error::BAD_PARAM);
            }
        }

        let bytes = buf.as_mut_bytes();
        let orig_length = bytes.len();
        let head_ptr = bytes.as_mut_ptr() as *mut c_void;

        let mut length: c_int = match orig_length.try_into() {
            Ok(len) => len,
            Err(err) => {
                error!("Cannot convert the length of the `key` into c_int: {}", err);
                return Err(Error::BAD_PARAM);
            }
        };

        let res = Error::check(func(self.as_ptr(), head_ptr, &mut length));
        if let Err(err) = res {
            // Operation failed.
            // No assumptions should be made to the buffer.
            buf.set_len(0);
            return Err(err);
        }

        #[cfg(debug_assertions)]
        if reserve {
            assert!(length as usize <= orig_length + sys::SRTP_MAX_TRAILER_LEN as usize)
        } else {
            assert!(length as usize <= orig_length)
        }

        buf.set_len(length as usize);

        Ok(())
    }

    /// Convert RTP packet stored in the `buf` into SRTP in-place
    pub fn protect<T: VecLike>(&mut self, buf: &mut T) -> Result<()> {
        unsafe { self.overwrite(buf, true, sys::srtp_protect) }
    }

    /// Convert RTCP packet stored in the `buf` into SRTCP in-place
    pub fn protect_rtcp<T: VecLike>(&mut self, buf: &mut T) -> Result<()> {
        unsafe { self.overwrite(buf, true, sys::srtp_protect_rtcp) }
    }

    /// Convert SRTP packet stored in the `buf` into RTP in-place
    pub fn unprotect<T: VecLike>(&mut self, buf: &mut T) -> Result<()> {
        unsafe { self.overwrite(buf, false, sys::srtp_unprotect) }
    }

    /// Convert SRTCP packet stored in the `buf` into RTCP in-place
    pub fn unprotect_rtcp<T: VecLike>(&mut self, buf: &mut T) -> Result<()> {
        unsafe { self.overwrite(buf, false, sys::srtp_unprotect_rtcp) }
    }

    /// Allocate and initialize an SRTP stream within this SRTP session.
    pub fn add_stream(&mut self, ssrc: u32, policy: StreamPolicy<'_>) -> Result<()> {
        let policy = policy.sys_policy_ssrc(ssrc)?;

        unsafe {
            Error::check(sys::srtp_add_stream(self.as_ptr(), &policy))?;
            Ok(())
        }
    }

    /// Remove the SRTP stream with the SSRC value from this SRTP session.
    pub fn remove_stream(&mut self, ssrc: u32) -> Result<()> {
        unsafe {
            Error::check(sys::srtp_remove_stream(self.as_ptr(), ssrc))?;
            Ok(())
        }
    }

    /// Update the SRTP stream with the SSRC value from this SRTP session.
    /// Existing ROC value will be preserved.
    pub fn update_stream(&mut self, ssrc: u32, policy: StreamPolicy<'_>) -> Result<()> {
        let policy = policy.sys_policy_ssrc(ssrc)?;

        unsafe {
            Error::check(sys::srtp_update_stream(self.as_ptr(), &policy))?;
            Ok(())
        }
    }

    /// Update the SRTP stream template and streams generated from it.
    pub fn update_inbound_template(&mut self, policy: StreamPolicy<'_>) -> Result<()> {
        let mut policy = policy.sys_policy()?;
        policy.ssrc.type_ = sys::srtp_ssrc_type_t_ssrc_any_inbound;

        unsafe {
            Error::check(sys::srtp_update_stream(self.as_ptr(), &policy))?;
            Ok(())
        }
    }

    /// Update the SRTP stream template and streams generated from it.
    pub fn update_outbound_template(&mut self, policy: StreamPolicy<'_>) -> Result<()> {
        let mut policy = policy.sys_policy()?;
        policy.ssrc.type_ = sys::srtp_ssrc_type_t_ssrc_any_outbound;

        unsafe {
            Error::check(sys::srtp_update_stream(self.as_ptr(), &policy))?;
            Ok(())
        }
    }

    /// Get the roll-over-counter of the SRTP stream with the SSRC value from this SRTP session.
    pub fn get_stream_roc(&mut self, ssrc: u32) -> Result<u32> {
        unsafe {
            let mut roc = 0;
            Error::check(sys::srtp_get_stream_roc(self.as_ptr(), ssrc, &mut roc))?;
            Ok(roc)
        }
    }

    /// Set the roll-over-counter of the SRTP stream with the SSRC value from this SRTP session.
    pub fn set_stream_roc(&mut self, ssrc: u32, roc: u32) -> Result<()> {
        unsafe {
            Error::check(sys::srtp_set_stream_roc(self.as_ptr(), ssrc, roc))?;
            Ok(())
        }
    }

    pub(crate) fn user_data_wrapper(&mut self) -> &mut UserDataWrapper {
        unsafe {
            match (sys::srtp_get_user_data(self.as_ptr()) as *mut UserDataWrapper).as_mut() {
                Some(wrapper) => wrapper,
                None => {
                    let wrapper = Box::into_raw(Box::new(UserDataWrapper::default()));
                    sys::srtp_set_user_data(self.as_ptr(), wrapper as *mut c_void);
                    &mut *wrapper
                }
            }
        }
    }

    /// Store user data to the SRTP session. This can be useful to share data with the event callbacks.
    pub fn set_user_data<T>(&mut self, data: T)
    where
        T: Any + Send + 'static,
    {
        self.user_data_wrapper().user_data = Some(Box::new(data))
    }

    /// Access the use data previously stored into the SRTP session, if any.
    pub fn user_data(&mut self) -> Option<&mut (dyn Any + Send + 'static)> {
        self.user_data_wrapper().user_data.as_deref_mut()
    }

    /// Take the user data back from the SRTP session, if any.
    pub fn take_user_data(&mut self) -> Option<Box<dyn Any + Send + 'static>> {
        self.user_data_wrapper().user_data.take()
    }

    /// Set callback for SSRC collision event.
    pub fn on_ssrc_collision<F>(&mut self, f: F)
    where
        F: FnMut(&mut SessionRef, u32, Option<&mut (dyn Any + Send + 'static)>) + Send + 'static,
    {
        self.user_data_wrapper().on_ssrc_collision = Some(Box::new(f))
    }

    /// Set callback for key hard limit event.
    ///
    /// This means the SRTP stream with given SSRC reached
    /// the hard key usage limit and has expired.
    pub fn on_key_hard_limit<F>(&mut self, f: F)
    where
        F: FnMut(&mut SessionRef, u32, Option<&mut (dyn Any + Send + 'static)>) + Send + 'static,
    {
        self.user_data_wrapper().on_key_hard_limit = Some(Box::new(f))
    }

    /// Set callback for key soft limit event.
    ///
    /// This means the SRTP stream with given SSRC reached
    /// the soft key usage limit and will expire soon.
    pub fn on_key_soft_limit<F>(&mut self, f: F)
    where
        F: FnMut(&mut SessionRef, u32, Option<&mut (dyn Any + Send + 'static)>) + Send + 'static,
    {
        self.user_data_wrapper().on_key_soft_limit = Some(Box::new(f))
    }
}

impl StreamPolicy<'_> {
    fn sys_policy(&self) -> Result<sys::srtp_policy_t> {
        let mut policy: sys::srtp_policy_t = unsafe { MaybeUninit::zeroed().assume_init() };

        policy.ssrc.type_ = sys::srtp_ssrc_type_t_ssrc_undefined;
        policy.rtp = self.rtp.into_raw();
        policy.rtcp = self.rtcp.into_raw();

        let key_length =
            std::cmp::max(policy.rtp.cipher_key_len, policy.rtcp.cipher_key_len) as usize;
        if self.key.len() < key_length {
            error!(
                "StreamPolicy key is too short, required: {}, provided: {}",
                key_length,
                self.key.len(),
            );
            return Err(Error::BAD_PARAM);
        }

        policy.key = self.key.as_ptr() as *mut u8;
        policy.window_size = self.window_size;
        policy.allow_repeat_tx = if self.allow_repeat_tx { 1 } else { 0 };
        policy.enc_xtn_hdr = if self.encrypt_extension_headers.is_empty() {
            ptr::null_mut()
        } else {
            self.encrypt_extension_headers.as_ptr() as *mut i32
        };
        policy.enc_xtn_hdr_count = match self.encrypt_extension_headers.len().try_into() {
            Ok(len) => len,
            Err(err) => {
                error!(
                    "Cannot convert the length of the `enc_xtn_hdr_count` into c_int: {}",
                    err
                );
                return Err(Error::BAD_PARAM);
            }
        };

        Ok(policy)
    }

    fn sys_policy_ssrc(&self, ssrc: u32) -> Result<sys::srtp_policy_t> {
        let mut policy = self.sys_policy()?;
        policy.ssrc.type_ = sys::srtp_ssrc_type_t_ssrc_specific;
        policy.ssrc.value = ssrc;
        Ok(policy)
    }
}

impl UserDataWrapper {
    pub(crate) fn event_handler(&mut self, kind: sys::srtp_event_t) -> &mut EventHandler {
        match kind {
            sys::srtp_event_t_event_ssrc_collision => &mut self.on_ssrc_collision,
            sys::srtp_event_t_event_key_hard_limit => &mut self.on_key_hard_limit,
            sys::srtp_event_t_event_key_soft_limit => &mut self.on_key_soft_limit,
            _ => unreachable!(),
        }
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Session { .. }")
    }
}

impl fmt::Debug for SessionRef {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("SessionRef { .. }")
    }
}
