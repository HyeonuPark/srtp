use std::fmt;
use std::num::NonZeroU32;

use paste::paste;

use crate::sys;

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// SRTP error.
///
/// This type is a wrapper around the `srtp_err_status_t` type of the libsrtp2.
#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Error(NonZeroU32);

macro_rules! impl_error {
    ($($name:ident)*) => {
        paste ! {
            impl Error {
                $(
                    #[allow(missing_docs)]
                    pub const [<$name:upper>]: Error = Error(unsafe {
                        NonZeroU32::new_unchecked(
                            sys::[<srtp_err_status_t_srtp_err_status_ $name>] as _,
                        )
                    });
                )*

                fn name(self) -> &'static str {
                    match self.0.get() as sys::srtp_err_status_t {
                        $(
                            sys::[<srtp_err_status_t_srtp_err_status_ $name>]
                                => stringify!([<$name:upper>]),
                        )*
                        _ => "UNKNOWN",
                    }
                }
            }

            #[test]
            fn test_increasing_number() {
                assert_eq!(sys::srtp_err_status_t_srtp_err_status_ok, 0);

                let mut n = 0;

                $(
                    n += 1;
                    assert_eq!(sys::[<srtp_err_status_t_srtp_err_status_ $name>], n);
                )*
            }
        }
    };
}

impl_error! {
    fail
    bad_param
    alloc_fail
    dealloc_fail
    init_fail
    terminus
    auth_fail
    cipher_fail
    replay_fail
    replay_old
    algo_fail
    no_such_op
    no_ctx
    cant_check
    key_expired
    socket_err
    signal_err
    nonce_bad
    read_fail
    write_fail
    parse_err
    encode_err
    semaphore_err
    pfkey_err
    bad_mki
    pkt_idx_old
    pkt_idx_adv
}

impl Error {
    /// Check and convert the libsrtp operation result.
    ///
    /// Zero maps to `Ok(())`, others map to corresponding constants.
    pub fn check(res: sys::srtp_err_status_t) -> Result<(), Self> {
        match NonZeroU32::new(res as _) {
            None => Ok(()),
            Some(num) => Err(Self(num)),
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple(self.name()).field(&self.0).finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl std::error::Error for Error {}
