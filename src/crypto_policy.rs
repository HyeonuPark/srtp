use std::fmt;
use std::mem::MaybeUninit;

use crate::sys;

#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq)]
pub struct CryptoPolicy {
    set: unsafe extern "C" fn(*mut sys::srtp_crypto_policy_t),
}

impl CryptoPolicy {
    pub const AES_CM_128_HMAC_SHA1_80: CryptoPolicy = CryptoPolicy {
        set: sys::srtp_crypto_policy_set_rtp_default,
    };

    pub(crate) unsafe fn make(self) -> sys::srtp_crypto_policy_t {
        let mut policy = MaybeUninit::uninit();
        (self.set)(policy.as_mut_ptr());
        policy.assume_init()
    }
}

impl Default for CryptoPolicy {
    fn default() -> Self {
        CryptoPolicy::AES_CM_128_HMAC_SHA1_80
    }
}

macro_rules! define_policies {
    (($($crypto:ident)*) ($($openssl_crypto:ident)*)) => {
        paste::paste! {
            impl CryptoPolicy {
                $(
                    pub const [<$crypto:upper>]: CryptoPolicy = CryptoPolicy {
                        set: sys::[<srtp_crypto_policy_set_ $crypto>],
                    };
                )*
                $(
                    #[cfg(feature = "enable-openssl")]
                    #[cfg_attr(docsrs, doc(cfg(feature = "enable-openssl")))]
                    pub const [<$openssl_crypto:upper>]: CryptoPolicy = CryptoPolicy {
                        set: sys::[<srtp_crypto_policy_set_ $openssl_crypto>],
                    };
                )*
            }

            impl fmt::Debug for CryptoPolicy {
                fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    if self == &CryptoPolicy::AES_CM_128_HMAC_SHA1_80 {
                        return f.write_str("AES_CM_128_HMAC_SHA1_80")
                    }
                    $(
                        if self == &CryptoPolicy::[<$crypto:upper>] {
                            return f.write_str(stringify!($crypto))
                        }
                    )*
                    $(
                        #[cfg(feature = "enable-openssl")]
                        if self == &CryptoPolicy::[<$openssl_crypto:upper>] {
                            return f.write_str(stringify!($openssl_crypto))
                        }
                    )*

                    f.write_str("UNKNOWN")
                }
            }
        }
    };
}

define_policies! {
    (
        aes_cm_128_hmac_sha1_32
        aes_cm_128_null_auth
        null_cipher_hmac_sha1_80
        null_cipher_hmac_null
        aes_cm_256_hmac_sha1_80
        aes_cm_256_hmac_sha1_32
        aes_cm_256_null_auth
    )
    (
        aes_cm_192_hmac_sha1_80
        aes_cm_192_hmac_sha1_32
        aes_cm_192_null_auth
        aes_gcm_128_8_auth
        aes_gcm_256_8_auth
        aes_gcm_128_8_only_auth
        aes_gcm_256_8_only_auth
        aes_gcm_128_16_auth
        aes_gcm_256_16_auth
    )
}
