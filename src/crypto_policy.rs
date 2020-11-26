use std::fmt;
use std::mem::MaybeUninit;

use crate::sys;

/// Cryptography policy used by the SRTP protection.
#[derive(Clone, Copy)]
pub struct CryptoPolicy {
    inner: sys::srtp_crypto_policy_t,
}

impl CryptoPolicy {
    #[allow(missing_docs)]
    pub fn aes_cm_128_hmac_sha1_80() -> Self {
        unsafe {
            let mut policy = MaybeUninit::uninit();
            sys::srtp_crypto_policy_set_rtp_default(policy.as_mut_ptr());
            Self {
                inner: policy.assume_init(),
            }
        }
    }

    /// Get required key length of this crypto policy.
    pub fn key_len(self) -> usize {
        self.inner.cipher_key_len as usize
    }

    /// Construct CryptoPolicy from the C struct
    ///
    /// # Safety
    ///
    /// `raw` value should be initialized using the functions of the libsrtp2
    /// and should not be modified after initialization.
    pub unsafe fn from_raw(raw: sys::srtp_crypto_policy_t) -> Self {
        CryptoPolicy { inner: raw }
    }

    /// Get the C struct underneath.
    pub fn into_raw(self) -> sys::srtp_crypto_policy_t {
        self.inner
    }
}

impl Default for CryptoPolicy {
    fn default() -> Self {
        Self::aes_cm_128_hmac_sha1_80()
    }
}

macro_rules! define_policies {
    (($($crypto:ident)*) ($($openssl_crypto:ident)*)) => {
        paste::paste! {
            impl CryptoPolicy {
                $(
                    #[allow(missing_docs)]
                    pub fn [<$crypto>]() -> Self {
                        unsafe {
                            let mut policy = MaybeUninit::uninit();
                            sys::[<srtp_crypto_policy_set_ $crypto>](policy.as_mut_ptr());
                            Self {
                                inner: policy.assume_init(),
                            }
                        }
                    }
                )*
                $(
                    #[cfg(feature = "enable-openssl")]
                    #[cfg_attr(docsrs, doc(cfg(feature = "enable-openssl")))]
                    #[allow(missing_docs)]
                    pub fn [<$openssl_crypto>]() -> Self {
                        unsafe {
                            let mut policy = MaybeUninit::uninit();
                            sys::[<srtp_crypto_policy_set_ $openssl_crypto>](policy.as_mut_ptr());
                            Self {
                                inner: policy.assume_init(),
                            }
                        }
                    }
                )*
            }

            impl fmt::Debug for CryptoPolicy {
                fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(f, "CryptoPolicy {{ cipher_key_len: {}, .. }}", self.key_len())
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
