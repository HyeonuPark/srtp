//! The [`VecLike`](self::VecLike) trait and its supplement types.

use std::convert::TryInto;

/// `Vec<u8>`-like buffer so we can append or shrink tag bytes after modifying its content.
///
/// A `VecLike` type has a byte buffer it can write into,
/// whose length is `capacity` and its first `size` bytes are initialized.
pub trait VecLike {
    /// Returns an unique reference of its first `size` bytes.
    fn as_mut_bytes(&mut self) -> &mut [u8];

    /// Reserve `capacity` for at least `additional` more bytes to be inserted in this buffer.
    /// Does nothing if capacity is already sufficient.
    ///
    /// # Safety
    ///
    /// This function usually is safe to call, but it's unsafe to implement.
    ///
    /// After calling this method,
    /// - the content of `self.as_mut_bytes()` must not be changed.
    /// - `capacity` must be greater than or equal to the `size + additional`.
    unsafe fn reserve(&mut self, additional: usize) -> Result<(), BufferTooShortError>;

    /// Forces the `size` to `new_len`.
    ///
    /// # Safety
    /// - `new_len` must be less than or equal to the `capacity`.
    /// - first `new_len` bytes of the buffer must be initialized.
    unsafe fn set_len(&mut self, new_len: usize);
}

/// Error that can be returned by the `VecLike::reserve()` call.
///
/// Some implementations of the `VecLike` trait is not backed by the growable buffer.
/// This error indicates the the length of the backing fixed size buffer
/// is not large enough to satisfy the safety requirement of the `VecLike::reserve()`.
#[derive(Debug, thiserror::Error)]
#[error("Cannot reserve buffer capacity to {requested_capacity}")]
pub struct BufferTooShortError {
    /// Total capacity required to satisfy the `VecLike::reserve()` call.
    pub requested_capacity: usize,
}

impl VecLike for Vec<u8> {
    fn as_mut_bytes(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }

    unsafe fn reserve(&mut self, additional: usize) -> Result<(), BufferTooShortError> {
        Vec::reserve(self, additional);
        Ok(())
    }

    unsafe fn set_len(&mut self, new_len: usize) {
        Vec::set_len(self, new_len)
    }
}

impl<'a> VecLike for std::io::Cursor<&'a mut [u8]> {
    fn as_mut_bytes(&mut self) -> &mut [u8] {
        let pos = self.position().try_into().unwrap_or(usize::max_value());
        let bytes = self.get_mut();
        let pos = pos.min(bytes.len());
        &mut bytes[..pos]
    }

    unsafe fn reserve(&mut self, additional: usize) -> Result<(), BufferTooShortError> {
        let pos = self.position().try_into().unwrap_or(usize::max_value());
        let reserved = pos.saturating_add(additional);

        if reserved >= self.get_ref().len() {
            Ok(())
        } else {
            Err(BufferTooShortError {
                requested_capacity: reserved,
            })
        }
    }

    unsafe fn set_len(&mut self, new_len: usize) {
        self.set_position(new_len as u64)
    }
}

#[cfg(feature = "bytes")]
impl VecLike for bytes::BytesMut {
    fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self[..]
    }

    unsafe fn reserve(&mut self, additional: usize) -> Result<(), BufferTooShortError> {
        bytes::BytesMut::reserve(self, additional);
        Ok(())
    }

    unsafe fn set_len(&mut self, new_len: usize) {
        bytes::BytesMut::set_len(self, new_len)
    }
}
