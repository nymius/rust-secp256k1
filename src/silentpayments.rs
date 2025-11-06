//! TODO
use crate::{
    constants,
    ffi::{self, CPtr},
    PublicKey, Secp256k1, Verification, XOnlyPublicKey,
};

#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// TODO: Docs
pub struct PrevoutsSummary(ffi::PrevoutsSummary);

impl CPtr for PrevoutsSummary {
    type Target = ffi::PrevoutsSummary;

    /// Obtains a const pointer suitable for use with FFI functions.
    fn as_c_ptr(&self) -> *const Self::Target {
        &self.0
    }

    /// Obtains a mutable pointer suitable for use with FFI functions.
    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        &mut self.0
    }
}

/// Label tweak errors
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum PrevoutsSummaryError {
    /// Failed to create the public data
    CreationFailure,
    /// Serialization Failure
    SerializationFailure,
    /// Parse Failure
    ParseFailure,
    /// Failed to create the shared secret
    SharedSecretFailure,
}

impl PrevoutsSummary {
    fn new() -> Self {
        Self(ffi::PrevoutsSummary::from_array(
            [0u8; constants::SILENT_PAYMENTS_PREVOUTS_SUMMARY_SIZE],
        ))
    }

    /// TODO: add docs
    pub fn create<C: Verification>(
        secp: &Secp256k1<C>,
        outpoint_smallest36: &[u8; 36],
        xonly_pubkeys: Option<&[&XOnlyPublicKey]>,
        plain_pubkeys: Option<&[&PublicKey]>,
    ) -> Result<Self, PrevoutsSummaryError> {
        let mut prevouts_summary = Self::new();

        let res = unsafe {
            let (ffi_xonly_pubkeys, n_xonly_pubkeys) = match xonly_pubkeys {
                Some(keys) => (keys.as_c_ptr() as *mut *const ffi::XOnlyPublicKey, keys.len()),
                None => (
                    core::ptr::null::<*mut *const ffi::XOnlyPublicKey>()
                        as *mut *const ffi::XOnlyPublicKey,
                    0_usize,
                ),
            };

            let (ffi_plain_pubkeys, n_plain_pubkeys) = match plain_pubkeys {
                Some(keys) => (keys.as_c_ptr() as *mut *const ffi::PublicKey, keys.len()),
                None => (
                    core::ptr::null::<*mut *const ffi::PublicKey>() as *mut *const ffi::PublicKey,
                    0_usize,
                ),
            };

            ffi::secp256k1_silentpayments_recipient_prevouts_summary_create(
                secp.ctx().as_ptr(),
                prevouts_summary.as_mut_c_ptr(),
                outpoint_smallest36.as_c_ptr(),
                ffi_xonly_pubkeys,
                n_xonly_pubkeys,
                ffi_plain_pubkeys,
                n_plain_pubkeys,
            )
        };

        if res == 1 {
            Ok(prevouts_summary)
        } else {
            Err(PrevoutsSummaryError::CreationFailure)
        }
    }

    /// TODO: add docs
    pub fn serialize<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        compressed: bool,
    ) -> Result<Vec<u8>, PrevoutsSummaryError> {
        let (mut output, size, flags) = if compressed {
            (
                vec![0u8; constants::PUBLIC_KEY_SIZE],
                constants::PUBLIC_KEY_SIZE,
                ffi::SECP256K1_SER_COMPRESSED,
            )
        } else {
            (
                vec![0u8; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE],
                constants::UNCOMPRESSED_PUBLIC_KEY_SIZE,
                ffi::SECP256K1_SER_UNCOMPRESSED,
            )
        };

        let res = unsafe {
            ffi::secp256k1_silentpayments_recipient_prevouts_summary_serialize(
                secp.ctx().as_ptr(),
                output.as_mut_c_ptr(),
                size,
                self.as_c_ptr(),
                flags,
            )
        };

        if res == 1 {
            Ok(output)
        } else {
            Err(PrevoutsSummaryError::SerializationFailure)
        }
    }
}
