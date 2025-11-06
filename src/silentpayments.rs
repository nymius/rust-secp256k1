//! TODO
use crate::{
    constants,
    ffi::{self, CPtr},
    PublicKey, Secp256k1, SecretKey, Verification, XOnlyPublicKey,
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

    /// TODO: add docs
    pub fn parse<C: Verification>(
        secp: &Secp256k1<C>,
        input: &[u8],
    ) -> Result<Self, PrevoutsSummaryError> {
        let mut prevouts_summary = Self::new();

        let res = unsafe {
            ffi::secp256k1_silentpayments_recipient_prevouts_summary_parse(
                secp.ctx().as_ptr(),
                prevouts_summary.as_mut_c_ptr(),
                input.as_c_ptr(),
                input.len(),
            )
        };

        if res == 1 {
            Ok(prevouts_summary)
        } else {
            Err(PrevoutsSummaryError::SerializationFailure)
        }
    }
}

/// Output scan errors
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum LabeledSpendPubkeyError {
    /// Failed to create output pubkey
    CreationFailure,
}

#[cfg(feature = "std")]
impl std::error::Error for LabeledSpendPubkeyError {}

impl core::fmt::Display for LabeledSpendPubkeyError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        match self {
            LabeledSpendPubkeyError::CreationFailure => {
                write!(f, "Failed to create labelled spend pubkey")
            }
        }
    }
}

/// Label tweak errors
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum LabelTweakError {
    /// Unexpected failures
    CreationFailure,
}

#[cfg(feature = "std")]
impl std::error::Error for LabelTweakError {}

impl core::fmt::Display for LabelTweakError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        match self {
            LabelTweakError::CreationFailure => write!(f, "Failed to create label tweak"),
        }
    }
}

/// TODO: add docs
pub fn silentpayments_recipient_create_label<C: Verification>(
    secp: &Secp256k1<C>,
    scan_key32: &SecretKey,
    m: u32,
) -> Result<(PublicKey, [u8; 32]), LabelTweakError> {
    unsafe {
        let mut label = ffi::PublicKey::new();
        let mut label_tweak32 = [0u8; 32];

        let res = ffi::secp256k1_silentpayments_recipient_create_label(
            secp.ctx().as_ptr(),
            &mut label,
            label_tweak32.as_mut_c_ptr(),
            scan_key32.as_c_ptr(),
            m,
        );

        if res == 1 {
            let label = PublicKey::from(label);
            Ok((label, label_tweak32))
        } else {
            Err(LabelTweakError::CreationFailure)
        }
    }
}

/// TODO: add docs
pub fn silentpayments_recipient_create_labeled_spend_pubkey<C: Verification>(
    secp: &Secp256k1<C>,
    unlabeled_spend_pubkey: &PublicKey,
    label: &PublicKey,
) -> Result<PublicKey, LabeledSpendPubkeyError> {
    unsafe {
        let mut pubkey = ffi::PublicKey::new();

        let res = ffi::secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(
            secp.ctx().as_ptr(),
            &mut pubkey,
            unlabeled_spend_pubkey.as_c_ptr(),
            label.as_c_ptr(),
        );

        if res == 1 {
            let pubkey = PublicKey::from(pubkey);
            Ok(pubkey)
        } else {
            Err(LabeledSpendPubkeyError::CreationFailure)
        }
    }
}
