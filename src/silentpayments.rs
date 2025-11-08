//! TODO
use crate::{
    constants,
    ffi::{self, types::c_void, CPtr},
    Keypair, PublicKey, Secp256k1, SecretKey, Verification, XOnlyPublicKey,
};
use core::{fmt::Write, mem::forget};

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
        lexmin_outpoint: &[u8; 36],
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
                lexmin_outpoint.as_c_ptr(),
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

    /// TODO: add docs
    pub fn create_output_pubkeys<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        scan_seckey: &SecretKey,
        spend_pubkeys: &[&mut PublicKey],
    ) -> Result<Vec<XOnlyPublicKey>, PrevoutsSummaryError> {
        unsafe {
            let mut outputs_xonly = vec![ffi::XOnlyPublicKey::new(); spend_pubkeys.len()];
            let mut ffi_outputs_xonly =
                outputs_xonly.iter_mut().map(|k| k as *mut _).collect::<Vec<_>>();
            let res = ffi::secp256k1_silentpayments_recipient_create_output_pubkeys(
                secp.ctx().as_ptr(),
                ffi_outputs_xonly.as_mut_c_ptr(),
                scan_seckey.as_c_ptr(),
                self.as_c_ptr(),
                spend_pubkeys.as_c_ptr() as *const *mut ffi::PublicKey,
                spend_pubkeys.len(),
            );
            if res == 1 {
                let length = outputs_xonly.len();
                let capacity = outputs_xonly.capacity();
                let ptr = outputs_xonly.as_mut_ptr();

                // Prevent destruction on drop by original vector
                forget(outputs_xonly);

                Ok(Vec::from_raw_parts(ptr as *mut XOnlyPublicKey, length, capacity))
            } else {
                Err(PrevoutsSummaryError::SerializationFailure)
            }
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

/// TODO: add docs
pub fn silentpayments_sender_create_outputs<C: Verification>(
    secp: &Secp256k1<C>,
    recipients: &[&mut SilentpaymentsRecipient],
    outpoint_smallest36: &[u8; 36],
    taproot_seckeys: Option<&[&Keypair]>,
    plain_seckeys: Option<&[&SecretKey]>,
) -> Result<Vec<XOnlyPublicKey>, LabeledSpendPubkeyError> {
    unsafe {
        let (ffi_taproot_seckeys, n_taproot_seckeys) = match taproot_seckeys {
            Some(keys) => (keys.as_c_ptr() as *const *const ffi::Keypair, keys.len()),
            None => (
                core::ptr::null::<*const *const ffi::Keypair>() as *const *const ffi::Keypair,
                0_usize,
            ),
        };

        let (ffi_plain_seckeys, n_plain_seckeys) = match plain_seckeys {
            Some(keys) => (
                keys.iter()
                    .map(|key| key.to_secret_bytes().as_c_ptr())
                    .collect::<Vec<*const u8>>()
                    .as_c_ptr(),
                keys.len(),
            ),
            None => (core::ptr::null::<*const *const u8>() as *const *const u8, 0_usize),
        };

        let mut generated_outputs = vec![ffi::XOnlyPublicKey::new(); recipients.len()];
        let mut ffi_generated_outputs =
            generated_outputs.iter_mut().map(|k| k as *mut _).collect::<Vec<_>>();

        let res = ffi::secp256k1_silentpayments_sender_create_outputs(
            secp.ctx().as_ptr(),
            ffi_generated_outputs.as_mut_c_ptr(),
            recipients.as_c_ptr() as *const *mut ffi::SilentpaymentsRecipient,
            recipients.len(),
            outpoint_smallest36.as_c_ptr(),
            ffi_taproot_seckeys,
            n_taproot_seckeys,
            ffi_plain_seckeys,
            n_plain_seckeys,
        );

        if res == 1 {
            let length = generated_outputs.len();
            let capacity = generated_outputs.capacity();
            let ptr = generated_outputs.as_mut_ptr();

            // Prevent destruction on drop by original vector
            forget(generated_outputs);

            Ok(Vec::from_raw_parts(ptr as *mut XOnlyPublicKey, length, capacity))
        } else {
            Err(LabeledSpendPubkeyError::CreationFailure)
        }
    }
}

/// Struct to store recipient data
#[repr(transparent)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct SilentpaymentsRecipient(ffi::SilentpaymentsRecipient);

impl SilentpaymentsRecipient {
    /// Get a new SilentpaymentsRecipient
    pub fn new(scan_pubkey: &PublicKey, spend_pubkey: &PublicKey, index: usize) -> Self {
        unsafe {
            Self(ffi::SilentpaymentsRecipient::new(
                &*scan_pubkey.as_c_ptr(),
                &*spend_pubkey.as_c_ptr(),
                index,
            ))
        }
    }
}

/// TODO: add docs
pub fn silentpayments_recipient_scan_outputs<C: Verification, L>(
    secp: &Secp256k1<C>,
    tx_outputs: &[&XOnlyPublicKey],
    scan_key32: &SecretKey,
    prevouts_summary: &PrevoutsSummary,
    unlabeled_spend_pubkey: &PublicKey,
    label_lookup: ffi::LabelLookup,
    label_context: Option<&L>,
) -> Result<Vec<FoundOutput>, LabeledSpendPubkeyError> {
    unsafe {
        let mut found_outputs = vec![ffi::FoundOutput::default(); tx_outputs.len()];
        let mut ffi_found_outputs: Vec<_> = found_outputs.iter_mut().map(|k| k as *mut _).collect();
        let mut n_found_outputs: usize = 0;

        let res = ffi::secp256k1_silentpayments_recipient_scan_outputs(
            secp.ctx().as_ptr(),
            ffi_found_outputs.as_mut_c_ptr(),
            &mut n_found_outputs,
            tx_outputs.as_c_ptr() as *const *const ffi::XOnlyPublicKey,
            tx_outputs.len(),
            scan_key32.to_secret_bytes().as_c_ptr(),
            prevouts_summary.as_c_ptr(),
            unlabeled_spend_pubkey.as_c_ptr(),
            label_lookup,
            label_context.as_ref().map_or(core::ptr::null(), |x| *x as *const L as *const c_void),
        );

        if res == 1 {
            let ptr = found_outputs.as_mut_c_ptr();

            // Prevent destruction on drop by original vector
            forget(found_outputs);

            Ok(Vec::from_raw_parts(ptr as *mut FoundOutput, n_found_outputs, n_found_outputs))
        } else {
            Err(LabeledSpendPubkeyError::CreationFailure)
        }
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// TODO: add docs
pub struct FoundOutput(ffi::FoundOutput);

impl CPtr for FoundOutput {
    type Target = ffi::FoundOutput;

    /// Obtains a const pointer suitable for use with FFI functions.
    fn as_c_ptr(&self) -> *const Self::Target {
        &self.0
    }

    /// Obtains a mutable pointer suitable for use with FFI functions.
    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        &mut self.0
    }
}

impl FoundOutput {
    /// TODO
    pub fn tweak(self) -> [u8; 32] {
        self.0.tweak
    }

    /// TODO
    pub fn output(self) -> XOnlyPublicKey {
        self.0.output.into()
    }

    pub fn label(self) -> Option<PublicKey> {
        if self.0.found_with_label != 0 {
            Some(self.0.label.into())
        } else {
            None
        }
    }
}

impl core::fmt::Display for FoundOutput {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}", self.output())
    }
}
