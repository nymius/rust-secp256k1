//! This module implements high-level Rust bindings for the libsecp256k1 implementation for Silent
//! Payments, as specified in BIP352.
//!
//! This particularly involves the creation of input tweak data by summing up secret or public keys
//! and the derivation of a shared secret using Elliptic Curve Diffie-Hellman. Combined are either:
//!
//!   - spender's secret keys and recipient's public key (a * B, sender side)
//!   - spender's public keys and recipient's secret key (A * b, recipient side)
//!
//! With this result, the necessary key material for ultimately creating/scanning
//! or spending Silent Payment outputs can be determined.
//!
//! Note that the underlying module this crate is binding is _not_ a full implementation of BIP352,
//! as it inherently doesn't deal with higher-level concepts like addresses, output script types or
//! transactions. The intent is to provide bindings to the libsecp256k1 module for abstracting away
//! the elliptic-curve operations required for the protocol. For any wallet software already using
//! this crate, this API should provide all the functions needed for a Silent Payments
//! implementation without requiring any further elliptic-curve operations from the wallet.
use crate::{
    constants,
    ffi::{self, types::c_void, CPtr},
    Keypair, PublicKey, Secp256k1, SecretKey, Verification, XOnlyPublicKey,
};
use core::mem::forget;

/// Struct to store silent payments prevouts summary data.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

/// PrevoutsSummary errors.
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum PrevoutsSummaryError {
    /// Failed to create the prevouts summary.
    CreationFailure,
    /// Failed to parse the serialized prevout summary.
    ParseFailure,
    /// Failed to create the output pubkeys.
    OutputCreationFailure,
}

#[cfg(feature = "std")]
impl std::error::Error for PrevoutsSummaryError {}

impl core::fmt::Display for PrevoutsSummaryError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        match self {
            PrevoutsSummaryError::CreationFailure => write!(f, "Failed to create the prevouts summary"),
            PrevoutsSummaryError::ParseFailure => write!(f, "Failed to parse the serialized prevout summary"),
            PrevoutsSummaryError::OutputCreationFailure => write!(f, "Failed to create the output pubkeys"),
        }
    }
}

impl PrevoutsSummary {
    /// Allocate an empty [`PrevoutsSummary`] for other methods to write.
    fn new() -> Self {
        Self(ffi::PrevoutsSummary::from_array(
            [0u8; constants::SILENT_PAYMENTS_PREVOUTS_SUMMARY_SIZE],
        ))
    }

    /// Create [`PrevoutsSummary`] from prevout public keys and transaction inputs.
    ///
    /// Given a list of n public keys A_1...A_n (one for each silent payment eligible input to
    /// spend) and a serialized `lexmin_outpoint`, create a `prevouts_summary` object. This object
    /// summarizes the prevout data from the transaction inputs needed for scanning.
    ///
    /// `lexmin_outpoint` refers to the smallest outpoint lexicographically
    /// from the transaction inputs (both silent payments eligible and non-eligible
    /// inputs). This value MUST be the smallest outpoint out of ALL of the
    /// transaction inputs, otherwise the recipient will be unable to find the
    /// payment.
    ///
    /// The public keys have to be passed in via two different parameter pairs, one
    /// for regular and one for x-only public keys, in order to avoid the need of
    /// users converting to a common public key format before calling this function.
    /// The resulting data can be used for scanning on the recipient side, or
    /// stored in an index for later use (e.g., wallet rescanning, sending data to
    /// light clients).
    ///
    /// If calling this function for simply aggregating the public transaction data
    /// for later use, the caller can save the result with [`PrevoutsSummary::serialize`].
    ///
    /// # Arguments
    /// * `secp` - a secp256k1 verification engine.
    /// * `lexmin_outpoint` - serialized smallest outpoint (lexicographically)
    ///   from the transaction inputs.
    /// * `xonly_pubkeys` - pointer to an array of pointers to taproot x-only
    ///   public keys (can be [`Option::None`] if no taproot inputs are used).
    /// * `plain_pubkeys` - pointer to an array of pointers to non-taproot
    ///   public keys (can be [`Option::None`] if no non-taproot inputs are used).
    ///
    /// # Returns
    /// A [`PrevoutsSummary`] struct, containing the summed public keys and the input hash.
    ///
    /// # Errors
    /// * [`PrevoutsSummaryError::CreationFailure] - the prevout summary could not be created
    ///   because arguments are invalid or transaction is not a silent payment transaction (no inputs
    ///   for shared secret derivation).
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

    /// Serialize a [`PrevoutsSummary`] struct into a 33-byte or 65-byte sequence.
    ///
    /// Serializing a prevouts_summary object created with [`PrevoutsSummary::create`] will result in
    /// an EC multiplication. This allows for a more compact serialization, but also means a serialized
    /// [`PrevoutsSummary`] will not parse back to a the same [`PrevoutsSummary`] struct (due to the EC multiplication).
    ///
    /// This function does not error because [`PrevoutsSummary`] is assumed valid after creation.
    ///
    /// # Arguments
    /// * `secp` - a secp256k1 verification engine.
    /// * `compressed` - a boolean indicating the preferred serialization output size.
    ///
    /// # Returns
    /// A byte vector with the serialized [`PrevoutsSummary`] in.
    pub fn serialize<C: Verification>(&self, secp: &Secp256k1<C>, compressed: bool) -> Vec<u8> {
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

        // Do not check return type, as it can only return 1
        let _res = unsafe {
            ffi::secp256k1_silentpayments_recipient_prevouts_summary_serialize(
                secp.ctx().as_ptr(),
                output.as_mut_c_ptr(),
                size,
                self.as_c_ptr(),
                flags,
            )
        };

        output
    }

    /// Parse a 33-byte or 65-byte sequence into a [`PrevoutsSummary`] struct.
    ///
    /// # Arguments:
    /// * `secp` - a secp256k1 verification engine.
    /// * `input` - a 33-byte or 65-byte slice.
    ///
    /// # Returns:
    /// A [`PrevoutsSummary`] struct if successful.
    ///
    /// # Errors:
    /// * [`PrevoutsSummaryError::ParseFailure`] if the slice could not be parsed.
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
            Err(PrevoutsSummaryError::ParseFailure)
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
                Err(PrevoutsSummaryError::OutputCreationFailure)
            }
        }
    }
}

/// Failed to create labeled spend pubkey.
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct LabeledSpendPubkeyCreationError;

#[cfg(feature = "std")]
impl std::error::Error for LabeledSpendPubkeyCreationError {}

impl core::fmt::Display for LabeledSpendPubkeyCreationError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        match self {
            LabeledSpendPubkeyCreationError => {
                write!(f, "Failed to create labeled spend pubkey")
            }
        }
    }
}

/// Error creating label tweak.
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct LabelTweakCreationError;

#[cfg(feature = "std")]
impl std::error::Error for LabelTweakCreationError {}

impl core::fmt::Display for LabelTweakCreationError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        match self {
            LabelTweakCreationError => write!(f, "Failed to create label tweak"),
        }
    }
}

/// TODO: add docs
pub fn silentpayments_recipient_create_label<C: Verification>(
    secp: &Secp256k1<C>,
    scan_seckey: &SecretKey,
    m: u32,
) -> Result<(PublicKey, [u8; 32]), LabelTweakCreationError> {
    unsafe {
        let mut label = ffi::PublicKey::new();
        let mut label_tweak32 = [0u8; 32];

        let res = ffi::secp256k1_silentpayments_recipient_create_label(
            secp.ctx().as_ptr(),
            &mut label,
            label_tweak32.as_mut_c_ptr(),
            scan_seckey.as_c_ptr(),
            m,
        );

        if res == 1 {
            let label = PublicKey::from(label);
            Ok((label, label_tweak32))
        } else {
            Err(LabelTweakCreationError)
        }
    }
}

/// TODO: add docs
pub fn silentpayments_recipient_create_labeled_spend_pubkey<C: Verification>(
    secp: &Secp256k1<C>,
    unlabeled_spend_pubkey: &PublicKey,
    label: &PublicKey,
) -> Result<PublicKey, LabeledSpendPubkeyCreationError> {
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
            Err(LabeledSpendPubkeyCreationError)
        }
    }
}

/// Error creating silent payment ouput x-only public keys.
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct SilentpaymentDerivationError;

#[cfg(feature = "std")]
impl std::error::Error for SilentpaymentDerivationError {}

impl core::fmt::Display for SilentpaymentDerivationError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        match self {
            SilentpaymentDerivationError => write!(f, "Failed while deriving silent payment output x-only public keys"),
        }
    }
}

/// TODO: add docs
pub fn silentpayments_sender_create_outputs<C: Verification>(
    secp: &Secp256k1<C>,
    recipients: &[&mut SilentpaymentsRecipient],
    lexmin_outpoint: &[u8; 36],
    taproot_seckeys: Option<&[&Keypair]>,
    plain_seckeys: Option<&[&SecretKey]>,
) -> Result<Vec<XOnlyPublicKey>, SilentpaymentDerivationError> {
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
            lexmin_outpoint.as_c_ptr(),
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
            Err(SilentpaymentDerivationError)
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

/// Error while scanning silent payment outputs
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct SilentpaymentScanningError;

#[cfg(feature = "std")]
impl std::error::Error for SilentpaymentScanningError {}

impl core::fmt::Display for SilentpaymentScanningError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        match self {
            SilentpaymentScanningError => write!(f, "Failed while scanning silent payment outputs"),
        }
    }
}

/// TODO: add docs
pub fn silentpayments_recipient_scan_outputs<C: Verification, L>(
    secp: &Secp256k1<C>,
    tx_outputs: &[&XOnlyPublicKey],
    scan_seckey: &SecretKey,
    prevouts_summary: &PrevoutsSummary,
    unlabeled_spend_pubkey: &PublicKey,
    label_lookup: ffi::LabelLookup,
    label_context: Option<&L>,
) -> Result<Vec<FoundOutput>, SilentpaymentScanningError> {
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
            scan_seckey.to_secret_bytes().as_c_ptr(),
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
            Err(SilentpaymentScanningError)
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
