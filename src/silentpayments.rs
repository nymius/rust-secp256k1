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
    Keypair, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey,
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
            PrevoutsSummaryError::CreationFailure => {
                write!(f, "Failed to create the prevouts summary")
            }
            PrevoutsSummaryError::ParseFailure => {
                write!(f, "Failed to parse the serialized prevout summary")
            }
            PrevoutsSummaryError::OutputCreationFailure => {
                write!(f, "Failed to create the output pubkeys")
            }
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
    pub fn create(
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

            crate::with_global_context(
                |secp: &Secp256k1<crate::AllPreallocated>| {
                    ffi::secp256k1_silentpayments_recipient_prevouts_summary_create(
                        secp.ctx().as_ptr(),
                        prevouts_summary.as_mut_c_ptr(),
                        lexmin_outpoint.as_c_ptr(),
                        ffi_xonly_pubkeys,
                        n_xonly_pubkeys,
                        ffi_plain_pubkeys,
                        n_plain_pubkeys,
                    )
                },
                None,
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
    /// * `compressed` - a boolean indicating the preferred serialization output size.
    ///
    /// # Returns
    /// A byte vector with the serialized [`PrevoutsSummary`] in.
    pub fn serialize(&self, compressed: bool) -> Vec<u8> {
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
        let _res = crate::with_global_context(
            |secp: &Secp256k1<crate::AllPreallocated>| unsafe {
                ffi::secp256k1_silentpayments_recipient_prevouts_summary_serialize(
                    secp.ctx().as_ptr(),
                    output.as_mut_c_ptr(),
                    size,
                    self.as_c_ptr(),
                    flags,
                )
            },
            None,
        );

        output
    }

    /// Parse a 33-byte or 65-byte sequence into a [`PrevoutsSummary`] struct.
    ///
    /// # Arguments:
    /// * `input` - a 33-byte or 65-byte slice.
    ///
    /// # Returns:
    /// A [`PrevoutsSummary`] struct if successful.
    ///
    /// # Errors:
    /// * [`PrevoutsSummaryError::ParseFailure`] if the slice could not be parsed.
    pub fn parse(
        input: &[u8],
    ) -> Result<Self, PrevoutsSummaryError> {
        let mut prevouts_summary = Self::new();

        let res = crate::with_global_context(
            |secp: &Secp256k1<crate::AllPreallocated>| unsafe {
                ffi::secp256k1_silentpayments_recipient_prevouts_summary_parse(
                    secp.ctx().as_ptr(),
                    prevouts_summary.as_mut_c_ptr(),
                    input.as_c_ptr(),
                    input.len(),
                )
            },
            None,
        );

        if res == 1 {
            Ok(prevouts_summary)
        } else {
            Err(PrevoutsSummaryError::ParseFailure)
        }
    }

    /// Create Silent Payment output public keys.
    ///
    /// Given a scan key, a [`PrevoutsSummary`], and array of recipient spend public keys,
    /// create the silent payments output public keys.
    ///
    /// This function is used by the recipient when scanning for outputs without
    /// access to the transaction outputs (e.g., using BIP158 block filters). It will
    /// create an output (the first output) for each of the spend public keys provided.
    ///
    /// **It is the caller's responsibility to determine if the created outputs exist.**
    ///
    /// If a match is found, the caller must download the full transaction and call
    /// [`silentpayments_recipient_scan_outputs`] to check if there are additional outputs
    /// for the recipient and get the full output tweak needed to spend the outputs.
    ///
    /// # Aruments
    /// * `scan_seckey` - the recipient scanning [`SecretKey`].
    /// * `spend_pubkeys` - slice with the recipient's spend [`PublicKey`]s (labeled or unlabeled).
    ///
    /// # Returns
    /// A vector with the resulting output [`XOnlyPublicKey`]s. Its size should be equal to the size of the
    /// spend_pubkeys slice.
    ///
    /// # Errors
    /// * [`PrevoutsSummaryError::OutputCreationFailure`] - if the transaction is not a silent
    ///   payment transacion.
    pub fn create_output_pubkeys(
        &self,
        scan_seckey: &SecretKey,
        spend_pubkeys: &[&mut PublicKey],
    ) -> Result<Vec<XOnlyPublicKey>, PrevoutsSummaryError> {
        unsafe {
            let mut outputs_xonly = vec![ffi::XOnlyPublicKey::new(); spend_pubkeys.len()];
            let mut ffi_outputs_xonly =
                outputs_xonly.iter_mut().map(|k| k as *mut _).collect::<Vec<_>>();

            let res = crate::with_global_context(
                |secp: &Secp256k1<crate::AllPreallocated>| {
                    ffi::secp256k1_silentpayments_recipient_create_output_pubkeys(
                        secp.ctx().as_ptr(),
                        ffi_outputs_xonly.as_mut_c_ptr(),
                        scan_seckey.as_c_ptr(),
                        self.as_c_ptr(),
                        spend_pubkeys.as_c_ptr() as *const *mut ffi::PublicKey,
                        spend_pubkeys.len(),
                    )
                },
                None,
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

/// Create Silent Payment label tweak and label.
///
/// Given a recipient's scan [`SecretKey`] and a label integer m, calculate the
/// corresponding label tweak and label:
///
///     label_tweak = hash(scan_key || m)
///           label = label_tweak * G
///
/// # Arguments
/// * `scan_seckey` - the recipient's scan [`SecretKey`].
/// * `m` - a label integer for the m-th label (0 is used for change outputs).
///
/// # Returns
/// A tuple ([`PublicKey`], [u8; 32]) where the first element is the label public key and the
/// second is the label tweak.
///
/// # Errors
/// * [`LabelTweakCreationError`] - if label tweak is not a valid scalar (negligible probability per hash evaluation).
pub fn silentpayments_recipient_create_label(
    scan_seckey: &SecretKey,
    m: u32,
) -> Result<(PublicKey, [u8; 32]), LabelTweakCreationError> {
    unsafe {
        let mut label = ffi::PublicKey::new();
        let mut label_tweak32 = [0u8; 32];

        let res = crate::with_global_context(
            |secp: &Secp256k1<crate::AllPreallocated>| {
                ffi::secp256k1_silentpayments_recipient_create_label(
                    secp.ctx().as_ptr(),
                    &mut label,
                    label_tweak32.as_mut_c_ptr(),
                    scan_seckey.as_c_ptr(),
                    m,
                )
            },
            None,
        );

        if res == 1 {
            let label = PublicKey::from(label);
            Ok((label, label_tweak32))
        } else {
            Err(LabelTweakCreationError)
        }
    }
}

/// Create Silent Payment labeled spend public key.
///
/// Given a recipient's spend public key and a label, calculate the
/// corresponding labeled spend public key:
///
///     labeled_spend_pubkey = unlabeled_spend_pubkey + label
///
/// The result is used by the recipient to create a Silent Payment address,
/// consisting of the serialized and concatenated scan public key and
/// (labeled) spend public key.
///
/// # Arguments:
/// * `unlabeled_spend_pubkey` - the recipient's unlabeled spend public key to label.
/// * `label` - the recipient's label public key.
///
/// # Returns
/// The resulting labeled [`PublicKey`].
///
/// # Errors
/// * [`LabeledSpendPubkeyCreationError`] - if spend pubkey and label sum to zero (negligible probability for labels created according to BIP352).
pub fn silentpayments_recipient_create_labeled_spend_pubkey(
    unlabeled_spend_pubkey: &PublicKey,
    label: &PublicKey,
) -> Result<PublicKey, LabeledSpendPubkeyCreationError> {
    unsafe {
        let mut pubkey = ffi::PublicKey::new();

        let res = crate::with_global_context(
            |secp: &Secp256k1<crate::AllPreallocated>| {
                ffi::secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(
                    secp.ctx().as_ptr(),
                    &mut pubkey,
                    unlabeled_spend_pubkey.as_c_ptr(),
                    label.as_c_ptr(),
                )
            },
            None,
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

/// Create Silent Payment outputs for recipient(s).
///
/// Given a list of n secret keys a_1...a_n (one for each silent payment
/// eligible input to spend), a serialized outpoint, and a list of recipients,
/// create the taproot outputs. Inputs with conditional branches or multiple
/// public keys are excluded from silent payments eligible inputs; see BIP352
/// for more information.
///
/// `lexmin_outpoint` refers to the smallest outpoint lexicographically
/// from the transaction inputs (both silent payments eligible and non-eligible
/// inputs). This value MUST be the smallest outpoint out of ALL of the
/// transaction inputs, otherwise the recipient will be unable to find the
/// payment. Determining the smallest outpoint from the list of transaction
/// inputs is the responsibility of the caller. It is strongly recommended
/// that implementations ensure they are doing this correctly by using the
/// test vectors from BIP352.
///
/// When creating more than one generated output, all of the generated outputs
/// MUST be included in the final transaction. Dropping any of the generated
/// outputs from the final transaction may make all or some of the outputs
/// unfindable by the recipient.
///
/// # Arguments
/// * `recipients` - slice of [`SilentpaymentsRecipient`] mutable references. The index indicates
///   its position in the original ordering. The recipients will be grouped by scan public key in
///   place (as specified in BIP0352), but generated outputs are saved in the `generated_outputs`
///   array to match the original ordering (using the index field). This ensures the caller is able
///   to match the generated outputs to the correct silent payment addresses. The same recipient can
///   be passed multiple times to create multiple outputs for the same recipient.
/// * `lexmin_outpoint` - serialized (36-byte) smallest outpoint (lexicographically) from the transaction inputs
/// * `taproot_seckeys` - optionally a slice of [`Keypair`] references of taproot inputs.
/// * `plain_seckeys` - optionally a slice of [`SecretKey`] references of non-taproot inputs.
///
/// # Returns
/// A vector to xonly public keys, one per recipient. Outputs are ordered to match the original
/// ordering of the recipient objects, i.e., the vector element zero is the generated output for
/// the [`SilentpaymentsRecipient`] struct with index = 0.
///
/// # Errors
/// * [`SilentpaymentDerivationError`] - This is expected only with an adversarially chosen
///   recipient spend key. Specifically, failure occurs when:
///   - Input secret keys sum to 0 or the negation of a spend key (negligible probability if at least
///     one of the input secret keys is uniformly random and independent of all other keys).
///   - A hash output is not a valid scalar (negligible probability per hash evaluation).
pub fn silentpayments_sender_create_outputs(
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

        let seed = [0u8; 32];
        let res = crate::with_global_context(
            |secp: &Secp256k1<crate::AllPreallocated>| {
                ffi::secp256k1_silentpayments_sender_create_outputs(
                    secp.ctx().as_ptr(),
                    ffi_generated_outputs.as_mut_c_ptr(),
                    recipients.as_c_ptr() as *const *mut ffi::SilentpaymentsRecipient,
                    recipients.len(),
                    lexmin_outpoint.as_c_ptr(),
                    ffi_taproot_seckeys,
                    n_taproot_seckeys,
                    ffi_plain_seckeys,
                    n_plain_seckeys,
                )
            },
            Some(&seed),
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

/// Struct to store recipient data.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct SilentpaymentsRecipient(ffi::SilentpaymentsRecipient);

impl SilentpaymentsRecipient {
    /// Get a new [`SilentpaymentsRecipient`]
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

/// Scan for Silent Payment transaction outputs.
///
/// Given a [`PrevoutsSummary`] object, a recipient's scan [`SecretKey`] and unlabeled spend
/// [`PublicKey`], and the relevant transaction outputs, scan for outputs belonging to the
/// recipient and return the tweak(s) needed for spending the output(s). An optional
/// [`ffi::LabelLookup`] callback function and `label_context` can be passed if the recipient uses labels.
/// This allows for checking if a label exists in the recipients label cache and retrieving the
/// label tweak during scanning.
///
/// If used, the `label_lookup` function must return a pointer to a 32-byte label
/// tweak if the label is found, or NULL otherwise. The returned pointer must remain
/// valid until the next call to `label_lookup` or until the function returns,
/// whichever comes first. It is not retained beyond that.
///
/// For creating the labels cache, [`silentpayments_recipient_create_label`] can be used.
///
/// # Arguments
/// * `tx_outputs` -  a slice of references to the transactions x-only public keys.
/// * `scan_seckey` - the recipient's [`SecretKey`].
/// * `prevouts_summary` - a reference to the transaction [`PrevoutsSummary`].
/// * `unlabeled_spend_pubkey` - a reference to the recipient's unlabeled spend [`PublicKey`].
/// * `label_lookup` - a pointer to a callback function for looking up label values. This function
///   takes a label public key as an argument and returns a pointer to the label tweak if it exists,
///   otherwise returns a NULL pointer. Should be [`Option::None`] if labels are not used.
/// * `label_context` - optionally a reference to a label context struct. [`Option::None`] if
///   labels are not used or context is not needed by label_lookup .
///
/// # Returns
/// A vector of [`FoundOutput`]s.
///
/// # Errors
/// * [`SilentpaymentScanningError`] - if the transaction is not a valid silent payment transaction
///   or the arguments are invalid.
pub fn silentpayments_recipient_scan_outputs<L>(
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

        let res = crate::with_global_context(
            |secp: &Secp256k1<crate::AllPreallocated>| {
                ffi::secp256k1_silentpayments_recipient_scan_outputs(
                    secp.ctx().as_ptr(),
                    ffi_found_outputs.as_mut_c_ptr(),
                    &mut n_found_outputs,
                    tx_outputs.as_c_ptr() as *const *const ffi::XOnlyPublicKey,
                    tx_outputs.len(),
                    scan_seckey.to_secret_bytes().as_c_ptr(),
                    prevouts_summary.as_c_ptr(),
                    unlabeled_spend_pubkey.as_c_ptr(),
                    label_lookup,
                    label_context
                        .as_ref()
                        .map_or(core::ptr::null(), |x| *x as *const L as *const c_void),
                )
            },
            None,
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

/// Struct for holding a found output along with data needed to spend it later.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    /// The 32-byte tweak needed to spend the output.
    pub fn tweak(self) -> [u8; 32] {
        self.0.tweak
    }

    /// The x-only public key for the taproot output.
    pub fn output(self) -> XOnlyPublicKey {
        self.0.output.into()
    }

    /// If this outputs was sent to a labeled addres, a public key representing the label used,
    /// [`Option::None`] otherwise.
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
