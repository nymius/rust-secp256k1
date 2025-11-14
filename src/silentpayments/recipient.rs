//! Provide all the binding functions and methods to be used from the perspective of the
//! silentpayments recipient.
use crate::{
    constants,
    ffi::{self, types::c_void, CPtr},
    PublicKey, Secp256k1, SecretKey, XOnlyPublicKey,
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
pub fn create_label(
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
pub fn create_labeled_spend_pubkey(
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

/// Error while scanning silent payment outputs
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct ScanningError;

#[cfg(feature = "std")]
impl std::error::Error for ScanningError {}

impl core::fmt::Display for ScanningError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        match self {
            ScanningError => write!(f, "Failed while scanning silent payment outputs"),
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
/// For creating the labels cache, [`create_label`] can be used.
///
/// # Arguments
/// * `tx_outputs` -  a slice of references to the transactions x-only public keys.
/// * `scan_seckey` - the recipient's [`SecretKey`].
/// * `prevouts_summary` - a reference to the transaction [`PrevoutsSummary`].
/// * `unlabeled_spend_pubkey` - a reference to the recipient's unlabeled spend [`PublicKey`].
/// * `label_lookup` - a closure that wraps the label cache. This function takes a label public key
///   as an argument and returns the label tweak if it exists. Should be [`Option::None`] if labels
///   are not used.
///
/// # Returns
/// A vector of [`FoundOutput`]s.
///
/// # Errors
/// * [`SilentpaymentScanningError`] - if the transaction is not a valid silent payment transaction
///   or the arguments are invalid.
pub fn scan_outputs<F>(
    tx_outputs: &[&XOnlyPublicKey],
    scan_seckey: &SecretKey,
    prevouts_summary: &PrevoutsSummary,
    unlabeled_spend_pubkey: &PublicKey,
    label_lookup: Option<F>,
) -> Result<Vec<FoundOutput>, ScanningError>
where
    F: for<'a> FnMut(&'a [u8; 33]) -> Option<[u8; 32]>,
{
    unsafe {
        type Context<F> = (F, [u8; 32]);

        let mut found_outputs = vec![ffi::FoundOutput::default(); tx_outputs.len()];
        let mut ffi_found_outputs: Vec<_> = found_outputs.iter_mut().map(|k| k as *mut _).collect();
        let mut n_found_outputs: usize = 0;
        let mut context: Context<F>;

        let (label_lookup, label_context): (ffi::LabelLookup, _) =
            if let Some(label_lookup) = label_lookup {
                unsafe extern "C" fn callback<F>(
                    label33: *const u8,
                    label_context: *const c_void,
                ) -> *const u8
                where
                    F: for<'a> FnMut(&'a [u8; 33]) -> Option<[u8; 32]>,
                {
                    let label33 = unsafe { &*label33.cast::<[u8; 33]>() };
                    // `.cast_mut()` requires slightly higher (1.65) msrv :(, using `as` instead.
                    let (f, storage) =
                        unsafe { &mut *(label_context as *mut c_void).cast::<Context<F>>() };
                    // `catch_unwind` is needed on Rust < 1.81 to prevent unwinding across an ffi
                    // boundary, which is undefined behavior. When the user supplied function panics,
                    // we abort the process. This behavior is consistent with Rust >= 1.81.
                    match std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| f(label33))) {
                        Ok(Some(tweak)) => {
                            // We can't return a pointer to `tweak` as that lives in this function's
                            // (the callback) stack frame, `storage`, on the other hand, remains valid
                            // for the duration of secp256k1_silentpayments_recipient_scan_outputs.
                            *storage = tweak;
                            storage.as_ptr()
                        }
                        Ok(None) => core::ptr::null(),
                        Err(_) => {
                            std::process::abort();
                        }
                    }
                }
                context = (label_lookup, [0u8; 32]);
                (Some(callback::<F>), &mut context as *mut Context<F> as *const c_void)
            } else {
                (None, core::ptr::null())
            };

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
                    label_context,
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
            Err(ScanningError)
        }
    }
}
