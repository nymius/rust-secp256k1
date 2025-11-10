//! Provide all the binding functions and methods to be used from the perspective of the
//! silentpayments sender.
use crate::{
    ffi::{self, CPtr},
    Keypair, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey,
};
use core::mem::forget;

/// Struct to store recipient data.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Recipient(ffi::SilentpaymentsRecipient);

impl Recipient {
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

/// Error creating silent payment ouput x-only public keys.
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct DerivationError;

#[cfg(feature = "std")]
impl std::error::Error for DerivationError {}

impl core::fmt::Display for DerivationError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        match self {
            DerivationError => {
                write!(f, "Failed while deriving silent payment output x-only public keys")
            }
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
pub fn create_outputs(
    recipients: &[&mut Recipient],
    lexmin_outpoint: &[u8; 36],
    taproot_seckeys: Option<&[&Keypair]>,
    plain_seckeys: Option<&[&SecretKey]>,
) -> Result<Vec<XOnlyPublicKey>, DerivationError> {
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
            Err(DerivationError)
        }
    }
}
