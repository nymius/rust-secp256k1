extern crate secp256k1;

use core::slice;
use secp256k1::silentpayments::{
    silentpayments_recipient_create_label, silentpayments_recipient_create_labeled_spend_pubkey,
    silentpayments_recipient_scan_outputs, silentpayments_sender_create_outputs, PrevoutsSummary,
    SilentpaymentsRecipient,
};
use secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use std::{
    collections::HashMap,
    ffi::{c_uchar, c_void},
};

const SENDER_SECRET_KEYS: [[u8; 32]; 2] = [
    [
        0x34, 0x18, 0x5f, 0xd2, 0xc0, 0xc3, 0x71, 0x19,
        0x73, 0x46, 0x2e, 0xc7, 0x7b, 0x65, 0x69, 0x95,
        0x43, 0x20, 0x5a, 0xee, 0x4f, 0x30, 0xf4, 0xee,
        0x32, 0x5b, 0xd8, 0x37, 0x6a, 0x1b, 0x36, 0xf3,
    ],
    [
        0xcf, 0x3e, 0x69, 0x66, 0x58, 0xa9, 0x6e, 0x45,
        0x70, 0x96, 0xcb, 0x2e, 0xc9, 0xa9, 0x7c, 0x27,
        0x8c, 0x1b, 0xf0, 0xc6, 0x0d, 0x1d, 0xc3, 0x13,
        0x92, 0x7d, 0xef, 0xac, 0xc2, 0x86, 0xae, 0x88,
    ],
];

const SMALLEST_OUTPOINT: [u8; 36] = [
    0x16, 0x9e, 0x1e, 0x83, 0xe9, 0x30, 0x85, 0x33, 0x91,
    0xbc, 0x6f, 0x35, 0xf6, 0x05, 0xc6, 0x75, 0x4c, 0xfe,
    0xad, 0x57, 0xcf, 0x83, 0x87, 0x63, 0x9d, 0x3b, 0x40,
    0x96, 0xc5, 0x4f, 0x18, 0xf4, 0x00, 0x00, 0x00, 0x00,
];

const BOB_SCAN_SECKEY: [u8; 32] = [
    0xa8, 0x90, 0x54, 0xc9, 0x5b, 0xe3, 0xc3, 0x01,
    0x56, 0x65, 0x74, 0xf2, 0xaa, 0x93, 0xad, 0xe0,
    0x51, 0x85, 0x09, 0x03, 0xa6, 0x9c, 0xbd, 0xd1,
    0xd4, 0x7e, 0xae, 0x26, 0x3d, 0x7b, 0xc0, 0x31,
];

const BOB_SPEND_PUBKEY: [u8; 33] = [
    0x02, 0xee, 0x97, 0xdf, 0x83, 0xb2, 0x54, 0x6a,
    0xf5, 0xa7, 0xd0, 0x62, 0x15, 0xd9, 0x8b, 0xcb,
    0x63, 0x7f, 0xe0, 0x5d, 0xd0, 0xfa, 0x37, 0x3b,
    0xd8, 0x20, 0xe6, 0x64, 0xd3, 0x72, 0xde, 0x9a, 0x01,
];

const BOB_ADDRESS: [[u8; 33]; 2] = [
    [
        0x02, 0x15, 0x40, 0xae, 0xa8, 0x97, 0x54, 0x7a,
        0xd4, 0x39, 0xb4, 0xe0, 0xf6, 0x09, 0xe5, 0xf0,
        0xfa, 0x63, 0xde, 0x89, 0xab, 0x11, 0xed, 0xe3,
        0x1e, 0x8c, 0xde, 0x4b, 0xe2, 0x19, 0x42, 0x5f, 0x23,
    ],
    [
        0x02, 0x3e, 0xff, 0xf8, 0x18, 0x51, 0x65, 0xea,
        0x63, 0xa9, 0x92, 0xb3, 0x9f, 0x31, 0xd8, 0xfd,
        0x8e, 0x0e, 0x64, 0xae, 0xf9, 0xd3, 0x88, 0x07,
        0x34, 0x97, 0x37, 0x14, 0xa5, 0x3d, 0x83, 0x11, 0x8d,
    ],
];

const CAROL_SCAN_KEY: [u8; 32] = [
    0x04, 0xb2, 0xa4, 0x11, 0x63, 0x5c, 0x09, 0x77,
    0x59, 0xaa, 0xcd, 0x0f, 0x00, 0x5a, 0x4c, 0x82,
    0xc8, 0xc9, 0x28, 0x62, 0xc6, 0xfc, 0x28, 0x4b,
    0x80, 0xb8, 0xef, 0xeb, 0xc2, 0x0c, 0x3d, 0x17,
];

const CAROL_ADDRESS: [[u8; 33]; 2] = [
    [
        0x03, 0xbb, 0xc6, 0x3f, 0x12, 0x74, 0x5d, 0x3b,
        0x9e, 0x9d, 0x24, 0xc6, 0xcd, 0x7a, 0x1e, 0xfe,
        0xba, 0xd0, 0xa7, 0xf4, 0x69, 0x23, 0x2f, 0xbe,
        0xcf, 0x31, 0xfb, 0xa7, 0xb4, 0xf7, 0xdd, 0xed, 0xa8,
    ],
    [
        0x03, 0x81, 0xeb, 0x9a, 0x9a, 0x9e, 0xc7, 0x39,
        0xd5, 0x27, 0xc1, 0x63, 0x1b, 0x31, 0xb4, 0x21,
        0x56, 0x6f, 0x5c, 0x2a, 0x47, 0xb4, 0xab, 0x5b,
        0x1f, 0x6a, 0x68, 0x6d, 0xfb, 0x68, 0xea, 0xb7, 0x16,
    ],
];

const ADDRESS_AMOUNTS: [&str; 3] = ["1.0 BTC", "2.0 BTC", "3.0 BTC"];

#[no_mangle]
/// TODO: add docs
/// # Safety
/// TODO
pub unsafe extern "C" fn label_lookup(
    label33: *const c_uchar,
    cache_ptr: *const c_void,
) -> *const c_uchar {
    // Safety checks
    if label33.is_null() || cache_ptr.is_null() {
        return std::ptr::null();
    }

    unsafe {
        let cache = &*(cache_ptr as *const HashMap<[u8; 33], [u8; 32]>);
        let label33_slice = slice::from_raw_parts(label33, 33);

        if let Some(tweak) = cache.get(label33_slice) {
            tweak.as_ptr()
        } else {
            std::ptr::null()
        }
    }
}

fn main() -> anyhow::Result<()> {
    let secp = Secp256k1::new();

    // Assign references to the addresses
    let sp_addresses: [&[[u8; 33]; 2]; 3] = [
        &CAROL_ADDRESS, // 1.0 BTC
        &BOB_ADDRESS,   // 2.0 BTC
        &CAROL_ADDRESS, // 3.0 BTC
    ];

    let mut recipients = Vec::<SilentpaymentsRecipient>::new();
    for (index, [scan_pubkey, spend_pubkey]) in sp_addresses.iter().enumerate() {
        let scan_pubkey = PublicKey::from_slice(scan_pubkey)?;
        let spend_pubkey = PublicKey::from_slice(spend_pubkey)?;

        let silentpayment_recipient =
            SilentpaymentsRecipient::new(&scan_pubkey, &spend_pubkey, index);

        recipients.push(silentpayment_recipient);
    }

    let recipients: Vec<&mut SilentpaymentsRecipient> =
        recipients.iter_mut().map(|k| k as &mut _).collect();

    let mut taproot_seckeys = Vec::<Keypair>::new();
    let mut tx_inputs = Vec::<XOnlyPublicKey>::new();

    for &key in SENDER_SECRET_KEYS.iter() {
        let seckey: [u8; 32] = key;

        let keypair = Keypair::from_seckey_byte_array(seckey)?;

        taproot_seckeys.push(keypair);

        tx_inputs.push(keypair.x_only_public_key().0);
    }

    let taproot_seckeys: Vec<&Keypair> = taproot_seckeys.iter().collect();

    let tx_outputs = silentpayments_sender_create_outputs(
        &secp,
        &recipients,
        &SMALLEST_OUTPOINT,
        Some(&taproot_seckeys),
        None,
    )?;

    println!("Alice created the following outputs for Bob and Carol:");
    for (i, xonly_pubkey) in tx_outputs.iter().enumerate() {
        println!("{}: 0x{}", ADDRESS_AMOUNTS[i], xonly_pubkey);
    }
    println!();

    let bob_scan_seckey = SecretKey::from_secret_bytes(BOB_SCAN_SECKEY)?;
    let m: u32 = 1;

    let (label, label_tweak32) =
        silentpayments_recipient_create_label(&bob_scan_seckey, m)?;

    let bob_spend_pubkey = PublicKey::from_slice(&BOB_SPEND_PUBKEY)?;

    let _labeled_spend_pubkey =
        silentpayments_recipient_create_labeled_spend_pubkey(&bob_spend_pubkey, &label)?;

    let tx_inputs_ref: Vec<&XOnlyPublicKey> = tx_inputs.iter().collect();
    let tx_inputs_ref = tx_inputs_ref.as_slice();

    let public_data: PrevoutsSummary =
        PrevoutsSummary::create(&SMALLEST_OUTPOINT, Some(tx_inputs_ref), None)?;

    let mut tweak_map = HashMap::<[u8; 33], [u8; 32]>::new();

    tweak_map.insert(label.serialize(), label_tweak32);

    let tweak32 = unsafe {
        let map = core::ptr::addr_of!(tweak_map) as *const c_void;
        let tweak32 = label_lookup(&label.serialize() as *const c_uchar, map);
        core::slice::from_raw_parts(tweak32, 32)
    };

    assert_eq!(tweak32, label_tweak32);

    let tx_outputs_ref: Vec<_> = tx_outputs.iter().collect();

    let found_outputs = silentpayments_recipient_scan_outputs(
        &secp,
        &tx_outputs_ref,
        &bob_scan_seckey,
        &public_data,
        &bob_spend_pubkey,
        Some(label_lookup),
        Some(&tweak_map),
    )?;

    if !found_outputs.is_empty() {
        println!("Bob found the following outputs:");
        for xonly_output in found_outputs {
            println!("\t0x{}", &xonly_output.to_string());
        }
        println!();
    } else {
        println!("Bob did not find any outputs in this transaction.\n");
    }

    let input33 = public_data.serialize(true);

    let prevouts_summary = PrevoutsSummary::parse(&input33)?;

    let carol_scan_key = SecretKey::from_secret_bytes(CAROL_SCAN_KEY)?;

    let mut carol_spend_pubkey = PublicKey::from_slice(&CAROL_ADDRESS[1])?;

    let spend_pubkeys = [&mut carol_spend_pubkey];

    let potential_output =
        prevouts_summary.create_output_pubkeys(&carol_scan_key, &spend_pubkeys)?;

    let mut found: bool = false;

    for tx_output in tx_outputs.iter() {
        if *tx_output == potential_output[0] {
            found = true;
            break;
        }
    }

    if found {
        let found_outputs = silentpayments_recipient_scan_outputs(
            &secp,
            &tx_outputs_ref,
            &carol_scan_key,
            &prevouts_summary,
            &carol_spend_pubkey,
            None,
            Option::<&HashMap<[u8; 33], [u8; 32]>>::None,
        )?;
        if !found_outputs.is_empty() {
            println!("Carol found the following outputs:");
            for xonly_output in found_outputs {
                println!("\t0x{}", &xonly_output.to_string());
            }
        } else {
            println!("Carol did not find any outputs in this transaction.\n");
        }
    }
    Ok(())
}
