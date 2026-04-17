use bitcoin::hashes::{sha256, HashEngine};
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey, Verification, XOnlyPublicKey};

mod scanning;
mod wallet;

pub use scanning::{
    extract_pubkey_from_input, scan_block, scan_transaction, FoundOutput, FoundPayment, InputData,
    OutputData, TransactionData,
};
pub use wallet::{build_history, HistoryEntry, Outpoint, OwnedUtxo, SilentPaymentWallet, SpentBy};

/// The scanning secret key (b_scan).
#[derive(Copy, Clone)]
pub struct ScanKey {
    secret: SecretKey,
    public: PublicKey,
}

/// The spend public key (B_spend).
#[derive(Copy, Clone)]
pub struct SpendKey {
    public: PublicKey,
}

impl ScanKey {
    pub fn from_slice(data: &[u8]) -> Result<Self, bitcoin::secp256k1::Error> {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(data)?;
        let public = PublicKey::from_secret_key(&secp, &secret);
        Ok(Self { secret, public })
    }

    pub fn secret_key(&self) -> SecretKey {
        self.secret
    }

    pub fn public_key(&self) -> PublicKey {
        self.public
    }
}

impl SpendKey {
    pub fn from_slice(data: &[u8]) -> Result<Self, bitcoin::secp256k1::Error> {
        let public = PublicKey::from_slice(data)?;
        Ok(Self { public })
    }

    pub fn public_key(&self) -> PublicKey {
        self.public
    }
}

pub fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag.as_bytes());
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_ref());
    engine.input(tag_hash.as_ref());
    engine.input(msg);
    sha256::Hash::from_engine(engine).to_byte_array()
}

pub fn compute_input_hash(smallest_outpoint: [u8; 36], a_sum: PublicKey) -> [u8; 32] {
    let mut data = [0u8; 69];
    data[..36].copy_from_slice(&smallest_outpoint);
    data[36..].copy_from_slice(&a_sum.serialize());
    tagged_hash("BIP0352/Inputs", &data)
}

pub fn compute_shared_secret<C: Verification>(
    secp: &Secp256k1<C>,
    scan_key: ScanKey,
    input_hash: [u8; 32],
    a_sum: PublicKey,
) -> Result<PublicKey, bitcoin::secp256k1::Error> {
    let input_hash_scalar = Scalar::from_be_bytes(input_hash)
        .expect("SHA256 output is virtually always a valid scalar");
    let tweaked_a = a_sum.mul_tweak(secp, &input_hash_scalar)?;
    let scan_scalar = Scalar::from_be_bytes(scan_key.secret_key().secret_bytes())
        .expect("a valid secret key is always a valid scalar");
    tweaked_a.mul_tweak(secp, &scan_scalar)
}

pub fn derive_output_pubkey<C: Verification>(
    secp: &Secp256k1<C>,
    shared_secret: PublicKey,
    spend_key: SpendKey,
    k: u32,
) -> Result<XOnlyPublicKey, bitcoin::secp256k1::Error> {
    let mut data = [0u8; 37];
    data[..33].copy_from_slice(&shared_secret.serialize());
    data[33..].copy_from_slice(&k.to_be_bytes());
    let t_k_bytes = tagged_hash("BIP0352/SharedSecret", &data);
    let t_k_scalar =
        Scalar::from_be_bytes(t_k_bytes).expect("SHA256 output is virtually always a valid scalar");
    let p_k = spend_key.public_key().add_exp_tweak(secp, &t_k_scalar)?;
    let (x_only, _parity) = p_k.x_only_public_key();
    Ok(x_only)
}

/// Derive B_spend_m = B_spend + H_tag("BIP0352/Label", b_scan || m) * G.
pub fn derive_labeled_spend_key<C: Verification>(
    secp: &Secp256k1<C>,
    scan_key: ScanKey,
    spend_key: SpendKey,
    label: u32,
) -> Result<SpendKey, bitcoin::secp256k1::Error> {
    let mut data = [0u8; 36];
    data[..32].copy_from_slice(&scan_key.secret_key().secret_bytes());
    data[32..].copy_from_slice(&label.to_be_bytes());
    let label_hash = tagged_hash("BIP0352/Label", &data);
    let label_scalar = Scalar::from_be_bytes(label_hash)
        .expect("SHA256 output is virtually always a valid scalar");
    let labeled_pub = spend_key.public_key().add_exp_tweak(secp, &label_scalar)?;
    Ok(SpendKey {
        public: labeled_pub,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::hash160;
    use bitcoin::hex::FromHex;
    use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};
    use std::io;

    fn make_keypair(byte: u8) -> (SecretKey, PublicKey) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[byte; 32]).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        (sk, pk)
    }

    #[test]
    fn sender_and_receiver_compute_same_shared_secret() {
        let secp = Secp256k1::new();
        let (a_secret, a_public) = make_keypair(0x03);
        let scan_key = ScanKey::from_slice(&[0x05; 32]).unwrap();
        let outpoint = [0xAB_u8; 36];
        let input_hash = compute_input_hash(outpoint, a_public);

        let receiver_shared = compute_shared_secret(&secp, scan_key, input_hash, a_public).unwrap();

        let input_hash_scalar = Scalar::from_be_bytes(input_hash).unwrap();
        let tweaked_bscan = scan_key
            .public_key()
            .mul_tweak(&secp, &input_hash_scalar)
            .unwrap();
        let a_scalar = Scalar::from_be_bytes(a_secret.secret_bytes()).unwrap();
        let sender_shared = tweaked_bscan.mul_tweak(&secp, &a_scalar).unwrap();

        assert_eq!(
            receiver_shared, sender_shared,
            "Sender and receiver must compute the same shared secret"
        );
    }

    #[test]
    fn different_scan_keys_produce_different_secrets() {
        let secp = Secp256k1::new();
        let (_a_sk, a_pk) = make_keypair(0x03);
        let outpoint = [0xAB_u8; 36];
        let input_hash = compute_input_hash(outpoint, a_pk);
        let scan1 = ScanKey::from_slice(&[0x05; 32]).unwrap();
        let scan2 = ScanKey::from_slice(&[0x06; 32]).unwrap();
        let shared1 = compute_shared_secret(&secp, scan1, input_hash, a_pk).unwrap();
        let shared2 = compute_shared_secret(&secp, scan2, input_hash, a_pk).unwrap();
        assert_ne!(shared1, shared2);
    }

    #[test]
    fn derive_output_pubkey_produces_valid_xonly_key() {
        let secp = Secp256k1::new();
        let (_a_sk, a_pk) = make_keypair(0x03);
        let scan_key = ScanKey::from_slice(&[0x05; 32]).unwrap();
        let spend_key = SpendKey::from_slice(
            &PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x07; 32]).unwrap())
                .serialize(),
        )
        .unwrap();
        let outpoint = [0xAB_u8; 36];
        let input_hash = compute_input_hash(outpoint, a_pk);
        let shared = compute_shared_secret(&secp, scan_key, input_hash, a_pk).unwrap();
        let output_key = derive_output_pubkey(&secp, shared, spend_key, 0).unwrap();
        assert_eq!(output_key.serialize().len(), 32);
    }

    fn make_pubkey(byte: u8) -> PublicKey {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[byte; 32]).unwrap();
        PublicKey::from_secret_key(&secp, &sk)
    }

    #[test]
    fn extract_from_p2wpkh() {
        let pubkey = make_pubkey(0x03);
        let pubkey_bytes = pubkey.serialize();
        let mut prevout = vec![0x00, 0x14];
        prevout.extend_from_slice(&[0xAA; 20]);
        let fake_sig = [0x30; 72];
        let witness: Vec<&[u8]> = vec![&fake_sig, &pubkey_bytes];
        let result = extract_pubkey_from_input(&prevout, &[], &witness);
        assert_eq!(result, Some(pubkey));
    }

    #[test]
    fn extract_from_p2tr_key_path() {
        let pubkey = make_pubkey(0x04);
        let (x_only, _parity) = pubkey.x_only_public_key();
        let mut prevout = vec![0x51, 0x20];
        prevout.extend_from_slice(&x_only.serialize());
        let schnorr_sig = [0x42; 64];
        let witness: Vec<&[u8]> = vec![&schnorr_sig];
        let result = extract_pubkey_from_input(&prevout, &[], &witness);
        assert!(result.is_some());
        let extracted = result.unwrap();
        let mut expected_full = [0u8; 33];
        expected_full[0] = 0x02;
        expected_full[1..].copy_from_slice(&x_only.serialize());
        assert_eq!(extracted.serialize(), expected_full);
    }

    #[test]
    fn extract_from_p2pkh() {
        let pubkey = make_pubkey(0x05);
        let pubkey_bytes = pubkey.serialize();
        let keyhash = hash160::Hash::hash(&pubkey_bytes);
        let mut prevout = vec![0x76, 0xa9, 0x14];
        prevout.extend_from_slice(keyhash.as_byte_array());
        prevout.push(0x88);
        prevout.push(0xac);
        let fake_sig = [0x30; 71];
        let mut script_sig = Vec::new();
        script_sig.push(71);
        script_sig.extend_from_slice(&fake_sig);
        script_sig.push(33);
        script_sig.extend_from_slice(&pubkey_bytes);
        let result = extract_pubkey_from_input(&prevout, &script_sig, &[]);
        assert_eq!(result, Some(pubkey));
    }

    #[test]
    fn extract_from_p2sh_p2wpkh() {
        let pubkey = make_pubkey(0x06);
        let pubkey_bytes = pubkey.serialize();
        let mut prevout = vec![0xa9, 0x14];
        prevout.extend_from_slice(&[0xCC; 20]);
        prevout.push(0x87);
        let fake_sig = [0x30; 72];
        let witness: Vec<&[u8]> = vec![&fake_sig, &pubkey_bytes];
        let result = extract_pubkey_from_input(&prevout, &[], &witness);
        assert_eq!(result, Some(pubkey));
    }

    #[test]
    fn reject_p2sh_without_witness() {
        let mut prevout = vec![0xa9, 0x14];
        prevout.extend_from_slice(&[0xCC; 20]);
        prevout.push(0x87);
        let result = extract_pubkey_from_input(&prevout, &[0x00], &[]);
        assert_eq!(result, None, "P2SH without witness is not eligible");
    }

    #[test]
    fn reject_unknown_script_type() {
        let prevout = vec![0xFF, 0x01, 0x02, 0x03];
        let result = extract_pubkey_from_input(&prevout, &[], &[]);
        assert_eq!(result, None);
    }

    #[test]
    fn p2tr_key_path_with_annex() {
        let pubkey = make_pubkey(0x04);
        let (x_only, _parity) = pubkey.x_only_public_key();
        let mut prevout = vec![0x51, 0x20];
        prevout.extend_from_slice(&x_only.serialize());
        let schnorr_sig = [0x42; 64];
        let mut annex = vec![0x50];
        annex.extend_from_slice(&[0x00; 10]);
        let witness: Vec<&[u8]> = vec![&schnorr_sig, &annex];
        let result = extract_pubkey_from_input(&prevout, &[], &witness);
        assert!(
            result.is_some(),
            "Key-path with annex should still be eligible"
        );
    }

    fn simulate_send(
        sender_secret: &SecretKey,
        scan_pub: &PublicKey,
        spend_pub: &PublicKey,
        outpoint: &[u8; 36],
    ) -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let sender_pub = PublicKey::from_secret_key(&secp, sender_secret);
        let input_hash = compute_input_hash(*outpoint, sender_pub);
        let ih_scalar = Scalar::from_be_bytes(input_hash).unwrap();
        let tweaked_bscan = scan_pub.mul_tweak(&secp, &ih_scalar).unwrap();
        let a_scalar = Scalar::from_be_bytes(sender_secret.secret_bytes()).unwrap();
        let shared = tweaked_bscan.mul_tweak(&secp, &a_scalar).unwrap();
        let spend_key = SpendKey::from_slice(&spend_pub.serialize()).unwrap();
        derive_output_pubkey(&secp, shared, spend_key, 0).unwrap()
    }

    #[test]
    fn scan_finds_silent_payment_p2wpkh_input() {
        let secp = Secp256k1::new();
        let scan_key = ScanKey::from_slice(&[0x05; 32]).unwrap();
        let spend_secret = SecretKey::from_slice(&[0x07; 32]).unwrap();
        let spend_pub = PublicKey::from_secret_key(&secp, &spend_secret);
        let spend_key = SpendKey::from_slice(&spend_pub.serialize()).unwrap();
        let sender_secret = SecretKey::from_slice(&[0x03; 32]).unwrap();
        let sender_pub = PublicKey::from_secret_key(&secp, &sender_secret);
        let sender_pub_bytes = sender_pub.serialize();
        let outpoint = [0xAB_u8; 36];
        let output_xonly = simulate_send(
            &sender_secret,
            &scan_key.public_key(),
            &spend_pub,
            &outpoint,
        );
        let fake_sig = [0x30_u8; 72];
        let mut p2wpkh_prevout = vec![0x00, 0x14];
        p2wpkh_prevout.extend_from_slice(&[0xAA; 20]);
        let inputs = vec![InputData {
            prevout_script: &p2wpkh_prevout,
            script_sig: &[],
            witness: vec![&fake_sig, &sender_pub_bytes],
            outpoint,
        }];
        let taproot_outputs = vec![(0, output_xonly)];
        let found = scan_transaction(&secp, &scan_key, &spend_key, &inputs, &taproot_outputs, &[]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].vout, 0);
        assert_eq!(found[0].k, 0);
        assert_eq!(found[0].x_only_pubkey, output_xonly);
    }

    #[test]
    fn scan_returns_empty_for_non_matching_output() {
        let secp = Secp256k1::new();
        let scan_key = ScanKey::from_slice(&[0x05; 32]).unwrap();
        let spend_secret = SecretKey::from_slice(&[0x07; 32]).unwrap();
        let spend_pub = PublicKey::from_secret_key(&secp, &spend_secret);
        let spend_key = SpendKey::from_slice(&spend_pub.serialize()).unwrap();
        let sender_secret = SecretKey::from_slice(&[0x03; 32]).unwrap();
        let sender_pub = PublicKey::from_secret_key(&secp, &sender_secret);
        let sender_pub_bytes = sender_pub.serialize();
        let outpoint = [0xAB_u8; 36];
        let random_key = SecretKey::from_slice(&[0x99; 32]).unwrap();
        let random_pub = PublicKey::from_secret_key(&secp, &random_key);
        let (random_xonly, _) = random_pub.x_only_public_key();
        let fake_sig = [0x30_u8; 72];
        let mut p2wpkh_prevout = vec![0x00, 0x14];
        p2wpkh_prevout.extend_from_slice(&[0xAA; 20]);
        let inputs = vec![InputData {
            prevout_script: &p2wpkh_prevout,
            script_sig: &[],
            witness: vec![&fake_sig, &sender_pub_bytes],
            outpoint,
        }];
        let taproot_outputs = vec![(0, random_xonly)];
        let found = scan_transaction(&secp, &scan_key, &spend_key, &inputs, &taproot_outputs, &[]);
        assert!(
            found.is_empty(),
            "Should not find a match for random output"
        );
    }

    #[test]
    fn scan_returns_empty_for_no_eligible_inputs() {
        let secp = Secp256k1::new();
        let scan_key = ScanKey::from_slice(&[0x05; 32]).unwrap();
        let spend_secret = SecretKey::from_slice(&[0x07; 32]).unwrap();
        let spend_pub = PublicKey::from_secret_key(&secp, &spend_secret);
        let spend_key = SpendKey::from_slice(&spend_pub.serialize()).unwrap();
        let inputs = vec![InputData {
            prevout_script: &[0xFF, 0x01, 0x02],
            script_sig: &[],
            witness: vec![],
            outpoint: [0xAB; 36],
        }];
        let random_key = SecretKey::from_slice(&[0x99; 32]).unwrap();
        let (random_xonly, _) = PublicKey::from_secret_key(&secp, &random_key).x_only_public_key();
        let taproot_outputs = vec![(0, random_xonly)];
        let found = scan_transaction(&secp, &scan_key, &spend_key, &inputs, &taproot_outputs, &[]);
        assert!(found.is_empty());
    }

    #[test]
    fn scan_uses_smallest_outpoint() {
        // Verify that the scanner picks the lexicographically smallest outpoint.
        // Using a different smallest outpoint changes the input_hash -> different
        // shared secret -> must still match if sender used the same logic.
        let secp = Secp256k1::new();
        let scan_key = ScanKey::from_slice(&[0x05; 32]).unwrap();
        let spend_secret = SecretKey::from_slice(&[0x07; 32]).unwrap();
        let spend_pub = PublicKey::from_secret_key(&secp, &spend_secret);
        let spend_key = SpendKey::from_slice(&spend_pub.serialize()).unwrap();
        let sender_secret = SecretKey::from_slice(&[0x03; 32]).unwrap();
        let sender_pub = PublicKey::from_secret_key(&secp, &sender_secret);
        let sender_pub_bytes = sender_pub.serialize();
        let outpoint_small = [0x01_u8; 36];
        let outpoint_big = [0xFF_u8; 36];
        let output_xonly = simulate_send(
            &sender_secret,
            &scan_key.public_key(),
            &spend_pub,
            &outpoint_small,
        );
        let fake_sig = [0x30_u8; 72];
        let mut p2wpkh_prevout = vec![0x00, 0x14];
        p2wpkh_prevout.extend_from_slice(&[0xAA; 20]);
        // Second input is not eligible but its outpoint still participates in
        // smallest-outpoint selection.
        let inputs = vec![
            InputData {
                prevout_script: &p2wpkh_prevout,
                script_sig: &[],
                witness: vec![&fake_sig, &sender_pub_bytes],
                outpoint: outpoint_big,
            },
            InputData {
                prevout_script: &[0xFF, 0x01],
                script_sig: &[],
                witness: vec![],
                outpoint: outpoint_small,
            },
        ];
        let taproot_outputs = vec![(0, output_xonly)];
        let found = scan_transaction(&secp, &scan_key, &spend_key, &inputs, &taproot_outputs, &[]);
        assert_eq!(
            found.len(),
            1,
            "Should find the payment using smallest outpoint"
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn build_silent_payment_tx<'a>(
        sender_secret: &SecretKey,
        scan_key: &ScanKey,
        spend_pub: &PublicKey,
        outpoint: [u8; 36],
        txid: [u8; 32],
        amount: i64,
        prevout_buf: &'a [u8],
        fake_sig: &'a [u8],
        sender_pub_bytes: &'a [u8; 33],
        output_script_buf: &'a mut Vec<u8>,
    ) -> (TransactionData<'a>, XOnlyPublicKey) {
        let output_xonly =
            simulate_send(sender_secret, &scan_key.public_key(), spend_pub, &outpoint);
        output_script_buf.clear();
        output_script_buf.push(0x51);
        output_script_buf.push(0x20);
        output_script_buf.extend_from_slice(&output_xonly.serialize());
        let tx = TransactionData {
            txid,
            inputs: vec![InputData {
                prevout_script: prevout_buf,
                script_sig: &[],
                witness: vec![fake_sig, sender_pub_bytes],
                outpoint,
            }],
            outputs: vec![OutputData {
                vout: 0,
                value: amount,
                script_pubkey: output_script_buf.as_slice(),
            }],
        };
        (tx, output_xonly)
    }

    #[test]
    fn block_scan_finds_payment_in_single_tx() {
        let secp = Secp256k1::new();
        let scan_key = ScanKey::from_slice(&[0x05; 32]).unwrap();
        let spend_secret = SecretKey::from_slice(&[0x07; 32]).unwrap();
        let spend_pub = PublicKey::from_secret_key(&secp, &spend_secret);
        let spend_key = SpendKey::from_slice(&spend_pub.serialize()).unwrap();
        let sender_secret = SecretKey::from_slice(&[0x03; 32]).unwrap();
        let sender_pub = PublicKey::from_secret_key(&secp, &sender_secret);
        let sender_pub_bytes = sender_pub.serialize();
        let outpoint = [0xAB_u8; 36];
        let txid = [0x01_u8; 32];
        let fake_sig = [0x30_u8; 72];
        let mut p2wpkh_prevout = vec![0x00, 0x14];
        p2wpkh_prevout.extend_from_slice(&[0xAA; 20]);
        let mut output_script = Vec::new();
        let (tx, output_xonly) = build_silent_payment_tx(
            &sender_secret,
            &scan_key,
            &spend_pub,
            outpoint,
            txid,
            50_000,
            &p2wpkh_prevout,
            &fake_sig,
            &sender_pub_bytes,
            &mut output_script,
        );
        let payments = scan_block(&secp, &scan_key, &spend_key, &[tx]);
        assert_eq!(payments.len(), 1);
        assert_eq!(payments[0].txid, txid);
        assert_eq!(payments[0].vout, 0);
        assert_eq!(payments[0].amount, 50_000);
        assert_eq!(payments[0].k, 0);
        assert_eq!(payments[0].x_only_pubkey, output_xonly);
    }

    #[test]
    fn block_scan_skips_tx_without_taproot_outputs() {
        let secp = Secp256k1::new();
        let scan_key = ScanKey::from_slice(&[0x05; 32]).unwrap();
        let spend_secret = SecretKey::from_slice(&[0x07; 32]).unwrap();
        let spend_pub = PublicKey::from_secret_key(&secp, &spend_secret);
        let spend_key = SpendKey::from_slice(&spend_pub.serialize()).unwrap();
        let sender_secret = SecretKey::from_slice(&[0x03; 32]).unwrap();
        let sender_pub = PublicKey::from_secret_key(&secp, &sender_secret);
        let sender_pub_bytes = sender_pub.serialize();
        let fake_sig = [0x30_u8; 72];
        let mut p2wpkh_prevout = vec![0x00, 0x14];
        p2wpkh_prevout.extend_from_slice(&[0xAA; 20]);
        let mut p2wpkh_output = vec![0x00, 0x14];
        p2wpkh_output.extend_from_slice(&[0xDD; 20]);
        let tx = TransactionData {
            txid: [0x02; 32],
            inputs: vec![InputData {
                prevout_script: &p2wpkh_prevout,
                script_sig: &[],
                witness: vec![&fake_sig, &sender_pub_bytes],
                outpoint: [0xAB; 36],
            }],
            outputs: vec![OutputData {
                vout: 0,
                value: 10_000,
                script_pubkey: &p2wpkh_output,
            }],
        };
        let payments = scan_block(&secp, &scan_key, &spend_key, &[tx]);
        assert!(
            payments.is_empty(),
            "No taproot outputs means no silent payments"
        );
    }

    #[test]
    fn block_scan_finds_payments_across_multiple_txs() {
        let secp = Secp256k1::new();
        let scan_key = ScanKey::from_slice(&[0x05; 32]).unwrap();
        let spend_secret = SecretKey::from_slice(&[0x07; 32]).unwrap();
        let spend_pub = PublicKey::from_secret_key(&secp, &spend_secret);
        let spend_key = SpendKey::from_slice(&spend_pub.serialize()).unwrap();
        let sender1_secret = SecretKey::from_slice(&[0x03; 32]).unwrap();
        let sender1_pub = PublicKey::from_secret_key(&secp, &sender1_secret);
        let sender1_pub_bytes = sender1_pub.serialize();
        let sender2_secret = SecretKey::from_slice(&[0x04; 32]).unwrap();
        let sender2_pub = PublicKey::from_secret_key(&secp, &sender2_secret);
        let sender2_pub_bytes = sender2_pub.serialize();
        let fake_sig = [0x30_u8; 72];
        let mut prevout = vec![0x00, 0x14];
        prevout.extend_from_slice(&[0xAA; 20]);
        let mut output_script1 = Vec::new();
        let mut output_script2 = Vec::new();
        let (tx1, _) = build_silent_payment_tx(
            &sender1_secret,
            &scan_key,
            &spend_pub,
            [0xAA; 36],
            [0x01; 32],
            25_000,
            &prevout,
            &fake_sig,
            &sender1_pub_bytes,
            &mut output_script1,
        );
        let (tx2, _) = build_silent_payment_tx(
            &sender2_secret,
            &scan_key,
            &spend_pub,
            [0xBB; 36],
            [0x02; 32],
            75_000,
            &prevout,
            &fake_sig,
            &sender2_pub_bytes,
            &mut output_script2,
        );
        let payments = scan_block(&secp, &scan_key, &spend_key, &[tx1, tx2]);
        assert_eq!(payments.len(), 2);
        assert_eq!(payments[0].txid, [0x01; 32]);
        assert_eq!(payments[0].amount, 25_000);
        assert_eq!(payments[1].txid, [0x02; 32]);
        assert_eq!(payments[1].amount, 75_000);
    }

    fn make_payment(txid: [u8; 32], vout: u32, amount: i64, k: u32) -> FoundPayment {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let (x_only, _) = pk.x_only_public_key();
        FoundPayment {
            txid,
            vout,
            x_only_pubkey: x_only,
            k,
            amount,
        }
    }

    #[test]
    fn wallet_tracks_received_payments() {
        let mut wallet = SilentPaymentWallet::new();
        let payments = vec![
            make_payment([0x01; 32], 0, 50_000, 0),
            make_payment([0x02; 32], 1, 30_000, 0),
        ];
        wallet.process_found_payments(&payments, 100);
        assert_eq!(wallet.balance(), 80_000);
        assert_eq!(wallet.total_outputs(), 2);
        assert_eq!(wallet.unspent_count(), 2);
        assert_eq!(wallet.scan_height, 100);
    }

    #[test]
    fn wallet_marks_spent_correctly() {
        let mut wallet = SilentPaymentWallet::new();
        let payments = vec![
            make_payment([0x01; 32], 0, 50_000, 0),
            make_payment([0x02; 32], 1, 30_000, 0),
        ];
        wallet.process_found_payments(&payments, 100);
        let was_ours = wallet.mark_spent(&[0x01; 32], 0, &[0xAA; 32], 105);
        assert!(was_ours, "Should return true for our outpoint");
        assert_eq!(wallet.balance(), 30_000, "Only unspent output remains");
        assert_eq!(wallet.unspent_count(), 1);
        assert_eq!(wallet.total_outputs(), 2, "Spent output still in history");
    }

    #[test]
    fn wallet_mark_spent_unknown_returns_false() {
        let mut wallet = SilentPaymentWallet::new();
        let was_ours = wallet.mark_spent(&[0xFF; 32], 0, &[0xAA; 32], 100);
        assert!(!was_ours, "Unknown outpoint should return false");
    }

    #[test]
    fn wallet_processes_multiple_blocks() {
        let mut wallet = SilentPaymentWallet::new();
        wallet.process_found_payments(&[make_payment([0x01; 32], 0, 50_000, 0)], 100);
        assert_eq!(wallet.balance(), 50_000);
        assert_eq!(wallet.scan_height, 100);
        wallet.process_found_payments(&[make_payment([0x02; 32], 0, 25_000, 0)], 101);
        assert_eq!(wallet.balance(), 75_000);
        assert_eq!(wallet.scan_height, 101);
        wallet.process_found_payments(&[], 102);
        assert_eq!(wallet.balance(), 75_000);
        assert_eq!(wallet.scan_height, 102);
    }

    #[test]
    fn wallet_unspent_utxos_excludes_spent() {
        let mut wallet = SilentPaymentWallet::new();
        let payments = vec![
            make_payment([0x01; 32], 0, 10_000, 0),
            make_payment([0x02; 32], 0, 20_000, 0),
            make_payment([0x03; 32], 0, 30_000, 0),
        ];
        wallet.process_found_payments(&payments, 100);
        wallet.mark_spent(&[0x02; 32], 0, &[0xAA; 32], 105);
        let unspent = wallet.unspent_utxos();
        assert_eq!(unspent.len(), 2);
        assert_eq!(unspent.iter().map(|u| u.amount).sum::<i64>(), 40_000);
        let all = wallet.all_utxos();
        assert_eq!(all.len(), 3, "all_utxos includes spent");
    }

    #[test]
    fn check_for_spends_detects_our_utxo() {
        let mut wallet = SilentPaymentWallet::new();
        let payments = vec![
            make_payment([0x01; 32], 0, 50_000, 0),
            make_payment([0x02; 32], 1, 30_000, 0),
        ];
        wallet.process_found_payments(&payments, 100);
        let input_outpoints = vec![([0xAA; 32], [0x01; 32], 0), ([0xAA; 32], [0xFF; 32], 0)];
        let count = wallet.check_for_spends(&input_outpoints, 105);
        assert_eq!(count, 1, "Should detect 1 spend");
        assert_eq!(wallet.balance(), 30_000);
        assert_eq!(wallet.unspent_count(), 1);
    }

    #[test]
    fn check_for_spends_records_spending_txid() {
        let mut wallet = SilentPaymentWallet::new();
        wallet.process_found_payments(&[make_payment([0x01; 32], 0, 50_000, 0)], 100);
        let spending_txid = [0xBB; 32];
        wallet.check_for_spends(&[(spending_txid, [0x01; 32], 0)], 110);
        let utxo = wallet.all_utxos().into_iter().next().unwrap();
        assert!(utxo.spent);
        let spent_by = utxo.spent_by.as_ref().unwrap();
        assert_eq!(spent_by.txid, spending_txid);
        assert_eq!(spent_by.block_height, 110);
    }

    #[test]
    fn check_for_spends_returns_zero_for_no_matches() {
        let mut wallet = SilentPaymentWallet::new();
        wallet.process_found_payments(&[make_payment([0x01; 32], 0, 50_000, 0)], 100);
        let input_outpoints = vec![([0xAA; 32], [0xFF; 32], 0), ([0xAA; 32], [0xFE; 32], 1)];
        let count = wallet.check_for_spends(&input_outpoints, 105);
        assert_eq!(count, 0);
        assert_eq!(wallet.balance(), 50_000, "Nothing should be spent");
    }

    #[test]
    fn history_shows_receives_and_spends() {
        let mut wallet = SilentPaymentWallet::new();
        wallet.process_found_payments(
            &[
                make_payment([0x01; 32], 0, 50_000, 0),
                make_payment([0x02; 32], 0, 30_000, 0),
            ],
            100,
        );
        wallet.check_for_spends(&[([0xAA; 32], [0x01; 32], 0)], 105);
        let history = build_history(&wallet);
        assert_eq!(history.len(), 3);
        assert!(matches!(
            &history[0],
            HistoryEntry::Received {
                block_height: 100,
                ..
            }
        ));
        assert!(matches!(
            &history[1],
            HistoryEntry::Received {
                block_height: 100,
                ..
            }
        ));
        match &history[2] {
            HistoryEntry::Spent {
                amount,
                block_height,
                spending_txid,
                ..
            } => {
                assert_eq!(*amount, 50_000);
                assert_eq!(*block_height, 105);
                assert_eq!(*spending_txid, [0xAA; 32]);
            }
            _ => panic!("Expected a Spent entry"),
        }
    }

    #[test]
    fn history_sorted_by_block_height() {
        let mut wallet = SilentPaymentWallet::new();
        wallet.process_found_payments(&[make_payment([0x01; 32], 0, 10_000, 0)], 100);
        wallet.process_found_payments(&[make_payment([0x02; 32], 0, 20_000, 0)], 200);
        wallet.process_found_payments(&[make_payment([0x03; 32], 0, 30_000, 0)], 150);
        let history = build_history(&wallet);
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].block_height(), 100);
        assert_eq!(history[1].block_height(), 150);
        assert_eq!(history[2].block_height(), 200);
    }

    #[test]
    fn history_receives_before_spends_same_block() {
        let mut wallet = SilentPaymentWallet::new();
        wallet.process_found_payments(&[make_payment([0x01; 32], 0, 50_000, 0)], 100);
        wallet.check_for_spends(&[([0xCC; 32], [0x01; 32], 0)], 100);
        let history = build_history(&wallet);
        assert_eq!(history.len(), 2);
        assert!(matches!(&history[0], HistoryEntry::Received { .. }));
        assert!(matches!(&history[1], HistoryEntry::Spent { .. }));
    }

    #[test]
    fn history_signed_amount_positive_for_receive_negative_for_spend() {
        let mut wallet = SilentPaymentWallet::new();
        wallet.process_found_payments(&[make_payment([0x01; 32], 0, 75_000, 0)], 100);
        wallet.check_for_spends(&[([0xDD; 32], [0x01; 32], 0)], 110);
        let history = build_history(&wallet);
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].signed_amount(), 75_000);
        assert_eq!(history[1].signed_amount(), -75_000);
    }

    #[test]
    fn save_and_load_wallet_with_unspent_utxos() {
        let mut wallet = SilentPaymentWallet::new();
        wallet.process_found_payments(
            &[
                make_payment([0x01; 32], 0, 50_000, 0),
                make_payment([0x02; 32], 1, 30_000, 1),
            ],
            100,
        );
        let mut buf = Vec::new();
        wallet.save(&mut buf).unwrap();
        let loaded = SilentPaymentWallet::load(&mut &buf[..]).unwrap();
        assert_eq!(loaded.scan_height, 100);
        assert_eq!(loaded.total_outputs(), 2);
        assert_eq!(loaded.balance(), 80_000);
        assert_eq!(loaded.unspent_count(), 2);
    }

    #[test]
    fn save_and_load_wallet_with_spent_utxo() {
        let mut wallet = SilentPaymentWallet::new();
        wallet.process_found_payments(
            &[
                make_payment([0x01; 32], 0, 50_000, 0),
                make_payment([0x02; 32], 0, 30_000, 0),
            ],
            100,
        );
        wallet.check_for_spends(&[([0xBB; 32], [0x01; 32], 0)], 110);
        let mut buf = Vec::new();
        wallet.save(&mut buf).unwrap();
        let loaded = SilentPaymentWallet::load(&mut &buf[..]).unwrap();
        assert_eq!(loaded.scan_height, 100);
        assert_eq!(loaded.total_outputs(), 2);
        assert_eq!(loaded.balance(), 30_000);
        assert_eq!(loaded.unspent_count(), 1);
        let history = build_history(&loaded);
        let spent_entries: Vec<_> = history
            .iter()
            .filter(|e| matches!(e, HistoryEntry::Spent { .. }))
            .collect();
        assert_eq!(spent_entries.len(), 1);
        match &spent_entries[0] {
            HistoryEntry::Spent {
                spending_txid,
                block_height,
                ..
            } => {
                assert_eq!(*spending_txid, [0xBB; 32]);
                assert_eq!(*block_height, 110);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn save_and_load_preserves_utxo_fields() {
        let mut wallet = SilentPaymentWallet::new();
        wallet.process_found_payments(&[make_payment([0x42; 32], 3, 123_456, 7)], 999);
        let mut buf = Vec::new();
        wallet.save(&mut buf).unwrap();
        let loaded = SilentPaymentWallet::load(&mut &buf[..]).unwrap();
        let utxo = loaded.all_utxos().into_iter().next().unwrap();
        assert_eq!(utxo.outpoint.txid, [0x42; 32]);
        assert_eq!(utxo.outpoint.vout, 3);
        assert_eq!(utxo.k, 7);
        assert_eq!(utxo.amount, 123_456);
        assert_eq!(utxo.block_height, 999);
        assert!(!utxo.spent);
        assert!(utxo.spent_by.is_none());
    }

    #[test]
    fn load_rejects_bad_magic() {
        let bad_data = b"BAD!some garbage data";
        let result = SilentPaymentWallet::load(&mut &bad_data[..]);
        assert!(result.is_err());
        match result {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::InvalidData),
            Ok(_) => panic!("Should have returned an error"),
        }
    }

    #[test]
    fn load_rejects_truncated_data() {
        let truncated = b"SP01";
        let result = SilentPaymentWallet::load(&mut &truncated[..]);
        assert!(result.is_err(), "Should fail on truncated input");
    }

    #[test]
    fn save_and_load_to_file() {
        let mut wallet = SilentPaymentWallet::new();
        wallet.process_found_payments(&[make_payment([0x01; 32], 0, 50_000, 0)], 100);
        let dir = std::env::temp_dir();
        let path = dir.join("sp_wallet_test.bin");
        wallet.save_to_file(&path).unwrap();
        let loaded = SilentPaymentWallet::load_from_file(&path).unwrap();
        assert_eq!(loaded.scan_height, 100);
        assert_eq!(loaded.balance(), 50_000);
        std::fs::remove_file(&path).ok();
    }

    fn decode_witness(hex: &str) -> Vec<Vec<u8>> {
        if hex.is_empty() {
            return vec![];
        }
        let bytes = Vec::<u8>::from_hex(hex).unwrap();
        let mut pos = 0;
        let n = bytes[pos] as usize;
        pos += 1;
        let mut items = Vec::with_capacity(n);
        for _ in 0..n {
            let len = bytes[pos] as usize;
            pos += 1;
            items.push(bytes[pos..pos + len].to_vec());
            pos += len;
        }
        items
    }

    // Bitcoin txids are big-endian in display/JSON; BIP-352 outpoint comparison
    // uses internal (little-endian) byte order — reverse the txid.
    fn build_outpoint(txid_hex: &str, vout: u32) -> [u8; 36] {
        let mut op = [0u8; 36];
        for (i, b) in Vec::<u8>::from_hex(txid_hex)
            .unwrap()
            .iter()
            .rev()
            .enumerate()
        {
            op[i] = *b;
        }
        op[32..].copy_from_slice(&vout.to_le_bytes());
        op
    }

    #[test]
    #[allow(clippy::type_complexity)]
    fn bip352_receiving_vectors() {
        let secp = Secp256k1::new();
        let raw = include_str!("../../tests/bip352_vectors.json");
        let data: serde_json::Value = serde_json::from_str(raw).unwrap();

        let mut passed = 0;

        for test_case in data.as_array().unwrap() {
            let comment = test_case["comment"].as_str().unwrap();

            if comment.contains("K_max") {
                continue;
            }

            for receiving in test_case["receiving"].as_array().unwrap() {
                let given = &receiving["given"];
                let expected = &receiving["expected"];

                let scan_key = ScanKey::from_slice(
                    &Vec::<u8>::from_hex(given["key_material"]["scan_priv_key"].as_str().unwrap())
                        .unwrap(),
                )
                .expect("valid scan key");

                let spend_priv = SecretKey::from_slice(
                    &Vec::<u8>::from_hex(given["key_material"]["spend_priv_key"].as_str().unwrap())
                        .unwrap(),
                )
                .expect("valid spend key");
                let spend_pub = PublicKey::from_secret_key(&secp, &spend_priv);
                let spend_key = SpendKey::from_slice(&spend_pub.serialize()).unwrap();

                let input_storage: Vec<(Vec<u8>, Vec<u8>, Vec<Vec<u8>>, [u8; 36])> = given["vin"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|vin| {
                        let prevout = Vec::<u8>::from_hex(
                            vin["prevout"]["scriptPubKey"]["hex"].as_str().unwrap(),
                        )
                        .unwrap();
                        let script_sig =
                            Vec::<u8>::from_hex(vin["scriptSig"].as_str().unwrap_or("")).unwrap();
                        let witness = decode_witness(vin["txinwitness"].as_str().unwrap_or(""));
                        let outpoint = build_outpoint(
                            vin["txid"].as_str().unwrap(),
                            vin["vout"].as_u64().unwrap() as u32,
                        );
                        (prevout, script_sig, witness, outpoint)
                    })
                    .collect();

                let inputs: Vec<InputData> = input_storage
                    .iter()
                    .map(|(ps, ss, wi, op)| InputData {
                        prevout_script: ps,
                        script_sig: ss,
                        witness: wi.iter().map(|w| w.as_slice()).collect(),
                        outpoint: *op,
                    })
                    .collect();

                let taproot_outputs: Vec<(u32, XOnlyPublicKey)> = given["outputs"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .enumerate()
                    .filter_map(|(i, out)| {
                        XOnlyPublicKey::from_slice(
                            &Vec::<u8>::from_hex(out.as_str().unwrap()).unwrap(),
                        )
                        .ok()
                        .map(|xonly| (i as u32, xonly))
                    })
                    .collect();

                let labeled_keys: Vec<SpendKey> = given["labels"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter_map(|v| {
                        derive_labeled_spend_key(
                            &secp,
                            scan_key,
                            spend_key,
                            v.as_u64().unwrap() as u32,
                        )
                        .ok()
                    })
                    .collect();

                let found = scan_transaction(
                    &secp,
                    &scan_key,
                    &spend_key,
                    &inputs,
                    &taproot_outputs,
                    &labeled_keys,
                );

                let expected_outputs = expected["outputs"].as_array().unwrap();
                assert_eq!(
                    found.len(),
                    expected_outputs.len(),
                    "{comment}: scan found {} outputs, expected {}",
                    found.len(),
                    expected_outputs.len()
                );

                for exp in expected_outputs {
                    let exp_hex = exp["pub_key"].as_str().unwrap();
                    let exp_xonly =
                        XOnlyPublicKey::from_slice(&Vec::<u8>::from_hex(exp_hex).unwrap()).unwrap();
                    assert!(
                        found.iter().any(|f| f.x_only_pubkey == exp_xonly),
                        "{comment}: expected output {exp_hex} not found in results"
                    );
                }

                passed += 1;
            }
        }

        assert!(passed >= 26, "expected ≥26 cases, ran {passed}");
    }
}
