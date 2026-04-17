use bitcoin::hashes::{sha256, HashEngine};
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey, Verification, XOnlyPublicKey};

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
    use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};

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
}
