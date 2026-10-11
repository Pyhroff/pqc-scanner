use rsa::RsaPrivateKey;
use p256::ecdh::EphemeralSecret;
use sha1::Sha1;

fn legacy_crypto() {
    let _rsa = RsaPrivateKey::new(&mut rng, 2048)?;
    let _secret = EphemeralSecret::random(&mut rng);
    let _digest = Sha1::new();
}
