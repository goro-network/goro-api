use crate::errors::GoRoError;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SignerSecret {
    pub(super) is_ed25519: bool,
    bytes: [u8; Self::PRIKEY_LENGTH],
}

impl SignerSecret {
    pub const PRIKEY_LENGTH: usize = 32;
    pub const SIGNING_CONTEXT: &[u8] = b"substrate";
    pub const SR25519_EXPANSION_MODE: schnorrkel::ExpansionMode = schnorrkel::MiniSecretKey::ED25519_MODE;
    pub const SIGNATURE_LENGTH: usize = schnorrkel::SIGNATURE_LENGTH;

    pub fn generate_sr25519() -> Self {
        let schnorrkel_mini_secret_key = schnorrkel::MiniSecretKey::generate();

        Self::try_from_sr25519_secret_bytes(&schnorrkel_mini_secret_key.to_bytes()).unwrap()
    }

    pub fn generate_ed25519() -> Self {
        let schnorrkel_mini_secret_key = schnorrkel::MiniSecretKey::generate();

        Self::try_from_ed25519_secret_bytes(&schnorrkel_mini_secret_key.to_bytes()).unwrap()
    }

    pub fn try_from_sr25519_secret_bytes(secret_bytes: &[u8]) -> Result<Self, GoRoError> {
        if secret_bytes.len() != Self::PRIKEY_LENGTH {
            return Err(GoRoError::BadInputBufferLength {
                expected: Self::PRIKEY_LENGTH,
                given: secret_bytes.len(),
            });
        }

        let mini_secret_key = schnorrkel::MiniSecretKey::from_bytes(secret_bytes).unwrap();
        let private = SignerSecret {
            is_ed25519: false,
            bytes: mini_secret_key.to_bytes(),
        };

        Ok(private)
    }

    pub fn try_from_ed25519_secret_bytes(secret_bytes: &[u8]) -> Result<Self, GoRoError> {
        if secret_bytes.len() != Self::PRIKEY_LENGTH {
            return Err(GoRoError::BadInputBufferLength {
                expected: Self::PRIKEY_LENGTH,
                given: secret_bytes.len(),
            });
        }

        let mini_secret_key = schnorrkel::MiniSecretKey::from_bytes(secret_bytes).unwrap();
        let private = SignerSecret {
            is_ed25519: true,
            bytes: mini_secret_key.to_bytes(),
        };

        Ok(private)
    }

    pub fn get_account(&self) -> super::public::SignerAccount {
        let mini_secret_key = schnorrkel::MiniSecretKey::from_bytes(&self.bytes).unwrap();
        let public_key_bytes = if self.is_ed25519 {
            let ed25519_secret = ed25519_zebra::SigningKey::from(mini_secret_key.to_bytes());
            let ed25519_public_bytes = ed25519_zebra::VerificationKeyBytes::from(&ed25519_secret);

            ed25519_public_bytes.into()
        } else {
            let keypair = mini_secret_key.expand_to_keypair(schnorrkel::ExpansionMode::Ed25519);

            keypair.public.to_bytes()
        };

        super::public::SignerAccount::from(public_key_bytes)
    }

    pub fn sign(&self, message: &[u8]) -> [u8; Self::SIGNATURE_LENGTH] {
        if self.is_ed25519 {
            let signer = ed25519_zebra::SigningKey::from(self.bytes);
            let signature = signer.sign(message);

            signature.into()
        } else {
            let mini_secret_key = schnorrkel::MiniSecretKey::from_bytes(&self.bytes).unwrap();
            let signer = mini_secret_key.expand(Self::SR25519_EXPANSION_MODE);
            let public_key = signer.to_public();
            let signature = signer.sign_simple(Self::SIGNING_CONTEXT, message, &public_key);

            signature.to_bytes()
        }
    }
}
