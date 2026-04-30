use crate::error::ProtocolError;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(pub Vec<u8>);

#[derive(Clone, Debug)]
pub struct PrivateKey(pub Vec<u8>);

#[derive(Clone, Debug)]
pub struct BlindMessage(pub Vec<u8>);

#[derive(Clone, Debug)]
pub struct BlindingFactor(pub Vec<u8>);

#[derive(Clone, Debug)]
pub struct BlindSignature(pub Vec<u8>);

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct Signature(pub Vec<u8>);

pub trait LatticeBlindUser: Send + Sync {
    /// 盲化
    fn blind(&self, pk: &PublicKey, message: &[u8], entropy: &[u8]) -> (BlindMessage, BlindingFactor);
    /// 去盲
    fn unblind(&self, blind_sig: &BlindSignature, factor: &BlindingFactor) -> Result<Signature, ProtocolError>;
}

pub trait LatticeBlindSigner: Send + Sync {
    /// 签名
    fn sign_blinded(&self, sk: &PrivateKey, blind_msg: &BlindMessage) -> Result<BlindSignature, ProtocolError>;
}

#[allow(dead_code)]
pub trait LatticeVerifier: Send + Sync {
    /// 验证
    fn verify(&self, pk: &PublicKey, message: &[u8], sig: &Signature) -> Result<bool, ProtocolError>;
}

pub struct MockLatticeCrypto;

impl MockLatticeCrypto {
    pub fn generate_keypair() -> (PublicKey, PrivateKey) {
        (PublicKey(b"mock_pk".to_vec()), PrivateKey(b"mock_sk".to_vec()))
    }
}

impl LatticeBlindUser for MockLatticeCrypto {
    fn blind(&self, _pk: &PublicKey, message: &[u8], entropy: &[u8]) -> (BlindMessage, BlindingFactor) {
        let mut hasher = Sha256::new();
        hasher.update(message);
        hasher.update(entropy);
        let m_prime = hasher.finalize().to_vec();
        
        let factor = b"mock_alpha_beta".to_vec();
        let m_blind = [m_prime, factor.clone()].concat();
        
        (BlindMessage(m_blind), BlindingFactor(factor))
    }

    fn unblind(&self, blind_sig: &BlindSignature, factor: &BlindingFactor) -> Result<Signature, ProtocolError> {
        let sig_len = blind_sig.0.len().saturating_sub(factor.0.len());
        Ok(Signature(blind_sig.0[..sig_len].to_vec()))
    }
}

impl LatticeBlindSigner for MockLatticeCrypto {
    fn sign_blinded(&self, sk: &PrivateKey, blind_msg: &BlindMessage) -> Result<BlindSignature, ProtocolError> {
        let mut sig_data = sk.0.clone();
        sig_data.extend_from_slice(&blind_msg.0);
        Ok(BlindSignature(sig_data))
    }
}

impl LatticeVerifier for MockLatticeCrypto {
    fn verify(&self, _sk: &PublicKey, _message: &[u8], _sig: &Signature) -> Result<bool, ProtocolError> {
        Ok(true)
    }
}
