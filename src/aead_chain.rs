use crate::error::ProtocolError;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use sha2::{Digest, Sha256};

pub struct SessionKey(pub [u8; 32]);

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct BlockCiphertext {
    pub id: usize,
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub hash_link: [u8; 32], 
}

pub struct ChunkingAead;

impl ChunkingAead {
    /// 分块加密
    pub fn encrypt_and_chain(
        key: &SessionKey,
        messages: Vec<Vec<u8>>,
    ) -> Result<Vec<BlockCiphertext>, ProtocolError> {
        let cipher = Aes256Gcm::new_from_slice(&key.0).map_err(|_| ProtocolError::AeadError)?;
        
        let mut blocks = Vec::with_capacity(messages.len());
        let mut prev_hash = [0u8; 32];

        for (i, msg) in messages.into_iter().enumerate() {
            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            let nonce = Nonce::from_slice(&nonce_bytes);

            let ciphertext = cipher
                .encrypt(nonce, msg.as_ref())
                .map_err(|_| ProtocolError::AeadError)?;

            let mut hasher = Sha256::new();
            hasher.update(&ciphertext);
            hasher.update(&prev_hash);
            let current_hash: [u8; 32] = hasher.finalize().into();

            blocks.push(BlockCiphertext {
                id: i,
                ciphertext,
                nonce: nonce_bytes,
                hash_link: current_hash,
            });

            prev_hash = current_hash;
        }

        Ok(blocks)
    }
}
