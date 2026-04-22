use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum ProtocolError {
    #[error("Entropy generation failed")]
    EntropyFailure,
    #[error("AEAD Encryption/Decryption error")]
    AeadError,
    #[error("Lattice cryptography error: {0}")]
    LatticeError(String),
    #[error("Signature verification failed")]
    VerificationFailed,
    #[error("Replay attack detected: Invalid nonce or timestamp")]
    ReplayDetected,
    #[error("Invalid protocol state: {0}")]
    InvalidState(String),
}
