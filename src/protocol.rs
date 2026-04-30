use crate::aead_chain::BlockCiphertext;
use crate::entropy::{EntropyMixer, EntropyOutput};
use crate::error::ProtocolError;
use crate::lattice_sig::{
    BlindMessage, BlindSignature, BlindingFactor, LatticeBlindSigner, PrivateKey, PublicKey, Signature,
};
use rayon::prelude::*;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct SessionContext {
    pub session_id: String,
    pub timestamp: u64,
    pub nonce: [u8; 16],
}

pub struct User<L: crate::lattice_sig::LatticeBlindUser> {
    pub pk: PublicKey,
    pub lattice_engine: L,
    pub entropy_mixer: EntropyMixer,
}

impl<L: crate::lattice_sig::LatticeBlindUser> User<L> {
    /// 准备盲化
    pub fn prepare_blind_blocks(
        &self,
        ciphertexts: &[BlockCiphertext],
    ) -> Vec<(BlindMessage, BlindingFactor, EntropyOutput)> {
        ciphertexts
            .par_iter()
            .map(|block| {
                let r = self.entropy_mixer.generate_entropy();
                let (blind_msg, factor) = self.lattice_engine.blind(&self.pk, &block.ciphertext, &r.0);
                (blind_msg, factor, r)
            })
            .collect()
    }

    /// 去盲签名
    pub fn unblind_signatures(
        &self,
        blind_sigs: &[BlindSignature],
        factors: &[BlindingFactor],
    ) -> Result<Vec<Signature>, ProtocolError> {
        if blind_sigs.len() != factors.len() {
            return Err(ProtocolError::InvalidState("Mismatched arrays".into()));
        }

        blind_sigs
            .par_iter()
            .zip(factors.par_iter())
            .map(|(sig, factor)| self.lattice_engine.unblind(sig, factor))
            .collect()
    }
}

pub struct Signer<S: LatticeBlindSigner> {
    pub sk: PrivateKey,
    pub lattice_engine: S,
}

impl<S: LatticeBlindSigner> Signer<S> {
    /// 签名块
    pub fn sign_blocks(
        &self,
        context: &SessionContext,
        blind_messages: &[BlindMessage],
    ) -> Result<Vec<BlindSignature>, ProtocolError> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        if now.saturating_sub(context.timestamp) > 300 {
            return Err(ProtocolError::ReplayDetected);
        }

        blind_messages
            .par_iter()
            .map(|msg| self.lattice_engine.sign_blinded(&self.sk, msg))
            .collect()
    }
}
