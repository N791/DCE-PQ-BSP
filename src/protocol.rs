use crate::aead_chain::BlockCiphertext;
use crate::entropy::{EntropyMixer, EntropyOutput};
use crate::error::ProtocolError;
use crate::lattice_sig::{
    BlindMessage, BlindSignature, BlindingFactor, LatticeBlindSigner, PrivateKey, PublicKey, Signature,
};
use rayon::prelude::*;
use std::time::{SystemTime, UNIX_EPOCH};

// --- 防重放与会话上下文 ---
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct SessionContext {
    pub session_id: String,
    pub timestamp: u64,
    pub nonce: [u8; 16],
}

// --- 实体结构 ---

pub struct User<L: crate::lattice_sig::LatticeBlindUser> {
    pub pk: PublicKey,
    pub lattice_engine: L,
    pub entropy_mixer: EntropyMixer,
}

impl<L: crate::lattice_sig::LatticeBlindUser> User<L> {
    /// 阶段 1：分块、获取混沌熵、盲化（使用 Rayon 并行盲化）
    pub fn prepare_blind_blocks(
        &self,
        ciphertexts: &[BlockCiphertext],
    ) -> Vec<(BlindMessage, BlindingFactor, EntropyOutput)> {
        // 使用并行迭代器处理所有块的盲化
        ciphertexts
            .par_iter()
            .map(|block| {
                // 每块单独生成混合混沌熵 r
                let r = self.entropy_mixer.generate_entropy();
                // 使用格基密码进行盲化 m' = H(m || r), m_blind = ...
                let (blind_msg, factor) = self.lattice_engine.blind(&self.pk, &block.ciphertext, &r.0);
                (blind_msg, factor, r)
            })
            .collect()
    }

    /// 阶段 3：并行去盲
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
    /// 阶段 2：校验上下文并并行签名
    pub fn sign_blocks(
        &self,
        context: &SessionContext,
        blind_messages: &[BlindMessage],
    ) -> Result<Vec<BlindSignature>, ProtocolError> {
        // 防重放检查 (Timestamp validation mock)
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        if now.saturating_sub(context.timestamp) > 300 {
            return Err(ProtocolError::ReplayDetected);
        }

        // 高性能并行格基签名
        blind_messages
            .par_iter()
            .map(|msg| self.lattice_engine.sign_blinded(&self.sk, msg))
            .collect()
    }
}
