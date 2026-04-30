use hkdf::Hkdf;
use rand::{rngs::ThreadRng, RngCore};
use sha2::Sha256;
use std::sync::atomic::{AtomicU64, Ordering};
use std::cell::RefCell;

/// 增强熵
#[derive(Debug, Clone)]
pub struct EntropyOutput(pub [u8; 32]);

/// 混沌配置
#[derive(Debug, Clone)]
pub struct ChaosConfig {
    /// 映射参数
    pub mu: f64,
    /// 初始状态
    pub initial_state: f64,
}

impl Default for ChaosConfig {
    fn default() -> Self {
        Self {
            mu: 4.0,
            initial_state: 0.12345,
        }
    }
}

pub struct EntropyMixer {
    counter: AtomicU64,
    chaos_config: parking_lot::Mutex<ChaosConfig>,
    chaos_state: parking_lot::Mutex<f64>,
}

impl EntropyMixer {
    pub fn new() -> Self {
        let config = ChaosConfig::default();
        let initial = config.initial_state;
        Self {
            counter: AtomicU64::new(0),
            chaos_config: parking_lot::Mutex::new(config),
            chaos_state: parking_lot::Mutex::new(initial),
        }
    }

    pub fn with_config(config: ChaosConfig) -> Self {
        let initial = config.initial_state;
        Self {
            counter: AtomicU64::new(0),
            chaos_config: parking_lot::Mutex::new(config),
            chaos_state: parking_lot::Mutex::new(initial),
        }
    }

    /// 设置配置
    pub fn set_config(&self, config: ChaosConfig) {
        *self.chaos_config.lock() = config.clone();
        *self.chaos_state.lock() = config.initial_state;
        self.counter.store(0, Ordering::SeqCst);
    }

    /// 混沌迭代
    pub fn chaos_simulate_once(&self) -> ([u8; 8], f64) {
        let config = self.chaos_config.lock().clone();
        let mut state = self.chaos_state.lock();
        
        let x = *state;
        *state = config.mu * x * (1.0 - x);
        
        let result = *state;
        drop(state);
        
        (result.to_le_bytes(), result)
    }
    
    /// 生成熵
    pub fn generate_entropy(&self) -> EntropyOutput {
        let mut r_sys = [0u8; 32];
        thread_local! {
            static THREAD_RNG: RefCell<ThreadRng> = RefCell::new(rand::thread_rng());
        }
        THREAD_RNG.with(|rng| rng.borrow_mut().fill_bytes(&mut r_sys));

        let (r_chaos, _) = self.chaos_simulate_once();

        let count = self.counter.fetch_add(1, Ordering::Relaxed);

        let mut ikm = Vec::with_capacity(32 + 8 + 8);
        ikm.extend_from_slice(&r_sys);
        ikm.extend_from_slice(&r_chaos);
        ikm.extend_from_slice(&count.to_le_bytes());

        let hk = Hkdf::<Sha256>::new(None, &ikm);
        let mut okm = [0u8; 32];
        hk.expand(b"chaos-lattice-blind-sig", &mut okm)
            .expect("HKDF expand length is valid");

        EntropyOutput(okm)
    }
}

impl Default for EntropyMixer {
    fn default() -> Self {
        Self::new()
    }
}
