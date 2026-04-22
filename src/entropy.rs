use hkdf::Hkdf;
use rand::{rngs::ThreadRng, RngCore};
use sha2::Sha256;
use std::sync::atomic::{AtomicU64, Ordering};
use std::cell::RefCell;

/// 强类型：输出的增强熵
#[derive(Debug, Clone)]
pub struct EntropyOutput(pub [u8; 32]);

/// 混沌参数配置
#[derive(Debug, Clone)]
pub struct ChaosConfig {
    /// 混沌映射参数 μ (3.5 ~ 4.0)
    pub mu: f64,
    /// 初始状态 x0 (0 ~ 1)
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
    // 使用 parking_lot::Mutex 支持可配置的混沌参数
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

    /// 获取当前混沌配置
    // pub fn get_config(&self) -> ChaosConfig {
    //     self.chaos_config.lock().clone()
    // }

    /// 设置混沌配置
    pub fn set_config(&self, config: ChaosConfig) {
        *self.chaos_config.lock() = config.clone();
        *self.chaos_state.lock() = config.initial_state;
        self.counter.store(0, Ordering::SeqCst);
    }

    /// 单次混沌迭代，返回浮点值和字节表示
    pub fn chaos_simulate_once(&self) -> ([u8; 8], f64) {
        let config = self.chaos_config.lock().clone();
        let mut state = self.chaos_state.lock();
        
        // Logistic map: x_{n+1} = μ * x_n * (1 - x_n)
        let x = *state;
        *state = config.mu * x * (1.0 - x);
        
        let result = *state;
        drop(state); // 显式释放锁
        
        (result.to_le_bytes(), result)
    }
    
    /// 核心算法：r = HKDF(r_sys || r_chaos || counter)
    pub fn generate_entropy(&self) -> EntropyOutput {
        // 1. 获取 OS TRNG
        let mut r_sys = [0u8; 32];
        thread_local! {
            static THREAD_RNG: RefCell<ThreadRng> = RefCell::new(rand::thread_rng());
        }
        THREAD_RNG.with(|rng| rng.borrow_mut().fill_bytes(&mut r_sys));

        // 2. 获取混沌熵（单次迭代）
        let (r_chaos, _) = self.chaos_simulate_once();

        // 3. 获取并增加并发安全的 Counter
        let count = self.counter.fetch_add(1, Ordering::Relaxed);

        // 4. 组合输入源 (IKM)
        let mut ikm = Vec::with_capacity(32 + 8 + 8);
        ikm.extend_from_slice(&r_sys);
        ikm.extend_from_slice(&r_chaos);
        ikm.extend_from_slice(&count.to_le_bytes());

        // 5. 使用 HKDF 放大和提取熵 (Leftover Hash Lemma 保证安全性)
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
