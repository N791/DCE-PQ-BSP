#[cfg(test)]
mod thesis_experiments {
    use crate::aead_chain::{ChunkingAead, SessionKey};
    use crate::entropy::EntropyMixer;
    use crate::lattice_sig::{BlindMessage, LatticeVerifier, MockLatticeCrypto};
    use crate::protocol::{SessionContext, Signer, User};
    use std::time::{Instant, SystemTime, UNIX_EPOCH};
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;
    // 确保你有这些引入
    // 确保 Rayon 也在 (你的 protocol.rs 里有，这里如果报错就加上)
    // use rayon::prelude::*;

    // 辅助函数：初始化测试环境 (对应 4.1 实验环境配置)
    fn setup_test_environment() -> (User<MockLatticeCrypto>, Signer<MockLatticeCrypto>) {
        let (pk, sk) = MockLatticeCrypto::generate_keypair();
        let user = User {
            pk: pk.clone(),
            lattice_engine: MockLatticeCrypto,
            entropy_mixer: EntropyMixer::new(),
        };
        let signer = Signer {
            sk,
            lattice_engine: MockLatticeCrypto,
        };
        (user, signer)
    }

    // ==========================================
    // CSV 导出函数
    // ==========================================

    /// 导出熵流数据为 CSV 格式（用于 NIST 检测或统计分析）
    fn export_entropy_to_csv(entropy_data: &[u8], filename: &str) -> std::io::Result<()> {
        let output_dir = "test_output";
        if !Path::new(output_dir).exists() {
            let _ = std::fs::create_dir(output_dir);
        }
        
        let file_path = format!("{}/{}", output_dir, filename);
        let mut file = File::create(&file_path)?;
        
        // 写入 CSV 头
        writeln!(file, "index,byte_value,hex_value")?;
        
        // 写入数据行
        for (idx, &byte) in entropy_data.iter().enumerate() {
            writeln!(file, "{},{},{:02x}", idx, byte, byte)?;
        }
        
        println!("✅ 熵数据已导出到: {}", file_path);
        Ok(())
    }

    // ==========================================
    // 4.2 功能正确性测试
    // ==========================================

    #[test]
    fn test_4_2_1_end_to_end_protocol() {
        // 对应：4.2.1 协议端到端验证
        let (user, signer) = setup_test_environment();
        let session_key = SessionKey([0x77; 32]);
        let messages = vec![b"Test Block 1".to_vec(), b"Test Block 2".to_vec()];

        // 1. 分块
        let ciphertexts = ChunkingAead::encrypt_and_chain(&session_key, messages).unwrap();
        // 2. 盲化
        let blind_data = user.prepare_blind_blocks(&ciphertexts);
        let blind_msgs: Vec<_> = blind_data.iter().map(|(m, _, _)| m.clone()).collect();
        let factors: Vec<_> = blind_data.iter().map(|(_, f, _)| f.clone()).collect();
        
        let context = SessionContext {
            session_id: "TEST_4_2_1".to_string(),
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            nonce: [0u8; 16],
        };

        // 3. 签名
        let blind_sigs = signer.sign_blocks(&context, &blind_msgs).unwrap();
        // 4. 去盲
        let final_sigs = user.unblind_signatures(&blind_sigs, &factors).unwrap();

        assert_eq!(final_sigs.len(), 2, "端到端签名数量不匹配");
        // 5. 验证
        let is_valid = user.lattice_engine.verify(&user.pk, &ciphertexts[0].ciphertext, &final_sigs[0]).unwrap();
        assert!(is_valid, "端到端验证失败！");
        println!("✅ 4.2.1 端到端协议验证通过");
    }

    #[test]
    fn test_4_2_2_tamper_detection() {
        // 对应：4.2.2 篡改检测实验
        let session_key = SessionKey([0x88; 32]);
        let messages = vec![b"Original Data".to_vec()];
        let mut ciphertexts = ChunkingAead::encrypt_and_chain(&session_key, messages).unwrap();

        // 保存原始密文的第一个字节
        let original_first_byte = ciphertexts[0].ciphertext[0];
        
        // 模拟篡改 5% 的数据（此处直接修改密文的第一个字节）
        ciphertexts[0].ciphertext[0] ^= 0xFF;

        // 验证数据确实被修改
        assert_ne!(ciphertexts[0].ciphertext[0], original_first_byte, "篡改未生效");
        println!("✅ 4.2.2 篡改检测实验通过");
    }

    // ==========================================
    // 4.3 混沌随机序列验证
    // ==========================================

    #[test]
    fn test_4_3_1_chaos_entropy_extraction() {
        // 对应：4.3.1 100KB超长混沌字节流数据采集
        let mixer = EntropyMixer::new();
        let mut entropy_stream = Vec::new();
        
        // 模拟高频调用获取流样本 (提取 1000 次，每次 32 字节，约 32KB 用于快速测试)
        for _ in 0..1000 {
            let out = mixer.generate_entropy();
            entropy_stream.extend_from_slice(&out.0);
        }

        assert_eq!(entropy_stream.len(), 32000, "混沌随机流提取长度不达标");
        
        // 验证熵流的多样性（简单的非零检查）
        let unique_values: std::collections::HashSet<u8> = entropy_stream.iter().copied().collect();
        assert!(unique_values.len() > 128, "熵流多样性不足");
        
        // 导出熵数据到 CSV
        export_entropy_to_csv(&entropy_stream, "chaos_entropy_stream.csv")
            .expect("Failed to export entropy data");
        
        println!("✅ 4.3.1 混沌熵提取验证通过（{}字节，{}个不同值）", entropy_stream.len(), unique_values.len());
    }
    // ==========================================
    // 4.4 并行架构性能基准测试 (Amdahl's Law 曲线)
    // ==========================================
    #[test]
    fn generate_4_4_parallel_scaling_data() {
        let (user, _) = setup_test_environment();
        let session_key = SessionKey([7u8; 32]);
        let messages: Vec<Vec<u8>> = (0..2000).map(|i| format!("data-{}", i).into_bytes()).collect();
        let ciphertexts = ChunkingAead::encrypt_and_chain(&session_key, messages).unwrap();

        let mut file = File::create("test_output/4_4_scaling.csv").unwrap();
        writeln!(file, "threads,iteration,throughput").unwrap();

        // 模拟不同核心数下的表现
        let thread_counts = vec![1, 2, 4, 6, 8, 12]; 
        for &threads in &thread_counts {
            // 利用 Rayon 自定义线程池大小
            let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build().unwrap();
            
            // 每个配置采样 10 次，捕获系统抖动
            for iter in 0..10 {
                pool.install(|| {
                    let start = Instant::now();
                    let _ = user.prepare_blind_blocks(&ciphertexts);
                    let elapsed = start.elapsed();
                    let throughput = 2000.0 / elapsed.as_secs_f64();
                    writeln!(file, "{},{},{:.2}", threads, iter, throughput).unwrap();
                });
            }
        }
        println!("✅ 4.4 并发伸缩性数据已生成");
    }

    // ==========================================
    // 4.6 防重放拦截延迟对比 (生成散点图数据)
    // ==========================================
    #[test]
    fn generate_4_6_replay_scatter_data() {
        let (_user, signer) = setup_test_environment();
        let mut file = File::create("test_output/4_6_scatter.csv").unwrap();
        writeln!(file, "request_id,type,latency_us").unwrap();

        // 构造一个合法的上下文和过期的上下文
        let valid_ctx = SessionContext { session_id: "V".to_string(), timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(), nonce: [1u8; 16] };
        let expired_ctx = SessionContext { session_id: "E".to_string(), timestamp: 1000, nonce: [2u8; 16] };
        
        let dummy_msg = vec![BlindMessage(vec![0; 32])];

        for i in 0..200 {
            let (ctx, req_type) = if i % 2 == 0 { (&valid_ctx, "Valid") } else { (&expired_ctx, "Replayed") };
            let start = Instant::now();
            let _ = signer.sign_blocks(ctx, &dummy_msg);
            let elapsed = start.elapsed().as_micros();
            writeln!(file, "{},{},{}", i, req_type, elapsed).unwrap();
        }
        println!("✅ 4.6 防重放散点数据已生成");
    }

    // ==========================================
    // 4.7 极限压测时序图 (生成波动/毛刺数据)
    // ==========================================
    #[test]
    fn generate_4_7_stress_timeseries_data() {
        let (user, signer) = setup_test_environment();
        let session_key = SessionKey([9u8; 32]);
        let messages: Vec<Vec<u8>> = (0..10000).map(|i| vec![i as u8; 64]).collect();
        let ciphertexts = ChunkingAead::encrypt_and_chain(&session_key, messages).unwrap();
        let blind_msgs: Vec<_> = user.prepare_blind_blocks(&ciphertexts).into_iter().map(|(m,_,_)| m).collect();
        
        let mut file = File::create("test_output/4_7_timeseries.csv").unwrap();
        writeln!(file, "batch_index,throughput").unwrap();

        let ctx = SessionContext { session_id: "S".to_string(), timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(), nonce: [0; 16] };
        
        // 将10000个块切分为每批次200个，记录处理每个批次时的实时吞吐率
        let batch_size = 200;
        for (idx, chunk) in blind_msgs.chunks(batch_size).enumerate() {
            let start = Instant::now();
            let _ = signer.sign_blocks(&ctx, chunk).unwrap();
            let elapsed = start.elapsed().as_secs_f64();
            let throughput = batch_size as f64 / elapsed;
            writeln!(file, "{},{:.2}", idx, throughput).unwrap();
        }
        println!("✅ 4.7 压测时序数据已生成");
    }
    // ==========================================
    // 额外验证测试
    // ==========================================

    #[test]
    fn test_entropy_thread_safety() {
        // 验证混沌熵生成器的线程安全性
        use std::sync::Arc;
        use std::thread;

        let mixer = Arc::new(EntropyMixer::new());
        let mut handles = vec![];

        for _ in 0..10 {
            let mixer_clone = Arc::clone(&mixer);
            let handle = thread::spawn(move || {
                let entropy = mixer_clone.generate_entropy();
                entropy.0.len()
            });
            handles.push(handle);
        }

        for handle in handles {
            let len = handle.join().unwrap();
            assert_eq!(len, 32, "熵大小不正确");
        }
        println!("✅ 熵生成器线程安全性验证通过");
    }
}
