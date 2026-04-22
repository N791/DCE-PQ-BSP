# 基于混沌增强与格密码的抗量子隐私保护盲签名协议系统

[![Language](https://img.shields.io/badge/language-Rust-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Framework](https://img.shields.io/badge/GUI-egui-green.svg)](https://github.com/emilk/egui)

## 🛡️ 项目概述

本项目是一个用于学术研究和技术演示的高性能隐私保护协议原型。它结合了**非线性动力学（混沌系统）**与**抗量子密码学（格基密码）**，实现了在大规模数据流下的隐私匿名签名与完整性校验。系统采用 Rust 编写，深度利用 `Rayon` 并行计算框架，确保在处理海量数据块时的高吞吐量。

### 核心特性

- **混沌增强熵源 (`entropy.rs`)**：采用 Logistic 迭代映射生成伪随机序列，结合系统级真随机（TRNG）与 HKDF 算法提取高质量增强熵。
- **抗量子盲签名 (`lattice_sig.rs`)**：实现格基盲签名协议（盲化 -> 签名 -> 去盲），有效抵御潜在的量子计算威胁。
- **AEAD 分块哈希链 (`aead_chain.rs`)**：使用 AES-256-GCM 对数据进行分块加密，并通过 $h_i = H(c_i \parallel h_{i-1})$ 机制构建防篡改时序链。
- **极速并行架构 (`protocol.rs`)**：基于 `Rayon` 实现了数据级的并行盲化与签名处理，支持百万级数据块的极限压测。
- **交互式可视化界面 (`gui.rs`)**：
  - 实时渲染混沌系统 2D 时间序列与相位图。
  - **3D 轨迹可视化**：动态展示混沌吸引子在三维相位空间中的演变。
  - 全流程协议执行状态追踪与性能统计。



## 🏗️ 技术架构

系统分为以下几个核心模块：

| 模块 | 功能描述 | 关键技术 |
| :--- | :--- | :--- |
| `entropy` | 混沌熵源生成 | Logistic Map, HKDF, Atomic Counter |
| `lattice_sig` | 抗量子密码底层 | Lattice Blind Signature (Mock 实现) |
| `aead_chain` | 数据加密与链路绑定 | AES-256-GCM, SHA-256 Hash Chain |
| `protocol` | 业务流转实体 | Multi-threaded User/Signer Entity |
| `gui` | 可视化交互 | eframe, egui_plot, 3D Canvas |



## 🚀 快速开始

### 前置要求

- **Rust Toolchain**: 建议使用 `cargo 1.70+`
- **字体文件**: 项目运行需要 `fonts/msyh.ttf` (微软雅黑) 放置于根目录，以支持中文显示。

### 安装与运行

1. 克隆仓库：
   ```bash
   git clone [https://github.com/YourUsername/YourProjectName.git](https://github.com/YourUsername/YourProjectName.git)
   cd YourProjectName
    ```

2.  运行项目：

    ```bash
    cargo run --release
    ```

3.  运行内置实验测试：

    ```bash
    # 执行端到端验证、混沌熵提取及并发伸缩性测试
    cargo test -- --nocapture
    ```



## 📈 实验报告数据支持

项目内置了完整的基准测试脚本 (`tests.rs`)，可以生成以下实验数据：

  - **Amdahl 定律验证**：测量不同线程数下的吞吐量加速比。
  - **防重放延迟分析**：记录合法请求与恶意重放攻击的拦截耗时分布。
  - **混沌特性检测**：导出 100KB 级熵流数据用于 NIST 随机数检测。



## 📸 界面预览

  * **参数配置**：动态调整混沌参数 $\mu$ 与初始状态 $x_0$。
  * **混沌轨迹**：支持 3D 实时旋转的相位空间轨迹展示。
  * **协议压测**：支持 1\~1,000,000 个数据块的自动化流水线执行。



## 📜 许可证

本项目采用 MIT 许可证。详见 [LICENSE](https://www.google.com/search?q=LICENSE) 文件。