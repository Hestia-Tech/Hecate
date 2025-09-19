//! # Hecate Security Configuration Module
//!
//! This module contains centralized security configuration constants for the Hecate system.
//! These constants are carefully tuned for resistance against state-level adversaries
//! including nation-state actors with advanced computing resources.
//!
//! ## Security Levels
//!
//! - **PARANOID**: Maximum security settings for highest-threat environments
//! - **HIGH**: Strong security for high-value targets
//! - **NORMAL**: Balanced security for standard deployments
//! - **PERFORMANCE**: Optimized for performance while maintaining essential security

/// Global security level that determines the intensity of all protection mechanisms.
/// 
/// # Security Levels
/// 
/// - `"PARANOID"`: Maximum protection against state-level adversaries (1GB+ RAM, 16+ iterations)
/// - `"HIGH"`: Strong protection for high-value targets (512MB RAM, 12 iterations)
/// - `"NORMAL"`: Balanced protection for standard use (256MB RAM, 8 iterations)
/// - `"PERFORMANCE"`: Performance-optimized with essential security (128MB RAM, 4 iterations)
/// 
/// # State-Level Adversary Resistance
/// 
/// Higher security levels provide increased resistance against:
/// - Advanced persistent threats (APTs)
/// - Quantum-resistant key derivation parameters
/// - Memory analysis and cold-boot attacks
/// - Side-channel and timing attacks
pub const SECURITY_LEVEL: &str = "NORMAL";

/// Override for Argon2 memory cost in KiB.
/// 
/// When `None`, the memory cost is automatically determined based on `SECURITY_LEVEL`:
/// - PARANOID: 1,048,576 KiB (1 GiB) - Maximum resistance to parallel attacks
/// - HIGH: 524,288 KiB (512 MiB) - Strong resistance with reasonable performance
/// - NORMAL: 262,144 KiB (256 MiB) - Balanced approach
/// - PERFORMANCE: 131,072 KiB (128 MiB) - Minimum for security
/// 
/// # Security Note
/// 
/// Higher memory costs significantly increase resistance to:
/// - ASIC-based attacks
/// - GPU-accelerated brute force attacks
/// - State-sponsored parallel computing clusters
pub const ARGON2_MEMORY_KIB_OVERRIDE: Option<u32> = None;

/// Argon2 time cost (number of iterations).
/// 
/// This parameter directly affects the computational cost of key derivation.
/// Higher values provide better resistance against brute force attacks but
/// increase legitimate operation time.
/// 
/// # Recommended Values
/// 
/// - `16`: Maximum security for paranoid environments
/// - `12`: High security for sensitive applications
/// - `8`: Balanced performance/security (default)
/// - `4`: Performance-oriented minimum
/// 
/// # State-Level Adversary Considerations
/// 
/// Time costs above 12 are recommended when facing adversaries with:
/// - Dedicated ASIC hardware
/// - Massive GPU clusters
/// - Quantum-assisted classical computing
pub const ARGON2_TIME_COST: u32 = 4;

/// Maximum number of threads for Argon2 parallel processing.
/// 
/// This parameter controls the degree of parallelism in Argon2 operations.
/// The actual parallelism used is the minimum of this value and the
/// number of available CPU cores.
/// 
/// # Security vs Performance Trade-off
/// 
/// - Higher values: Better performance on multi-core systems
/// - Lower values: Better resistance to parallel attacks, lower resource usage
/// 
/// # State-Level Adversary Resistance
/// 
/// Values of 2-4 provide optimal balance between:
/// - Performance on legitimate systems
/// - Resistance to massively parallel attacks
/// - Memory bandwidth limitations that favor defenders
pub const ARGON2_MAX_PARALLELISM: u32 = 4;

/// Minimum key entropy bits required for master keys.
/// 
/// This enforces a minimum security level for all cryptographic operations.
/// Keys with insufficient entropy will be rejected.
pub const MIN_KEY_ENTROPY_BITS: usize = 256;

/// Maximum number of concurrent access attempts before triggering rate limiting.
/// 
/// This helps prevent:
/// - Brute force attacks
/// - Timing analysis through repeated access
/// - Resource exhaustion attacks
pub const MAX_CONCURRENT_ACCESS_ATTEMPTS: u64 = 100;

/// Interval in milliseconds for memory rotation to prevent long-term analysis.
/// 
/// Regular memory rotation helps defend against:
/// - Long-term memory analysis
/// - Cold boot attacks
/// - Advanced persistent memory monitoring
pub const MEMORY_ROTATION_INTERVAL_MS: u64 = 30000; // 30 seconds

/// Number of decoy fragments to generate for forensic confusion.
/// 
/// More decoy fragments provide better protection against:
/// - Memory forensics
/// - Pattern analysis
/// - Fragment reconstruction attempts
pub const DECOY_FRAGMENT_COUNT: usize = 100;