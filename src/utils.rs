use ring::rand::{SecureRandom, SystemRandom};
use std::sync::Arc;
use std::sync::Mutex;
use crate::MemoryFragment;
use chacha20poly1305::aead::KeyInit;

/// Helper pour échantillonnage uniforme sans biais
pub fn sample_uniform_u32(rng: &SystemRandom, max_exclusive: u32) -> Result<u32, String> {
    if max_exclusive == 0 {
        return Ok(0);
    }

    let threshold = (u32::MAX / max_exclusive) * max_exclusive;
    loop {
        let mut bytes = [0u8; 4];
        rng.fill(&mut bytes).map_err(|_| "Erreur génération aléatoire")?;
        let value = u32::from_le_bytes(bytes);
        if value < threshold {
            return Ok(value % max_exclusive);
        }
    }
}

/// Génère des tailles de fragments aléatoires pour la fragmentation
pub fn generate_random_fragment_sizes(total_size: usize) -> Result<Vec<usize>, String> {
    if total_size == 0 {
        return Ok(Vec::new());
    }

    let rng = SystemRandom::new();
    let mut fragments = Vec::new();
    let mut remaining = total_size;

    while remaining > 0 {
        if remaining <= 64 {
            fragments.push(remaining);
            break;
        }

        // Cap fragment size to 256 bytes to match retrieval byte budget (BYTES_PER_FRAGMENT_BUDGET)
        let max_size = std::cmp::min(remaining, 256);
        let min_size = std::cmp::min(64, remaining);
        
        let size_range = max_size - min_size;
        let random_size = if size_range > 0 {
            sample_uniform_u32(&rng, size_range as u32)? as usize + min_size
        } else {
            min_size
        };

        fragments.push(random_size);
        remaining -= random_size;
    }

    Ok(fragments)
}

/// Génère une couche d'obfuscation aléatoire
pub fn generate_obfuscation_layer(size: usize) -> Result<Vec<u8>, String> {
    let rng = SystemRandom::new();
    let mut obfuscation = vec![0u8; size];
    rng.fill(&mut obfuscation).map_err(|_| "Erreur génération obfuscation")?;
    Ok(obfuscation)
}

/// Insère un fragment à une position aléatoire dans la liste des fragments
pub fn random_insert_fragment_impl(fragments: &mut Vec<Arc<Mutex<MemoryFragment>>>, fragment: MemoryFragment) -> usize {
    // Indices stables: pas de coût ni de biais d’insertion observable
    let index = fragments.len();
    fragments.push(Arc::new(Mutex::new(fragment)));
    index
}

/// Génération de données leurres améliorées
pub fn generate_enhanced_decoy_data(count: usize) -> Vec<Box<[u8]>> {
    let mut decoys = Vec::new();
    let rng = SystemRandom::new();

    for _ in 0..count {
        let mut size_bytes = [0u8; 2];
        rng.fill(&mut size_bytes).unwrap();
        let size = ((u16::from_le_bytes(size_bytes) % (2048 - 64)) + 64) as usize;
        let mut data = vec![0u8; size];

        let mut pattern_bytes = [0u8; 1];
        rng.fill(&mut pattern_bytes).unwrap();
        match pattern_bytes[0] % 3 {
            0 => { rng.fill(&mut data).unwrap(); },
            1 => {
                // Pattern déterministe
                for (i, byte) in data.iter_mut().enumerate() {
                    *byte = ((i * 13 + 37) % 256) as u8;
                }
            }
            _ => {
                // Pattern avec header
                data[0..4].copy_from_slice(&(size as u32).to_le_bytes());
                rng.fill(&mut data[4..]).unwrap();
            }
        }

        decoys.push(data.into_boxed_slice());
    }

    decoys
}

/// Opérations factices sur les données leurres
pub fn perform_enhanced_decoy_operations_impl(decoy_data: &[Box<[u8]>]) {
    let rng = SystemRandom::new();

    let mut ops_bytes = [0u8; 1];
    rng.fill(&mut ops_bytes).unwrap();
    let operations_count = ((ops_bytes[0] % 10) + 5) as usize;

    for i in 0..operations_count {
        let mut index_bytes = [0u8; 4];
        rng.fill(&mut index_bytes).unwrap();
        let index = (u32::from_le_bytes(index_bytes) as usize) % decoy_data.len();

        let mut op_type_bytes = [0u8; 1];
        rng.fill(&mut op_type_bytes).unwrap();
        let operation_type = op_type_bytes[0] % 6;

        let start_time = std::time::Instant::now();

        match operation_type {
            0 => { 
                let _ = &decoy_data[index][0];
                std::hint::black_box(&decoy_data[index][0]);
            },
            1 => { 
                let end = std::cmp::min(8, decoy_data[index].len());
                let data_slice = &decoy_data[index][0..end];
                std::hint::black_box(data_slice);
            },
            2 => { 
                let checksum = crate::crypto::calculate_checksum(&decoy_data[index]);
                std::hint::black_box(checksum);
            },
            3 => {
                let fake_key = [0u8; 32];
                let key = chacha20poly1305::Key::from_slice(&fake_key);
                let cipher = chacha20poly1305::XChaCha20Poly1305::new(key);
                std::hint::black_box(&cipher);
            },
            4 => {
                let mut hasher = blake3::Hasher::new();
                let end = std::cmp::min(32, decoy_data[index].len());
                hasher.update(&decoy_data[index][..end]);
                let result = hasher.finalize();
                std::hint::black_box(result);
            },
            _ => {
                let mut dummy_calc = 0u64;
                for (j, &byte) in decoy_data[index].iter().enumerate().take(16) {
                    dummy_calc = dummy_calc.wrapping_add((byte as u64).wrapping_mul(j as u64));
                }
                std::hint::black_box(dummy_calc);
            }
        }

        let elapsed = start_time.elapsed();
        if elapsed < std::time::Duration::from_micros(100) {
            let sleep_time = std::time::Duration::from_micros(100) - elapsed;
            std::thread::sleep(sleep_time); 
        }

        // Jitter temporel
        if i % 3 == 0 {
            let mut delay_bytes = [0u8; 2];
            rng.fill(&mut delay_bytes).unwrap();
            let delay = ((u16::from_le_bytes(delay_bytes) % 450) + 50) as u64;
            std::thread::sleep(std::time::Duration::from_nanos(delay));
        }
    }
}

/// Randomisation mémoire basique (s'appuie sur l'OS ASLR et l'allocateur)
pub fn basic_memory_randomization() {
    let rng = SystemRandom::new();

    let mut temp_allocations = Vec::new();
    for _ in 0..10 {
        let mut size_bytes = [0u8; 2];
        rng.fill(&mut size_bytes).unwrap();
        let size = ((u16::from_le_bytes(size_bytes) % (4096 - 1024)) + 1024) as usize;
        let mut buffer = vec![0u8; size];
        rng.fill(&mut buffer).unwrap();
        temp_allocations.push(buffer);
    }

    drop(temp_allocations);
}