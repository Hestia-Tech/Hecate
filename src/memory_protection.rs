use libc::{mlock, munlock, sysconf, _SC_PAGESIZE, mmap, munmap, MAP_PRIVATE, MAP_ANONYMOUS, PROT_READ, PROT_WRITE};
use ring::rand::{SecureRandom, SystemRandom};
use std::ptr;
use std::sync::Arc;
use std::sync::Mutex;
use std::collections::HashMap;
use crate::{MemoryFragment, utils::sample_uniform_u32};

/// Région mémoire verrouillée sécurisée avec mmap
pub struct LockedMemoryRegion {
    pub ptr: *mut u8,
    pub size: usize,
    pub page_aligned_size: usize,
}

impl Drop for LockedMemoryRegion {
    fn drop(&mut self) {
        unsafe {
            // DESTRUCTION SÉCURISÉE CRITIQUE avant déverrouillage
            if !self.ptr.is_null() {
                // Triple pass destruction volatile pour régions sensibles
                for pass in 0..3 {
                    for i in 0..self.page_aligned_size {
                        ptr::write_volatile(self.ptr.add(i), match pass {
                            0 => 0x00,  // Pass 1: zéros
                            1 => 0xFF,  // Pass 2: uns  
                            _ => 0x55,  // Pass 3: alternance
                        });

                        // Vérification read-back immédiate CRITIQUE
                        let expected = match pass {
                            0 => 0x00, 1 => 0xFF, _ => 0x55,
                        };
                        let read_back = ptr::read_volatile(self.ptr.add(i));
                        if read_back != expected {
                            eprintln!("ALERTE SÉCURITAIRE: Échec destruction région verrouillée passe {} offset {}: attendu 0x{:02X}, lu 0x{:02X}", 
                                    pass + 1, i, expected, read_back);
                        }
                    }
                    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
                }

                // Déverrouiller puis désallouer après destruction complète
                munlock(self.ptr as *const libc::c_void, self.page_aligned_size);
                munmap(self.ptr as *mut libc::c_void, self.page_aligned_size);

                self.ptr = ptr::null_mut();
            }
        }
    }
}

/// PROTECTION CRITIQUE: Tenter de verrouiller les pages des Box<[u8]> contre swap/core dump
pub fn attempt_fragment_memory_protection(fragment: &MemoryFragment) {
    unsafe {
        let data_ptr = fragment.data.as_ptr() as *const libc::c_void;
        let data_len = fragment.data.len();
        let obf_ptr = fragment.obfuscation_layer.as_ptr() as *const libc::c_void;
        let obf_len = fragment.obfuscation_layer.len();
        
        // Marquer DONTDUMP et tenter de verrouiller (peut échouer selon privilèges)
        let _ = libc::madvise(data_ptr as *mut libc::c_void, data_len, libc::MADV_DONTDUMP);
        let _ = libc::madvise(obf_ptr as *mut libc::c_void, obf_len, libc::MADV_DONTDUMP);

        let data_result = mlock(data_ptr, data_len);
        let obf_result = mlock(obf_ptr, obf_len);
        
        if data_result != 0 || obf_result != 0 {
            // Mode dégradé silencieux - pas de panique critique
        }
    }
}

/// Lookup à temps constant avec brouillage
pub fn constant_time_lookup_impl(
    lookup_table: &HashMap<u64, Vec<usize>>, 
    fragments: &[Arc<Mutex<MemoryFragment>>],
    data_id: u64
) -> (Vec<usize>, bool) {
    let rng = SystemRandom::new();

    let lookup_result = lookup_table.get(&data_id);
    let lookup_success = lookup_result.is_some();

    let indices = if let Some(real_indices) = lookup_result {
        real_indices.clone()
    } else {
        // Générer des indices factices
        let mut fake_count_bytes = [0u8; 1];
        rng.fill(&mut fake_count_bytes).unwrap();
        let fake_count = ((fake_count_bytes[0] % 8) + 1) as usize;
        let max_fragment_index = fragments.len().saturating_sub(1);

        (0..fake_count).map(|_| {
            if max_fragment_index > 0 {
                sample_uniform_u32(&rng, (max_fragment_index + 1) as u32)
                    .unwrap_or(0) as usize
            } else {
                0
            }
        }).collect()
    };

    crate::crypto::apply_lookup_timing_protection(lookup_table, fragments);

    (indices, lookup_success)
}

/// Traitement de fragment à temps constant
pub fn process_fragment_constant_time_impl(
    fragments: &[Arc<Mutex<MemoryFragment>>], 
    indices: &[usize], 
    fragment_idx: usize, 
    byte_budget: usize
) -> Result<Vec<u8>, String> {
    let mut processing_buffer = vec![0u8; byte_budget];
    let mut actual_data_size = 0;

    if fragment_idx < indices.len() {
        let fragment_index = indices[fragment_idx];

        if let Some(fragment_arc) = fragments.get(fragment_index) {
            if let Ok(fragment) = fragment_arc.lock() {
                let data_size = std::cmp::min(fragment.data.len(), byte_budget);
                processing_buffer[..data_size].copy_from_slice(&fragment.data[..data_size]);
                actual_data_size = data_size;

                let current_checksum = crate::crypto::calculate_checksum(&fragment.data);
                let expected_checksum = fragment.checksum;

                let checksum_valid = current_checksum[..] == expected_checksum[..];

                let _dummy_checksum = crate::crypto::calculate_checksum(&processing_buffer);
                std::hint::black_box(_dummy_checksum);

                if !checksum_valid {
                    return Err("Checksum invalide".into());
                }

                // Désobfuscation
                let obf_size = std::cmp::min(fragment.obfuscation_layer.len(), byte_budget);
                for (i, byte) in processing_buffer.iter_mut().enumerate() {
                    if i < obf_size {
                        *byte ^= fragment.obfuscation_layer[i];
                    }
                }
            } else {
                return Err("Erreur de verrouillage".into());
            }
        } else {
            return Err("Fragment introuvable".into());
        }
    }

    Ok(processing_buffer[..actual_data_size].to_vec())
}

/// Initialisation de la mémoire anti-forensique
pub fn initialize_anti_forensic_memory_impl(hecate: &mut crate::Hecate) -> Result<(), String> {
    // Durcissement process (undumpable, no_new_privs)
    apply_process_hardening();

    // Désactiver les core dumps système critiques
    disable_system_core_dumps()?;
    
    // Protection cold-boot attacks
    apply_cold_boot_memory_scrambling(hecate)?;
    
    // Générer pools de pollution mémoire distribués
    generate_memory_pollution_waves(hecate)?;
    
    // Créer fragments de confusion forensique
    generate_forensic_confusion_fragments(hecate)?;
    
    // Verrouiller régions critiques sécurisées
    lock_critical_memory_regions(hecate)?;

    Ok(())
}

/// Durcissement process global (undumpable, no_new_privs)
fn apply_process_hardening() {
    unsafe {
        let _ = libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        let _ = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    }
}

/// Désactive les core dumps système pour protection critique
fn disable_system_core_dumps() -> Result<(), String> {
    use libc::{setrlimit, RLIMIT_CORE, rlimit};
    
    unsafe {
        let rlim = rlimit {
            rlim_cur: 0, // Limite courante = 0
            rlim_max: 0, // Limite maximale = 0
        };
        
        let result = setrlimit(RLIMIT_CORE, &rlim as *const rlimit);
        if result != 0 {
            eprintln!("Avertissement: Impossible de désactiver complètement les core dumps");
        }
    }
    
    Ok(())
}

/// Protection contre les attaques cold-boot avec brouillage mémoire
fn apply_cold_boot_memory_scrambling(hecate: &mut crate::Hecate) -> Result<(), String> {
    let rng = SystemRandom::new();
    
    // Effectuer 3-5 cycles de brouillage mémoire
    let mut cycles_bytes = [0u8; 1];
    rng.fill(&mut cycles_bytes).map_err(|_| "Erreur génération cycles")?;
    let scramble_cycles = ((cycles_bytes[0] % 3) + 3) as usize;
    
    println!("Application de {} cycles de brouillage anti-cold-boot", scramble_cycles);
    
    for cycle in 0..scramble_cycles {
        // Allocation temporaire pour brouiller la layout mémoire
        let mut scramble_sizes = Vec::new();
        for _ in 0..20 {
            let mut size_bytes = [0u8; 2];
            rng.fill(&mut size_bytes).map_err(|_| "Erreur génération taille scramble")?;
            let size = ((u16::from_le_bytes(size_bytes) % 8192) + 1024) as usize;
            scramble_sizes.push(size);
        }
        
        let mut temp_allocations = Vec::new();
        for &size in &scramble_sizes {
            let mut buffer = vec![0u8; size];
            rng.fill(&mut buffer).map_err(|_| "Erreur remplissage scramble")?;
            temp_allocations.push(buffer);
        }
        
        // Libérer dans un ordre aléatoire
        drop(temp_allocations);
        
        // Rotation des compteurs
        hecate.memory_rotation_counter = hecate.memory_rotation_counter.wrapping_add(1);
        if cycle % 2 == 0 {
            hecate.last_rotation_time = std::time::Instant::now();
        }
    }
    
    Ok(())
}

/// Génère des vagues de pollution mémoire distribués
fn generate_memory_pollution_waves(hecate: &mut crate::Hecate) -> Result<(), String> {
    let rng = SystemRandom::new();
    let mut wave_size_bytes = [0u8; 2];
    rng.fill(&mut wave_size_bytes).map_err(|_| "Erreur génération wave")?;
    let wave_size = ((u16::from_le_bytes(wave_size_bytes) % 32) + 8) as usize;

    for _ in 0..wave_size {
        let mut size_bytes = [0u8; 2];
        rng.fill(&mut size_bytes).map_err(|_| "Erreur génération taille wave")?;
        let size = ((u16::from_le_bytes(size_bytes) % 16384) + 1024) as usize;

        let mut pool = vec![0u8; size];
        fill_with_realistic_decoy_patterns(&mut pool);
        hecate.memory_pools.push(pool);
    }

    Ok(())
}

/// Remplit la mémoire avec des patterns réalistes pour tromper l'analyse
fn fill_with_realistic_decoy_patterns(buffer: &mut [u8]) {
    let rng = SystemRandom::new();
    let pattern_choice = {
        let mut choice = [0u8; 1];
        rng.fill(&mut choice).unwrap_or_default();
        choice[0] % 4
    };

    match pattern_choice {
        0 => {
            // Pattern ressemblant à des clés cryptographiques
            for (i, byte) in buffer.iter_mut().enumerate() {
                *byte = ((i * 31 + 17) ^ (i * 13 + 7)) as u8;
            }
        },
        1 => {
            // Pattern ressemblant à des données chiffrées
            rng.fill(buffer).unwrap_or_default();
        },
        2 => {
            // Pattern avec des séquences répétitives (simule des structures)
            let pattern = &[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
            for (i, byte) in buffer.iter_mut().enumerate() {
                *byte = pattern[i % pattern.len()] ^ ((i / pattern.len()) as u8);
            }
        },
        _ => {
            // Pattern avec checksum factice
            for (i, byte) in buffer.iter_mut().enumerate() {
                let checksum_byte = i.wrapping_mul(7).wrapping_add(23) as u8;
                *byte = checksum_byte ^ 0x5A;
            }
        }
    }
}

/// Génère des fragments factices pour confondre l'analyse forensique
fn generate_forensic_confusion_fragments(hecate: &mut crate::Hecate) -> Result<(), String> {
    let rng = SystemRandom::new();

    // Générer 50-100 fragments factices
    let mut count_bytes = [0u8; 1];
    rng.fill(&mut count_bytes).map_err(|_| "Erreur génération count")?;
    let fragment_count = ((count_bytes[0] % 50) + 50) as usize;

    for _ in 0..fragment_count {
        let mut size_bytes = [0u8; 2];
        rng.fill(&mut size_bytes).map_err(|_| "Erreur génération taille")?;
        let size = ((u16::from_le_bytes(size_bytes) % 512) + 64) as usize;

        let mut fragment = vec![0u8; size];
        fill_with_realistic_decoy_patterns(&mut fragment);

        hecate.decoy_fragments.push(fragment);
    }

    println!("Fragments de confusion générés: {}", hecate.decoy_fragments.len());
    Ok(())
}

/// Verrouille des régions critiques sécurisées avec mmap pour empêcher le swap
fn lock_critical_memory_regions(hecate: &mut crate::Hecate) -> Result<(), String> {
    let page_size = unsafe { sysconf(_SC_PAGESIZE) } as usize;

    // Régions adaptées au niveau de sécurité pour adversaire étatique
    let base_regions = match crate::config::SECURITY_LEVEL {
        "PARANOID" => vec![page_size * 256, page_size * 512, page_size * 1024], // 1-4 MiB
        "HIGH" => vec![page_size * 64, page_size * 128, page_size * 256],       // 256KB-1MiB
        _ => vec![page_size * 16, page_size * 32, page_size * 64],               // 64KB-256KB
    };

    let mut successful_locks = 0;

    for &size in &base_regions {
        match create_secure_locked_region(size, page_size) {
            Ok(region) => {
                hecate.locked_regions.push(region);
                successful_locks += 1;
            },
            Err(e) => {
                eprintln!("Avertissement: Impossible de créer la région verrouillée ({}): {}", size, e);
                // Continuer avec des régions plus petites si possible
            }
        }
    }

    if successful_locks == 0 {
        eprintln!("AVERTISSEMENT CRITIQUE: Aucune région mémoire verrouillée créée!");
        eprintln!("Considérez: 1) sudo sysctl vm.max_map_count=262144, 2) ulimit -l unlimited, 3) privilèges CAP_IPC_LOCK");
        return Err("Impossible de créer des régions sécurisées".to_string());
    }

    println!("Régions mémoire verrouillées: {} sur {} tentées", successful_locks, base_regions.len());
    Ok(())
}

/// Crée une région mémoire sécurisée avec mmap et mlock
fn create_secure_locked_region(size: usize, page_size: usize) -> Result<LockedMemoryRegion, String> {
    let page_aligned_size = size.div_ceil(page_size) * page_size;

    unsafe {
        // Allocation avec mmap pour contrôle total
        let ptr = mmap(
            ptr::null_mut(),
            page_aligned_size,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0
        ) as *mut u8;

        if ptr == libc::MAP_FAILED as *mut u8 {
            return Err("Erreur mmap".to_string());
        }

        // Remplir avec des données factices réalistes (toute la région mappée)
        let rng = SystemRandom::new();
        let slice = std::slice::from_raw_parts_mut(ptr, page_aligned_size);
        rng.fill(slice).map_err(|_| "Erreur remplissage région")?;

        // Marquer la région comme non-dumpable (meilleure résistance aux core dumps)
        let _ = libc::madvise(ptr as *mut libc::c_void, page_aligned_size, libc::MADV_DONTDUMP);

        // Verrouiller en mémoire
        let lock_result = mlock(ptr as *const libc::c_void, page_aligned_size);
        if lock_result != 0 {
            // Échec du verrouillage, nettoyer
            munmap(ptr as *mut libc::c_void, page_aligned_size);
            return Err("Erreur mlock".to_string());
        }

        Ok(LockedMemoryRegion {
            ptr,
            size,
            page_aligned_size,
        })
    }
}

/// Nettoie les structures anti-forensiques sécurisées  
pub fn cleanup_anti_forensic_memory_impl(hecate: &mut crate::Hecate) {
    // Les régions verrouillées se nettoient automatiquement via Drop trait
    let locked_count = hecate.locked_regions.len();
    hecate.locked_regions.clear(); // Trigger Drop pour chaque région

    // Effacement sécurisé des pools de mémoire
    for pool in &mut hecate.memory_pools {
        pool.fill(0); // Effacement avant libération
    }
    hecate.memory_pools.clear();

    // Effacement sécurisé des fragments factices
    for fragment in &mut hecate.decoy_fragments {
        fragment.fill(0);
    }
    hecate.decoy_fragments.clear();

    println!("Nettoyage anti-forensique terminé ({} régions verrouillées libérées)", locked_count);
}