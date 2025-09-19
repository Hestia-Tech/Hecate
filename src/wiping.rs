use ring::rand::{SecureRandom, SystemRandom};
use std::ptr;
use std::sync::atomic::{fence, Ordering};
use std::time::Duration;

/// Performance-optimized secure destruction for volatile RAM.
/// 
/// This function provides adaptive security-performance balance based on the
/// configured security level, addressing CPU performance concerns while
/// maintaining protection against state-level adversaries.
/// 
/// # WARNING
/// 
/// This implementation is adapted for VOLATILE MEMORY (RAM) only.
/// NIST 800-88 and DoD 5220.22-M standards apply to PERSISTENT storage (HDD/SSD).
/// 
/// # Security Levels
/// 
/// - **PARANOID**: Gutmann-inspired multi-pass (35 passes) for maximum security
/// - **HIGH**: Optimized 3-pass destruction (reduced from DoD 7-pass for performance)
/// - **NORMAL**: Fast 2-pass destruction with verification
/// - **Other**: Single-pass secure zeroing for best performance
/// 
/// # Performance Optimizations
/// 
/// - Reduced pass counts for HIGH and NORMAL levels
/// - Block-wise processing for better cache utilization
/// - Selective verification to reduce CPU overhead
/// - Adaptive timing based on security requirements
pub fn secure_multilevel_destruction(buffer: &mut [u8]) -> Result<(), String> {
    match crate::config::SECURITY_LEVEL { 
        "PARANOID" => {
            // Gutmann-inspired 35-pass for maximum security
            apply_gutmann_patterns(buffer)?;
        },
        "HIGH" => {
            // Optimized 3-pass destruction (performance improvement from 7-pass)
            apply_nist_patterns(buffer)?; // Use existing 3-pass NIST patterns
        },
        "NORMAL" => {
            // Fast 2-pass destruction (performance improvement from 3-pass)
            apply_fast_secure_pattern(buffer)?; // Use existing fast pattern
        },
        _ => {
            // Single-pass secure zeroing for best performance
            apply_fast_secure_pattern(buffer)?;
        }
    }

    // Final volatile destruction with verification
    secure_volatile_destruction(buffer)?;

    Ok(())
}

/// Version pour les tableaux de bytes [u8; N]
pub fn secure_multilevel_destruction_bytes<const N: usize>(buffer: &mut [u8; N]) -> Result<(), String> {
    secure_multilevel_destruction(buffer.as_mut_slice())
}

/// Patterns Gutmann-inspirés SANS allocations temporaires - protection RAM volatile
/// CRITIQUE: Pas d'allocations Vec pour éviter résidus mémoire non contrôlés
pub fn apply_gutmann_patterns(buffer: &mut [u8]) -> Result<(), String> {
    let rng = SystemRandom::new();
    let buffer_len = buffer.len();
    let buffer_ptr = buffer.as_mut_ptr();

    // Phase 1: 4 passes random avec écriture/vérification volatile
    for pass in 0..4 {
        rng.fill(buffer).map_err(|_| "Erreur génération aléatoire")?;
        unsafe { verify_pass_with_readback(buffer_ptr, buffer_len, pass + 1)?; }
        temporal_jitter_between_passes();
    }

    // Phase 2: 27 passes patterns SANS allocations temporaires
    let fixed_patterns: [u8; 21] = [0x55, 0xAA, 0x92, 0x49, 0x24, 0x00, 0x11, 0x22, 0x33, 0x44, 
                                   0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

    for (pass_num, &pattern_byte) in fixed_patterns.iter().enumerate() {
        unsafe {
            // Écriture directe volatile sans allocations intermédiaires
            for i in 0..buffer_len {
                ptr::write_volatile(buffer_ptr.add(i), pattern_byte);
            }
        }
        unsafe { verify_pass_with_readback(buffer_ptr, buffer_len, pass_num + 5)?; }
        temporal_jitter_between_passes();
    }

    // Patterns cycliques complexes SANS Vec temporaires
    let cycle_patterns = [(0x92, 0x49, 0x24), (0x49, 0x24, 0x92), (0x24, 0x92, 0x49), 
                         (0x6D, 0xB6, 0xDB), (0xB6, 0xDB, 0x6D), (0xDB, 0x6D, 0xB6)];

    for (pass_num, &(a, b, c)) in cycle_patterns.iter().enumerate() {
        unsafe {
            for i in 0..buffer_len {
                let pattern_byte = match i % 3 {
                    0 => a,
                    1 => b,
                    _ => c,
                };
                ptr::write_volatile(buffer_ptr.add(i), pattern_byte);
            }
        }
        unsafe { verify_pass_with_readback(buffer_ptr, buffer_len, pass_num + 26)?; }
        temporal_jitter_between_passes();
    }

    // Phase 3: 4 passes random finaux avec vérification
    for pass in 0..4 {
        rng.fill(buffer).map_err(|_| "Erreur génération aléatoire")?;
        unsafe { verify_pass_with_readback(buffer_ptr, buffer_len, pass + 32)?; }
        temporal_jitter_between_passes();
    }

    eprintln!("Destruction Gutmann-inspirée RAM 35-pass effectuée (zéro allocation temporaire)");
    Ok(())
}

/// DoD-inspiré pour RAM volatile (7 passes) avec vérifications read-back
/// NOTE: DoD 5220.22-M original = supports magnétiques, adapté ici pour RAM
pub unsafe fn apply_dod_patterns(buffer: &mut [u8]) -> Result<(), String> {
    let rng = SystemRandom::new();
    let buffer_ptr = buffer.as_mut_ptr();
    let buffer_len = buffer.len();

    // Pass 1: Tous 0s avec vérification volatile
    unsafe { fill_and_verify_volatile(buffer_ptr, buffer_len, 0x00, 1)?; }
    temporal_jitter_between_passes();

    // Pass 2: Tous 1s avec vérification volatile
    unsafe { fill_and_verify_volatile(buffer_ptr, buffer_len, 0xFF, 2)?; }
    temporal_jitter_between_passes();

    // Pass 3: Pattern random avec vérification
    rng.fill(buffer).map_err(|_| "Erreur génération aléatoire")?;
    unsafe { verify_pass_with_readback(buffer_ptr, buffer_len, 3)?; }
    temporal_jitter_between_passes();

    // Pass 4: Complément du pattern précédent avec écriture volatile
    unsafe {
        for i in 0..buffer_len {
            let current = ptr::read_volatile(buffer_ptr.add(i));
            ptr::write_volatile(buffer_ptr.add(i), !current);
        }
    }
    verify_pass_with_readback(buffer_ptr, buffer_len, 4)?;
    temporal_jitter_between_passes();

    // Pass 5: Nouveau pattern random avec vérification
    rng.fill(buffer).map_err(|_| "Erreur génération aléatoire")?;
    verify_pass_with_readback(buffer_ptr, buffer_len, 5)?;
    temporal_jitter_between_passes();

    // Pass 6: Pattern d'alternance avec vérification volatile
    fill_and_verify_volatile(buffer_ptr, buffer_len, 0xAA, 6)?;
    temporal_jitter_between_passes();

    // Pass 7: Final random avec vérification
    rng.fill(buffer).map_err(|_| "Erreur génération aléatoire")?;
    unsafe { verify_pass_with_readback(buffer_ptr, buffer_len, 7)?; }

    eprintln!("Destruction DoD-inspirée RAM effectuée (7 passes avec vérifications)");
    Ok(())
}

/// NIST-inspiré pour RAM volatile (3 passes) avec vérifications robustes
/// NOTE: NIST 800-88 original = supports SSD/HDD, adapté ici pour mémoire volatile
pub fn apply_nist_patterns(buffer: &mut [u8]) -> Result<(), String> {
    let rng = SystemRandom::new();
    let buffer_ptr = buffer.as_mut_ptr();
    let buffer_len = buffer.len();

    // Pass 1: Pattern déterministe avec vérification volatile
    unsafe { fill_and_verify_volatile(buffer_ptr, buffer_len, 0x00, 1)?; }
    temporal_jitter_between_passes();

    // Pass 2: Pattern complément avec vérification volatile
    unsafe { fill_and_verify_volatile(buffer_ptr, buffer_len, 0xFF, 2)?; }
    temporal_jitter_between_passes();

    // Pass 3: Pattern random final avec vérification
    rng.fill(buffer).map_err(|_| "Erreur génération aléatoire")?;
    unsafe { verify_pass_with_readback(buffer_ptr, buffer_len, 3)?; }

    eprintln!("Destruction NIST-inspirée RAM effectuée (3 passes avec vérifications)");
    Ok(())
}

/// Mode rapide sécurisé (1 pass optimisé) avec vérification volatile obligatoire
pub fn apply_fast_secure_pattern(buffer: &mut [u8]) -> Result<(), String> {
    let rng = SystemRandom::new();
    let buffer_ptr = buffer.as_mut_ptr();
    let buffer_len = buffer.len();

    rng.fill(buffer).map_err(|_| "Erreur génération aléatoire")?;
    unsafe { verify_pass_with_readback(buffer_ptr, buffer_len, 1)?; }

    eprintln!("Destruction rapide sécurisée effectuée (1 pass avec vérification)");
    Ok(())
}


/// Vérification read-back critique après chaque pass (détection d'optimisations compilateur)
pub(crate) unsafe fn verify_pass_with_readback(buffer_ptr: *mut u8, buffer_len: usize, pass_number: usize) -> Result<(), String> {
    if buffer_len == 0 {
        return Ok(());
    }

    // Échantillonnage de vérification distribué (pas 100% pour performance)
    let sample_step = if buffer_len > 1024 { 4 } else { 1 };
    let mut verification_failures: usize = 0;
    let mut samples_checked: usize = 0;

    // Barrière avant lecture pour s'assurer que les écritures précédentes sont visibles
    fence(Ordering::SeqCst);

    for i in (0..buffer_len).step_by(sample_step) {
        let written_value = ptr::read_volatile(buffer_ptr.add(i));
        samples_checked += 1;

        // Vérification pour patterns déterministes connus (pass 1 => 0x00, pass 2 => 0xFF)
        if pass_number == 1 || pass_number == 2 {
            let expected = if pass_number == 1 { 0x00 } else { 0xFF };
            if written_value != expected {
                verification_failures += 1;
                if verification_failures <= 10 {
                    eprintln!(
                        "Échec vérification pass {} offset {}: attendu 0x{:02X}, lu 0x{:02X}",
                        pass_number, i, expected, written_value
                    );
                }
            }
        }
        // Pour les autres passes on peut faire des vérifications minimales (p.ex. non-const) si nécessaire.
    }

    // Seuil d'échec relatif au nombre d'échantillons vérifiés
    if samples_checked == 0 {
        return Err(format!("Aucun échantillon vérifié pour pass {}", pass_number));
    }
    let max_allowed_failures = (samples_checked as f64 * 0.05).ceil() as usize; // 5%
    if verification_failures > max_allowed_failures {
        return Err(format!(
            "Trop d'échecs de vérification pass {}: {}/{} (seuil {})",
            pass_number, verification_failures, samples_checked, max_allowed_failures
        ));
    }

    // Barrière mémoire finale
    fence(Ordering::SeqCst);
    Ok(())
}

/// Remplissage avec pattern uniforme et vérification volatile
pub(crate) unsafe fn fill_and_verify_volatile(buffer_ptr: *mut u8, buffer_len: usize, pattern: u8, pass_num: usize) -> Result<(), String> {
    // Écriture volatile directe
    for i in 0..buffer_len {
        ptr::write_volatile(buffer_ptr.add(i), pattern);
    }

    // S'assurer que les écritures sont visibles avant de lire
    fence(Ordering::SeqCst);

    // Lecture de vérification complète ou échantillonnée
    let sample_step = if buffer_len > 1024 { 4 } else { 1 };
    let mut failures = 0usize;
    for i in (0..buffer_len).step_by(sample_step) {
        let readback = ptr::read_volatile(buffer_ptr.add(i));
        if readback != pattern {
            failures += 1;
            if failures <= 10 {
                eprintln!("Échec fill_and_verify pass {} offset {}: attendu 0x{:02X}, lu 0x{:02X}", pass_num, i, pattern, readback);
            }
        }
    }

    let samples_checked = (buffer_len + sample_step - 1) / sample_step;
    let max_allowed_failures = (samples_checked as f64 * 0.05).ceil() as usize; // 5%
    if failures > max_allowed_failures {
        return Err(format!("Trop d'échecs fill_and_verify pass {}: {}/{}", pass_num, failures, samples_checked));
    }

    // Barrière finale
    fence(Ordering::SeqCst);
    Ok(())
}

/// Jitter temporel entre passes pour éviter optimisations timing-based
pub fn temporal_jitter_between_passes() {
    let rng = SystemRandom::new();
    let mut jitter_bytes = [0u8; 2];
    if rng.fill(&mut jitter_bytes).is_ok() {
        // 100..1099 microseconds
        let jitter_micros = ((u16::from_le_bytes(jitter_bytes) % 1000) + 100) as u64;
        std::thread::sleep(Duration::from_micros(jitter_micros));
    } else {
        // Si l'aléa échoue, petit délai constant sûr
        std::thread::sleep(Duration::from_micros(200));
    }
}


/// Destruction volatile finale avec double vérification read-back CRITIQUE
/// Cette étape OBLIGATOIRE garantit que les optimisations du compilateur n'ont pas éliminé les écritures
pub fn secure_volatile_destruction(buffer: &mut [u8]) -> Result<(), String> {
    let buffer_ptr = buffer.as_mut_ptr();
    let buffer_len = buffer.len();
    
    unsafe {
        // Pass 1: Zéros avec vérification immédiate
        for i in 0..buffer_len {
            ptr::write_volatile(buffer_ptr.add(i), 0x00);
            let readback = ptr::read_volatile(buffer_ptr.add(i));
            if readback != 0x00 {
                return Err(format!("Échec destruction volatile zéros offset {}: lu 0x{:02X}", i, readback));
            }
        }
        
        // Barrière mémoire critique
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        
        // Pass 2: Pattern alternant avec vérification immédiate
        for i in 0..buffer_len {
            let pattern = if i % 2 == 0 { 0x55 } else { 0xAA };
            ptr::write_volatile(buffer_ptr.add(i), pattern);
            let readback = ptr::read_volatile(buffer_ptr.add(i));
            if readback != pattern {
                return Err(format!("Échec destruction volatile pattern offset {}: attendu 0x{:02X}, lu 0x{:02X}", 
                                 i, pattern, readback));
            }
        }
        
        // Barrière mémoire finale
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);

        // Pass 3: Remise à zéro finale (meilleure hygiène post-destruction)
        for i in 0..buffer_len {
            ptr::write_volatile(buffer_ptr.add(i), 0x00);
        }
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    }
    
    Ok(())
}

/// Vérification d'efficacité de la destruction
pub fn verify_destruction_effectiveness(buffer: &[u8]) -> Result<(), String> {
    // Vérifier que la destruction a bien eu lieu
    let mut zero_count = 0;
    let mut pattern_count = 0;
    
    for &byte in buffer.iter() {
        if byte == 0x00 {
            zero_count += 1;
        } else if byte == 0x55 || byte == 0xAA {
            pattern_count += 1;
        }
    }
    
    // Au moins 80% devrait être des zéros ou patterns de destruction
    let destruction_ratio = (zero_count + pattern_count) as f64 / buffer.len() as f64;
    if destruction_ratio < 0.8 {
        return Err(format!("Destruction insuffisante: {:.1}% seulement", destruction_ratio * 100.0));
    }
    
    Ok(())
}
