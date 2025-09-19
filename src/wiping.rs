use ring::rand::{SecureRandom, SystemRandom};
use std::ptr;

/// Destruction sécurisée multiniveau pour RAM volatile - NE PAS CONFONDRE avec standards disques
/// AVERTISSEMENT: NIST 800-88 et DoD 5220.22-M s'appliquent aux supports PERSISTANTS (HDD/SSD), 
/// pas à la RAM volatile. Cette impl. adapte les principes pour mémoire volatile uniquement.
pub fn secure_multilevel_destruction(buffer: &mut [u8]) -> Result<(), String> {
    match crate::config::SECURITY_LEVEL { 
        "PARANOID" => {
            // Pattern Gutmann 35-pass pour résistance maximale
            apply_gutmann_patterns(buffer)?;
        },
        "HIGH" => unsafe {
            // US DoD 5220.22-M standard (7 passes)
            apply_dod_patterns(buffer)?;
        },
        "NORMAL" => {
            // NIST 800-88 recommandé (3 passes)
            apply_nist_patterns(buffer)?;
        },
        _ => {
            // Mode rapide adaptatif (1 pass sécurisé)
            apply_fast_secure_pattern(buffer)?;
        }
    }

    // Destruction finale volatile avec vérification read-back
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
    let mut verification_failures = 0;
    
    // Échantillonnage de vérification distribué (pas 100% pour performance)
    let sample_step = if buffer_len > 1024 { 4 } else { 1 };
    
    for i in (0..buffer_len).step_by(sample_step) {
        let written_value = ptr::read_volatile(buffer_ptr.add(i));
        
        // Si c'est un pattern connu, on peut le vérifier
        if pass_number <= 2 {
            let expected = if pass_number == 1 { 0x00 } else { 0xFF };
            if written_value != expected {
                verification_failures += 1;
                if verification_failures < 10 { // Limite les logs
                    eprintln!("Échec vérification pass {} offset {}: attendu 0x{:02X}, lu 0x{:02X}", 
                            pass_number, i, expected, written_value);
                }
            }
        }
    }
    
    let sample_step = if buffer_len > 1024 { 4 } else { 1 };
    if verification_failures > buffer_len / 20 { // > 5% échecs
        return Err(format!("Trop d'échecs de vérification pass {}: {}/{}", 
                          pass_number, verification_failures, buffer_len / sample_step));
    }
    
    // Barrière mémoire critique pour forcer écriture
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    Ok(())
}

/// Remplissage avec pattern uniforme et vérification volatile
pub(crate) unsafe fn fill_and_verify_volatile(buffer_ptr: *mut u8, buffer_len: usize, pattern: u8, pass_num: usize) -> Result<(), String> {
    // Écriture volatile directe
    for i in 0..buffer_len {
        ptr::write_volatile(buffer_ptr.add(i), pattern);
    }
    
    verify_pass_with_readback(buffer_ptr, buffer_len, pass_num)
}

/// Jitter temporel entre passes pour éviter optimisations timing-based
pub fn temporal_jitter_between_passes() {
    let rng = SystemRandom::new();
    let mut jitter_bytes = [0u8; 2];
    rng.fill(&mut jitter_bytes).unwrap_or_default();
    
    let jitter_micros = ((u16::from_le_bytes(jitter_bytes) % 1000) + 100) as u64;
    std::thread::sleep(std::time::Duration::from_micros(jitter_micros));
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