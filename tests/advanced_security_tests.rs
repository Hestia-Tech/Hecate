use hecate::Hecate;
use hecate::crypto::{encrypt_data_impl, decrypt_data_impl, derive_key_argon2};
use ring::rand::{SecureRandom, SystemRandom};

fn fixed_key() -> [u8; 32] {
    // Clé de test fixe de 32 octets
    *b"0123456789ABCDEF0123456789ABCDEF"
}

#[test]
fn test_unique_nonce_and_aead_integrity() {
    let key = fixed_key();
    let plaintext = b"State-grade adversary resilience test payload";

    // Plusieurs chiffrages: doivent être tous différents grâce au nonce aléatoire
    let mut outputs = Vec::new();
    for _ in 0..5 {
        let enc = encrypt_data_impl(&key, plaintext).expect("encrypt");
        assert!(enc.len() > 24, "nonce + ciphertext expected");
        outputs.push(enc);
    }

    // Chaque sortie doit être différente (nonce change)
    for i in 0..outputs.len() {
        for j in (i + 1)..outputs.len() {
            assert_ne!(outputs[i], outputs[j], "ciphertexts must differ due to random nonce");
        }
    }

    // Tous doivent se déchiffrer correctement
    for enc in outputs {
        let dec = decrypt_data_impl(&key, &enc).expect("decrypt");
        assert_eq!(dec, plaintext);
    }
}

#[test]
fn test_ciphertext_tamper_detection() {
    let key = fixed_key();
    let plaintext = b"AEAD tamper detection";
    let mut enc = encrypt_data_impl(&key, plaintext).expect("encrypt");

    // Corruption ciblée dans la partie ciphertext (après les 24 octets de nonce)
    assert!(enc.len() > 24);
    if enc.len() > 30 { enc[30] ^= 0x80; } else { enc[24] ^= 0x01; }

    // Le déchiffrement doit échouer (auth tag invalide)
    assert!(decrypt_data_impl(&key, &enc).is_err(), "tampering must be detected by AEAD");
}

#[test]
fn test_truncated_data_rejected() {
    let key = fixed_key();
    // Données trop courtes pour contenir un nonce
    let too_short = vec![0u8; 16];
    assert!(decrypt_data_impl(&key, &too_short).is_err(), "should reject truncated input");
}

#[test]
fn test_high_cardinality_many_items() {
    // Test réaliste: beaucoup d'items de tailles variées (mais raisonnables pour ne pas exploser le temps de test)
    let master_key = b"cardinality_key_32_bytes_exactly_____"; // 36 bytes, OK >= 32
    let mut hecate = Hecate::new(master_key).expect("Hecate::new");

    let rng = SystemRandom::new();
    let mut id_buf = [0u8; 8];
    let mut stored_ids = Vec::new();

    for _ in 0..5 {
        rng.fill(&mut id_buf).unwrap();
        let id = format!("item_{:016x}", u64::from_le_bytes(id_buf));

        // Tailles variables jusqu'à 32 KiB pour tester la fragmentation et reconstruction
        let mut sz_bytes = [0u8; 2];
        rng.fill(&mut sz_bytes).unwrap();
        let size = ((u16::from_le_bytes(sz_bytes) as usize) % 512) + 512; // [512, 33_279]

        let mut data = vec![0u8; size];
        rng.fill(&mut data).unwrap();

        hecate.conceal(&id, &data).expect("conceal");
        let out = hecate.retrieve(&id).expect("retrieve");
        assert_eq!(out, data, "retrieved data must match");

        stored_ids.push((id, data));
    }

    // Purge aléatoire de la moitié, vérifier erreurs et consistence des autres
    for (idx, (id, _data)) in stored_ids.iter().enumerate() {
        if idx % 2 == 0 {
            hecate.purge(id).expect("purge");
        }
    }

    for (idx, (id, data)) in stored_ids.into_iter().enumerate() {
        if idx % 2 == 0 {
            assert!(hecate.retrieve(&id).is_err(), "purged items must be gone");
        } else {
            assert_eq!(hecate.retrieve(&id).unwrap(), data, "kept items must still be retrievable");
        }
    }
}

#[test]
fn test_kdf_properties() {
    // Même entrée/salt => même clé; salt différent => clé différente
    let input = b"master_key_for_kdf";
    let salt1 = b"0123456789ABCDEF0123456789ABCDEF"; // 32 bytes
    let salt2 = b"FEDCBA9876543210FEDCBA9876543210"; // 32 bytes

    let k1 = derive_key_argon2(input, salt1).expect("kdf1");
    let k1b = derive_key_argon2(input, salt1).expect("kdf1b");
    let k2 = derive_key_argon2(input, salt2).expect("kdf2");

    assert_eq!(k1, k1b, "KDF must be deterministic for same salt");
    assert_ne!(k1, k2, "KDF must differ with different salt");
}

#[test]
fn test_binary_heavy_patterns() {
    let master_key = b"binary_heavy_key_32_bytes_exactly____"; // >=32 bytes
    let mut hecate = Hecate::new(master_key).expect("Hecate::new");

    // Données binaires variées
    let mut pattern1 = vec![0u8; 4096];
    let pattern2 = vec![0xAAu8; 8192];
    let pattern3: Vec<u8> = (0..=255).cycle().take(16_384).collect();

    let rng = SystemRandom::new();
    rng.fill(&mut pattern1).unwrap();

    hecate.conceal("p1", &pattern1).unwrap();
    hecate.conceal("p2", &pattern2).unwrap();
    hecate.conceal("p3", &pattern3).unwrap();

    assert_eq!(hecate.retrieve("p1").unwrap(), pattern1);
    assert_eq!(hecate.retrieve("p2").unwrap(), pattern2);
    assert_eq!(hecate.retrieve("p3").unwrap(), pattern3);
}

// Tests très lourds (volumes très élevés et/ou concurrence). Lancer avec: cargo test -- --ignored
#[ignore]
#[test]
fn test_extreme_large_payloads_1_4_mb() {
    let master_key = b"extreme_large_key_32_bytes_exactly____";
    let mut hecate = Hecate::new(master_key).expect("Hecate::new");

    let data1 = vec![0x37u8; 4096]; // 1 MiB
    let data2 = vec![0x55u8; 8192]; // 4 MiB

    hecate.conceal("big1", &data1).unwrap();
    hecate.conceal("big2", &data2).unwrap();

    assert_eq!(hecate.retrieve("big1").unwrap(), data1);
    assert_eq!(hecate.retrieve("big2").unwrap(), data2);
}

#[ignore]
#[test]
fn test_concurrent_instances_under_pressure() {
    use std::thread;

    let keys: Vec<[u8; 36]> = (0..8)
        .map(|i| {
            let mut k = [0u8; 36];
            k[..32].copy_from_slice(b"concurrent_key_32_bytes________");
            k[32..].copy_from_slice(&(i as u32).to_le_bytes());
            k
        })
        .collect();

    let mut handles = Vec::new();
    for (ti, k) in keys.into_iter().enumerate() {
        handles.push(thread::spawn(move || {
            let mut hecate = Hecate::new(&k).expect("Hecate::new");
            let rng = SystemRandom::new();

            for ii in 0..32 {
                let id = format!("tid{}_item{}", ti, ii);
                let mut sz_b = [0u8; 2];
                rng.fill(&mut sz_b).unwrap();
                let size = ((u16::from_le_bytes(sz_b) as usize) % 8192) + 1024;
                let mut data = vec![0u8; size];
                rng.fill(&mut data).unwrap();

                hecate.conceal(&id, &data).unwrap();
                let out = hecate.retrieve(&id).unwrap();
                assert_eq!(out, data);

                if ii % 3 == 0 {
                    hecate.purge(&id).unwrap();
                    assert!(hecate.retrieve(&id).is_err());
                }
            }
        }));
    }

    for h in handles { h.join().expect("thread join"); }
}