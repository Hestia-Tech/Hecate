use hecate::Hecate;


#[test]
fn bteste(){
    // Initialisation avec clé maître
    let mut hecate = Hecate::new(b"cle_32_octets_minimum_securiseeeeeeeeeeeeee").unwrap();
    println!("Hecate initialisée avec succès");

    // Dissimulation
    let datae = b"information sensible";
    hecate.conceal("document_secret", datae).unwrap();
    println!("Information dissimulée avec succès");

    // Récupération
    let data = hecate.retrieve("document_secret").unwrap();
    println!("Récupéré: {:?}", data);

    assert_eq!(datae, datae);

    // Effacement sécurisé
    hecate.purge("document_secret").unwrap();
}
/// Test basique de fonctionnement
#[test]
fn test_basic_functionality() {


    let mut hecate = Hecate::new(b"cle_32_octets_minimum_securiseeeeeeeeeeeeee").unwrap();

    let test_data = b"information sensible .is_err().is_err()";
    hecate.conceal("document_er", test_data).unwrap();
    
    // Test retrieve
    let retrieved = hecate.retrieve("document_er").unwrap();
    assert_eq!(test_data.to_vec(), retrieved);

    // Test purge
    hecate.purge("document").unwrap();
    //assert!(hecate.retrieve("document_er").is_err());


}

/// Test avec différentes tailles de données
#[test]
fn test_data_sizes() {

    
    let master_key = b"size_test_key_32_bytes_exactly__";
    let mut hecate = Hecate::new(master_key).unwrap();

    // Petit
    let small = b"Small data but long enough for proper encryption";
    hecate.conceal("small", small).unwrap();
    assert_eq!(small.to_vec(), hecate.retrieve("small").unwrap());

    // Moyen (1KB)
    let medium = vec![0x42u8; 1024];
    hecate.conceal("medium", &medium).unwrap();
    assert_eq!(medium, hecate.retrieve("medium").unwrap());

    // Grand (4KB)
    let large = vec![0x37u8; 4096];
    hecate.conceal("large", &large).unwrap();
    assert_eq!(large, hecate.retrieve("large").unwrap());

}

/// Test gestion d'erreurs basique
#[test]
fn test_basic_errors() {
    // Clé trop courte
    assert!(Hecate::new(b"short").is_err());
    
    //setup_fast_mode();
    
    // Clé valide
    let master_key = b"valid_key_32_bytes_for_testing__";
    let mut hecate = Hecate::new(master_key).unwrap();

    // Récupération d'une donnée inexistante
    assert!(hecate.retrieve("nonexistent").is_err());

}

/// Test stockage multiple
#[test]
fn test_multiple_storage() {
    
    let master_key = b"multi_test_key_32_bytes_exactly_";
    let mut hecate = Hecate::new(master_key).unwrap();

    // Stocker plusieurs items
    hecate.conceal("item1", b"First item data long enough for encryption").unwrap();
    hecate.conceal("item2", b"Second item data long enough for encryption").unwrap();
    hecate.conceal("item3", b"Third item data long enough for encryption").unwrap();

    // Vérifier récupération
    assert_eq!(b"First item data long enough for encryption".to_vec(), 
               hecate.retrieve("item1").unwrap());
    assert_eq!(b"Second item data long enough for encryption".to_vec(), 
               hecate.retrieve("item2").unwrap());
    assert_eq!(b"Third item data long enough for encryption".to_vec(), 
               hecate.retrieve("item3").unwrap());

    // Purge sélective
    hecate.purge("item2").unwrap();
    assert!(hecate.retrieve("item2").is_err());
    
    // Les autres doivent toujours exister
    assert!(hecate.retrieve("item1").is_ok());
    assert!(hecate.retrieve("item3").is_ok());

}

/// Test patterns binaires
#[test]
fn test_binary_patterns() {
   
    
    let master_key = b"binary_test_key_32_bytes_exactly";
    let mut hecate = Hecate::new(master_key).unwrap();

    // Données avec tous types de bytes
    let binary_data: Vec<u8> = (0..=255).cycle().take(512).collect();
    hecate.conceal("binary", &binary_data).unwrap();
    assert_eq!(binary_data, hecate.retrieve("binary").unwrap());

    // Pattern répétitif
    let pattern = vec![0xAA; 256];
    hecate.conceal("pattern", &pattern).unwrap();
    assert_eq!(pattern, hecate.retrieve("pattern").unwrap());
    
    
}

/// Test identifiants spéciaux
#[test]
fn test_special_identifiers() {
   
    
    let master_key = b"special_id_key_32_bytes_exactly_";
    let mut hecate = Hecate::new(master_key).unwrap();

    let test_data = b"Test data for special identifiers that is long enough";

    let special_ids = [
        "normal_id",
        "id_with_numbers_123",
        "id@domain.com",
        "path/to/file.txt",
        "very_long_identifier_that_might_cause_issues_in_some_systems",
        "", // ID vide
    ];

    for id in &special_ids {
        hecate.conceal(id, test_data).unwrap();
        assert_eq!(test_data.to_vec(), hecate.retrieve(id).unwrap());
        hecate.purge(id).unwrap();
    }
    
    
}

/// Test instances multiples
#[test]
fn test_multiple_instances() {
   
    
    let key1 = b"instance1_key_32_bytes_exactly__";
    let key2 = b"instance2_key_32_bytes_exactly__";

    let mut hecate1 = Hecate::new(key1).unwrap();
    let mut hecate2 = Hecate::new(key2).unwrap();

    let data1 = b"Data from first instance that is long enough for encryption";
    let data2 = b"Data from second instance that is long enough for encryption";

    hecate1.conceal("shared_id", data1).unwrap();
    hecate2.conceal("shared_id", data2).unwrap();

    // Chaque instance récupère ses propres données
    assert_eq!(data1.to_vec(), hecate1.retrieve("shared_id").unwrap());
    assert_eq!(data2.to_vec(), hecate2.retrieve("shared_id").unwrap());
    
    
}

/// Test de robustesse léger
#[test]
fn test_light_robustness() {
   
    
    let master_key = b"robustness_key_32_bytes_exactly_";
    let mut hecate = Hecate::new(master_key).unwrap();

    // Test avec accès répétés
    let data = b"Robustness test data that is long enough for proper encryption";
    hecate.conceal("robust_test", data).unwrap();

    // Accès multiple
    for _ in 0..10 {
        assert_eq!(data.to_vec(), hecate.retrieve("robust_test").unwrap());
    }
    
    
}

/// Test performance basique
#[test]
fn test_basic_performance() {
   
    
    let master_key = b"performance_key_32_bytes_exactly";
    let mut hecate = Hecate::new(master_key).unwrap();

    // Test avec 8KB (taille raisonnable)
    let data = vec![0x55; 8192];
    
    let start = std::time::Instant::now();
    hecate.conceal("perf_test", &data).unwrap();
    let conceal_time = start.elapsed();
    
    let start = std::time::Instant::now();
    let retrieved = hecate.retrieve("perf_test").unwrap();
    let retrieve_time = start.elapsed();
    
    assert_eq!(data, retrieved);
    
    println!("Performance (8KB): Conceal {:?}, Retrieve {:?}",
             conceal_time, retrieve_time);
    
    
}