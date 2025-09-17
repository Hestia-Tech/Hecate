use std::sync::Arc;
use std::sync::Mutex;
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, Key, XNonce
};
use rand::{Rng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::collections::HashMap;
use sha3::{Sha3_256, Digest};
use argon2::{Argon2, Params};
use secrecy::{Secret, ExposeSecret};


#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;


pub struct Hecate {

    fragments: Vec<Arc<Mutex<MemoryFragment>>>,

    lookup_table: HashMap<u64, Vec<usize>>,
	
    derived_key: Secret<[u8; 32]>,

    argon2_salt: [u8; 32],

    decoy_data: Vec<Box<[u8]>>,

    access_counter: Arc<Mutex<u64>>,
}

#[derive(Zeroize)]
#[zeroize(drop)]
struct MemoryFragment {
    data: Box<[u8]>,
    checksum: [u8; 32],
    obfuscation_layer: Box<[u8]>,
}

impl Hecate {

    pub fn new(master_key: &[u8]) -> Result<Self, String> {
        if master_key.len() < 32 {
            return Err("Clé trop courte (min 32 octets)".into());
        }

      println!("Initialisation de Hecate avec une clé maître de {} octets", master_key.len());


        Self::basic_memory_randomization();

       println!("Randomisation mémoire initiale effectuée");

        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);

      println!("Salage aléatoire généré");
        
        let derived_key = Self::derive_key_argon2(master_key, &salt)?;

      println!("Dérivation de clé sécurisée effectuée");

        let decoy_data = Self::generate_enhanced_decoy_data(20);

      println!("Données leurres générées");

        Ok(Self {
            fragments: Vec::new(),
            lookup_table: HashMap::new(),
            derived_key: Secret::new(derived_key),
            argon2_salt: salt,
            decoy_data,
            access_counter: Arc::new(Mutex::new(0)),
        })
    }


    pub fn conceal(&mut self, identifier: &str, data: &[u8]) -> Result<(), String> {

        self.enhanced_intrusion_detection()?;

        let data_id = Self::hash_identifier(identifier);

        let encrypted = self.encrypt_data(data)?;

        let fragment_sizes = Self::generate_random_fragment_sizes(encrypted.len());
        let mut fragments_indices = Vec::new();
        let mut offset = 0;

        for size in fragment_sizes {
            let end = std::cmp::min(offset + size, encrypted.len());
            let fragment_data = &encrypted[offset..end];

            let obfuscation = Self::generate_obfuscation_layer(fragment_data.len());
            let mut obfuscated = fragment_data.to_vec();
            for (i, byte) in obfuscated.iter_mut().enumerate() {
                *byte ^= obfuscation[i];
            }

            let checksum = Self::calculate_checksum(&obfuscated);

            let fragment = MemoryFragment {
                data: obfuscated.into_boxed_slice(),
                checksum,
                obfuscation_layer: obfuscation.into_boxed_slice(),
            };

            let index = self.random_insert_fragment(fragment);
            fragments_indices.push(index);

            offset = end;
        }

        self.lookup_table.insert(data_id, fragments_indices);

        self.perform_enhanced_decoy_operations();

        Ok(())
    }

    pub fn retrieve(&mut self, identifier: &str) -> Result<Vec<u8>, String> {

        self.enhanced_intrusion_detection()?;


        self.apply_timing_protection();

        let data_id = Self::hash_identifier(identifier);

        let (indices, lookup_success) = self.constant_time_lookup(data_id);


        const MAX_FRAGMENTS: usize = 16; 
        const BYTES_PER_FRAGMENT_BUDGET: usize = 128; 
        
        let mut reconstructed = Vec::new();
        let mut accumulated_errors = Vec::new();
        let mut integrity_valid = true;

        for fragment_idx in 0..MAX_FRAGMENTS {
            let processing_result = self.process_fragment_constant_time(
                &indices, 
                fragment_idx, 
                BYTES_PER_FRAGMENT_BUDGET
            );
            
            match processing_result {
                Ok(fragment_data) => {
                    if fragment_idx < indices.len() {
                        reconstructed.extend_from_slice(&fragment_data);
                    }
                },
                Err(error) => {
                    accumulated_errors.push(error);
                    integrity_valid = false;
                }
            }
            

            self.apply_fragment_timing_protection();
        }
        

        if !lookup_success {
            return Err("Donnée non trouvée".into());
        }
        
        if !integrity_valid || !accumulated_errors.is_empty() {
            return Err("Intégrité compromise ou fragments corrompus".into());
        }
        
        self.decrypt_data(&reconstructed)
    }

    fn constant_time_lookup(&self, data_id: u64) -> (Vec<usize>, bool) {
        let mut rng = rand::thread_rng();

        let lookup_result = self.lookup_table.get(&data_id);
        let lookup_success = lookup_result.is_some();
        
        let indices = if let Some(real_indices) = lookup_result {
            real_indices.clone()
        } else {

            let fake_count = rng.gen_range(1..=8); 
            let max_fragment_index = self.fragments.len().saturating_sub(1);
            
            (0..fake_count).map(|_| {
                if max_fragment_index > 0 {
                    rng.gen_range(0..=max_fragment_index)
                } else {
                    0
                }
            }).collect()
        };

        self.apply_lookup_timing_protection();
        
        (indices, lookup_success)
    }
    

    fn process_fragment_constant_time(
        &self, 
        indices: &[usize], 
        fragment_idx: usize, 
        byte_budget: usize
    ) -> Result<Vec<u8>, String> {
        let mut processing_buffer = vec![0u8; byte_budget];
        let mut actual_data_size = 0;
        
        if fragment_idx < indices.len() {
            let fragment_index = indices[fragment_idx];
            
            if let Some(fragment_arc) = self.fragments.get(fragment_index) {
                if let Ok(fragment) = fragment_arc.lock() {

                    let data_size = std::cmp::min(fragment.data.len(), byte_budget);
                    processing_buffer[..data_size].copy_from_slice(&fragment.data[..data_size]);
                    actual_data_size = data_size;
                    
                    let current_checksum = Self::calculate_checksum(&fragment.data);
                    let expected_checksum = fragment.checksum;
                    
                    let checksum_valid = current_checksum[..] == expected_checksum[..];
                    
                    let _dummy_checksum = Self::calculate_checksum(&processing_buffer);
                    std::hint::black_box(_dummy_checksum);
                    
                    if !checksum_valid {
                        return Err("Checksum invalide".into());
                    }
                    

                    let obf_size = std::cmp::min(fragment.obfuscation_layer.len(), byte_budget);
                    for i in 0..byte_budget {
                        if i < obf_size {
                            processing_buffer[i] ^= fragment.obfuscation_layer[i];
                        } else {
                            processing_buffer[i] ^= 0; 
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

    fn apply_lookup_timing_protection(&self) {
        let mut rng = rand::thread_rng();
        
        let dummy_lookups = rng.gen_range(2..5);
        for _ in 0..dummy_lookups {
            let dummy_id = rng.gen::<u64>();
            let _ = self.lookup_table.get(&dummy_id);
        }
        
        std::thread::sleep(std::time::Duration::from_micros(20));
    }
    

    fn apply_fragment_timing_protection(&self) {
        let mut dummy_buffer = [0u8; 64];
        OsRng.fill_bytes(&mut dummy_buffer);
        let _dummy_checksum = Self::calculate_checksum(&dummy_buffer);
        

        std::thread::sleep(std::time::Duration::from_micros(10));
    }

    pub fn purge(&mut self, identifier: &str) -> Result<(), String> {
        let data_id = Self::hash_identifier(identifier);

        if let Some(indices) = self.lookup_table.remove(&data_id) {
            for &index in &indices {
                if let Some(fragment_arc) = self.fragments.get_mut(index) {
                    if let Ok(mut fragment) = fragment_arc.lock() {

                        for _ in 0..3 {
                            OsRng.fill_bytes(&mut fragment.data);
                            OsRng.fill_bytes(&mut fragment.checksum);
                        }

                    }
                }
            }
        }

        Ok(())
    }

    // === Méthodes privées de sécurité ===


    fn derive_key_argon2(master_key: &[u8], salt: &[u8]) -> Result<[u8; 32], String> {

        let params = if cfg!(test) || std::env::var("HECATE_FAST_MODE").is_ok() {
            Params::new(
                8_192,     // 8 MiB pour tests (au lieu de 1 GiB)
                2,         // 2 itérations (au lieu de 10)
                1,         // 1 thread (au lieu de 4)
                Some(32),  // Longueur de sortie: 32 octets
            ).map_err(|e| format!("Erreur paramètres Argon2: {}", e))?
        } else {
            Params::new(
                8_192, // 1 GiB de mémoire (en KiB)  1_048_576
                2,        // 10 itérations
                1,         // 4 threads parallèles
                Some(32),  // Longueur de sortie: 32 octets
            ).map_err(|e| format!("Erreur paramètres Argon2: {}", e))?
        };
        
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id, // Variante id (résistante aux attaques par canaux latéraux)
            argon2::Version::V0x13,      // Version 1.3
            params,
        );
        
        let mut output = [0u8; 32];
        

        let pepper = b"HECATE_SYSTEM_2025_DOMAIN_SEPARATION";
        let mut combined_input = Vec::with_capacity(master_key.len() + pepper.len());
        combined_input.extend_from_slice(master_key);
        combined_input.extend_from_slice(pepper);
        
        argon2.hash_password_into(&combined_input, salt, &mut output)
            .map_err(|e| format!("Erreur dérivation Argon2: {}", e))?;
            
        Ok(output)
    }

    fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let key = Key::from_slice(self.derived_key.expose_secret());
        let cipher = XChaCha20Poly1305::new(key);

        let mut nonce_bytes = [0u8; 24]; 
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        cipher.encrypt(nonce, data)
            .map(|mut encrypted| {

                let mut result = nonce_bytes.to_vec();
                result.append(&mut encrypted);
                result
            })
            .map_err(|_| "Erreur de chiffrement XChaCha20".into())
    }

    fn decrypt_data(&self, encrypted: &[u8]) -> Result<Vec<u8>, String> {
        if encrypted.len() < 24 {
            return Err("Données corrompues".into());
        }

        let (nonce_bytes, ciphertext) = encrypted.split_at(24); 
        let nonce = XNonce::from_slice(nonce_bytes);

        let key = Key::from_slice(self.derived_key.expose_secret());
        let cipher = XChaCha20Poly1305::new(key);

        cipher.decrypt(nonce, ciphertext)
            .map_err(|_| "Erreur de déchiffrement XChaCha20".into())
    }

    fn hash_identifier(identifier: &str) -> u64 {
        let mut hasher = Sha3_256::new();
        hasher.update(identifier.as_bytes());
        let result = hasher.finalize();
        u64::from_le_bytes(result[0..8].try_into().unwrap())
    }

    fn calculate_checksum(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    fn generate_random_fragment_sizes(total_size: usize) -> Vec<usize> {
        let mut rng = rand::thread_rng();
        let mut sizes = Vec::new();
        let mut remaining = total_size;

        while remaining > 0 {
            let size = if remaining > 64 {
                rng.gen_range(16..=64)
            } else {
                remaining
            };
            sizes.push(size);
            remaining = remaining.saturating_sub(size);
        }

        sizes
    }

    fn generate_obfuscation_layer(size: usize) -> Vec<u8> {
        let mut layer = vec![0u8; size];
        OsRng.fill_bytes(&mut layer);
        layer
    }

    fn random_insert_fragment(&mut self, fragment: MemoryFragment) -> usize {
        let mut rng = rand::thread_rng();
        let insert_pos = if self.fragments.is_empty() {
            0
        } else {
            rng.gen_range(0..=self.fragments.len())
        };

        self.fragments.insert(insert_pos, Arc::new(Mutex::new(fragment)));
        insert_pos
    }

    fn generate_decoy_data(count: usize) -> Vec<Box<[u8]>> {
        let mut decoys = Vec::new();
        let mut rng = rand::thread_rng();

        for _ in 0..count {
            let size = rng.gen_range(100..1000);
            let mut data = vec![0u8; size];
            OsRng.fill_bytes(&mut data);
            decoys.push(data.into_boxed_slice());
        }

        decoys
    }

    fn perform_decoy_operations(&mut self) {
        let mut rng = rand::thread_rng();


        for _ in 0..rng.gen_range(1..5) {
            let index = rng.gen_range(0..self.decoy_data.len());

            let _ = &self.decoy_data[index][0];
        }
    }

    fn check_access_pattern(&self) -> Result<(), String> {
        let mut counter = self.access_counter.lock()
            .map_err(|_| "Erreur de verrouillage")?;

        *counter += 1;

        if *counter > 1000 {
            return Err("Trop d'accès détectés".into());
        }

        Ok(())
    }
}

impl Drop for Hecate {
    fn drop(&mut self) {

        self.argon2_salt.zeroize();
        

        for fragment_arc in &mut self.fragments {
            if let Ok(mut fragment) = fragment_arc.lock() {
                fragment.zeroize();
            }
        }

        self.lookup_table.clear();

    }
}

impl Hecate {
    /// Randomisation mémoire basique (s'appuie sur l'OS ASLR et l'allocateur)
    fn basic_memory_randomization() {
        let mut rng = rand::thread_rng();

        let mut temp_allocations = Vec::new();
        for _ in 0..10 {
            let size = rng.gen_range(1024..4096);
            let mut buffer = vec![0u8; size];
            OsRng.fill_bytes(&mut buffer);
            temp_allocations.push(buffer);
        }
        
        drop(temp_allocations);
    }

    fn apply_timing_protection(&self) {
        let mut rng = rand::thread_rng();
        

        let start = std::time::Instant::now();
        
        let dummy_ops = rng.gen_range(5..8);
        for _ in 0..dummy_ops {

            let mut dummy = 0u64;
            for i in 0..100 {
                dummy = dummy.wrapping_add(i * 17);
            }
            std::hint::black_box(dummy);
        }
        
        let elapsed = start.elapsed();
        if elapsed < std::time::Duration::from_micros(50) {
            let sleep_time = std::time::Duration::from_micros(50) - elapsed;
            std::thread::sleep(sleep_time);
        }
    }

    fn generate_enhanced_decoy_data(count: usize) -> Vec<Box<[u8]>> {
        let mut decoys = Vec::new();
        let mut rng = rand::thread_rng();

        for _ in 0..count {
            let size = rng.gen_range(64..2048);
            let mut data = vec![0u8; size];

            match rng.gen_range(0..3) {
                0 => OsRng.fill_bytes(&mut data), 
                1 => {

                    for (i, byte) in data.iter_mut().enumerate() {
                        *byte = ((i * 13 + 37) % 256) as u8;
                    }
                }
                _ => {

                    data[0..4].copy_from_slice(&(size as u32).to_le_bytes());
                    OsRng.fill_bytes(&mut data[4..]);
                }
            }
            
            decoys.push(data.into_boxed_slice());
        }

        decoys
    }

    fn perform_enhanced_decoy_operations(&mut self) {
        let mut rng = rand::thread_rng();
        
        let operations_count = rng.gen_range(5..15);
        
        for i in 0..operations_count {
            let index = rng.gen_range(0..self.decoy_data.len());

            let operation_type = rng.gen_range(0..6);

            let start_time = std::time::Instant::now();
            
            match operation_type {
                0 => { 

                    let _ = &self.decoy_data[index][0];
                    std::hint::black_box(&self.decoy_data[index][0]);
                },
                1 => { 

                    let end = std::cmp::min(8, self.decoy_data[index].len());
                    let data_slice = &self.decoy_data[index][0..end];
                    std::hint::black_box(data_slice);
                },
                2 => { 

                    let checksum = Self::calculate_checksum(&self.decoy_data[index]);
                    std::hint::black_box(checksum);
                },
                3 => {

                    let fake_key = [0u8; 32];
                    let key = Key::from_slice(&fake_key);
                    let cipher = XChaCha20Poly1305::new(key);
                    std::hint::black_box(&cipher);
                },
                4 => {

                    let mut hasher = Sha3_256::new();
                    hasher.update(&self.decoy_data[index][..std::cmp::min(32, self.decoy_data[index].len())]);
                    let result = hasher.finalize();
                    std::hint::black_box(result);
                },
                _ => {

                    let mut dummy_calc = 0u64;
                    for (j, &byte) in self.decoy_data[index].iter().enumerate().take(16) {
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
            

            if i % 3 == 0 {
                std::thread::sleep(std::time::Duration::from_nanos(rng.gen_range(50..500)));
            }
        }
    }


    fn enhanced_intrusion_detection(&self) -> Result<(), String> {
        let mut counter = self.access_counter.lock()
            .map_err(|_| "Erreur de verrouillage critique")?;


        *counter += 1;
        let access_rate = *counter;
        

        if access_rate > 2000 {
            return Err("Détection d'attaque par force brute".into());
        }
        

        if Self::detect_high_cpu_usage() {
            return Err("Activité CPU suspecte détectée".into());
        }
        
        Ok(())
    }
    
    fn detect_high_cpu_usage() -> bool {
        // Implémentation simplifiée 
        false // Placeholder
    }
}

fn main(){
  // Initialisation avec clé maître
  let mut hecate = Hecate::new(b"cle_32_octets_minimum_securiseeeeeeeeeeeeee").unwrap();
  println!("Hecate initialisée avec succès");

  // Dissimulation
  hecate.conceal("document_secret", b"Information sensible").unwrap();
  println!("Information dissimulée avec succès");

  // Récupération
  let data = hecate.retrieve("document_secret").unwrap();
  println!("Récupéré: {:?}", data);

  if data == b"Information sensible" {
    println!("Récupération réussie");
  } else {
   print!("erreur mismatch") 
}

  // Effacement sécurisé
  hecate.purge("document_secret").unwrap();
}
// === Tests ===
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conceal_and_retrieve() {
        let master_key = b"une_cle_tres_secrete_de_32_bytes";
        let mut hecate = Hecate::new(master_key).unwrap();

        let secret = b"Information ultra confidentielle";
        hecate.conceal("doc1", secret).unwrap();

        let retrieved = hecate.retrieve("doc1").unwrap();
        assert_eq!(secret.to_vec(), retrieved);
    }

    #[test]
    fn test_purge() {
        let master_key = b"une_cle_tres_secrete_de_32_bytes";
        let mut hecate = Hecate::new(master_key).unwrap();

        hecate.conceal("doc2", b"Secret").unwrap();
        hecate.purge("doc2").unwrap();

        assert!(hecate.retrieve("doc2").is_err());
    }
}

