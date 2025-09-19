use my_project::Hecate;

fn main(){
    // Initialisation avec clé maître
    let mut hecate = Hecate::new(b"cle_32_octets_minimum_securiseeeeeeeeeeeeee").unwrap();
    println!("Hecate initialisée avec succès");

    // Dissimulation
    let datae = b"information sensible";
    hecate.conceal("document_secret", datae).unwrap();
    println!("Information dissimulée avec succès");

    // Récupération
    let data = hecate.retrieve("document_secret").unwrap();
    // Attention: ne pas logger les données sensibles en production

    if data == datae {
        println!(" ---------------> Récupération réussie");
    } else {
        println!("erreur mismatch") 
    }

    // Effacement sécurisé
    hecate.purge("document_secret").unwrap();
}

