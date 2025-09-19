// Configuration centrale de Hecate
// Modifiez ces constantes pour ajuster le comportement sans variables d'environnement.

/// Niveau de sécurité global
/// Valeurs possibles: "PARANOID" | "HIGH" | "NORMAL"
pub const SECURITY_LEVEL: &str = "NORMAL";

/// Coût mémoire Argon2 en KiB si vous forcez une valeur.
/// Laissez à None pour une valeur dérivée automatiquement selon SECURITY_LEVEL.
/// Exemples de valeurs: 1_048_576 (PARANOID), 524_288 (HIGH), 262_144 (NORMAL)
pub const ARGON2_MEMORY_KIB_OVERRIDE: Option<u32> = None;

/// Coût temps Argon2 (nombre d'itérations).
/// Recommandations: 8 (équilibré), 3 (plus rapide), 16 (très élevé)
pub const ARGON2_TIME_COST: u32 = 8;

/// Nombre maximal de threads utilisés pour Argon2.
/// Bornes recommandées: 1..=4
pub const ARGON2_MAX_PARALLELISM: u32 = 4;