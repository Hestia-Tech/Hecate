# Hecate

**Cryptographic memory vault and secure fragment manager**

> Named after the goddess of magic. The project uses dark-magic-themed naming for aesthetic purposes only. It involve occult practices. It is a software security project.

---

## Table of contents

* [About](#about)
* [Features](#features)
* [Status](#status)
* [Requirements](#requirements)
* [Installation](#installation)
* [Quick start](#quick-start)
* [Configuration](#configuration)
* [Design overview](#design-overview)
* [Security considerations](#security-considerations)
* [Testing](#testing)
* [Contributing](#contributing)
* [License](#license)
* [Acknowledgements & Inspiration](#acknowledgements--inspiration)
* [Disclaimer](#disclaimer)

---

## About

Hecate is a Rust library and demonstration daemon that implements a secure in-memory vault. It fragments, obfuscates, and protects sensitive byte sequences with robust cryptographic primitives and memory hygiene. The project focuses on minimizing attack surface for secrets that must live in RAM.

The repository mixes practical cryptography with an aesthetic theme taken from mythology. All cryptographic decisions and parameters are documented in-code and in this README.

## Features

* Fragmented memory storage to reduce contiguous secret exposure.
* Authenticated encryption of fragments.
* Argon2-based key derivation with per-instance salt.
* Integrity verification using SHA3 checksums.
* Zeroize-backed memory structures to wipe secrets on drop.
* Decoy/ham-sandwich data to complicate memory forensics.
* Thread-safe access via `Arc<Mutex<...>>` containers.
* Configurable parameters for tests and production use.

## Status

* Repository contains prototype and core library code.
* Not audited by a third party. Treat as experimental.

## Requirements

* Rust toolchain (stable, minimum version `1.70` recommended).
* `cargo` build system.
* Recommended system libraries: modern Linux distribution.

Dependencies are declared in `Cargo.toml` and include cryptographic crates. Review them before use.

## Installation

Clone the repository and build with cargo:

```bash
git clone https://github.com/Hestia-Tech/Hecate.git
cd hecate
cargo build --release
```


## Quick start

Example usage of the library is in `examples/` and in the `main.rs` entrypoint. Typical flow:

1. Provide a master key (minimum 32 bytes).
2. Initialize `Hecate::new(master_key)` which derives an instance key and salt.
3. Call `conceal(data)` to store sensitive data as a fragment.
4. Retrieve and `reveal(id)` when needed.

Unit tests show expected calls and error handling.

## Configuration

Configuration options are intentionally explicit and compile-time friendly. Key parameters to review:

* Argon2 parameters (`memory`, `iterations`, `parallelism`).
* Fragment size target.
* Decoy count and decoy size.
* Encryption algorithm choice and nonce size.

All parameters live in `config.rs` or at the top of the library crate. Change them only with a clear threat model in mind.

## Design overview

Inputs: master key and secret byte arrays.

Levers:

* Key derivation (Argon2)
* Fragmentation policy
* AEAD encryption per fragment

Outputs:

* Encrypted, integrity-checked fragments in memory
* Lookup table mapping hashed identifiers to fragment indices

The code is intentionally modular. See `src/` for modules: `hecate`, `fragment`, `crypto`, `policy`.

## Security considerations

This project aims to reduce the risk surface for secrets in RAM. 

Important notes:

* Master key management is the user's responsibility. Keep it out of swap and logs.
* Use OS-level protections: disable core dumps, lock memory (`mlock`) where possible.
* Review crate dependencies for vulnerabilities before production use.
* Parameterize Argon2 for your environment. Higher memory/iterations increase cost for attackers but also for legitimate users.
* The decoy mechanism increases forensic resistance but is not foolproof.

## Testing

Run unit tests and examples with cargo:

```bash
cargo test
cargo run --example simple
```

Include additional integration tests when changing crypto parameters.

## Contributing

Contributions are welcome. Follow these rules:

1. Open an issue before a major feature.
2. Use feature branches named `feature/<short-desc>`.
3. Create a pull request with a clear description and tests.
4. Keep changes small and reviewable.

Follow the repository `CODE_OF_CONDUCT.md` if present.

## License

This project is released under the Private License. See `LICENSE` for details.

## Acknowledgements & Inspiration

* Named after Hecate, the goddess associated with crossroads, magic, and thresholds. The name is thematic only.
* Cryptography primitives drawn from widely used crates in the Rust ecosystem.

## Disclaimer

 Use this software responsibly and legally. The authors are not liable for misuse.
