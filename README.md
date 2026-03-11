# Post-Quantum VPN (PQ-VPN)

A quantum-resistant Virtual Private Network using ML-KEM-768 for key exchange and AES-256-GCM for packet encryption.

## Project Status

🚧 **In Development** - MSc Final Project

## Overview

This project implements a VPN that uses post-quantum cryptography to protect against future quantum computer attacks.

### Features

- ✅ ML-KEM-768 (NIST FIPS 203) key exchange
- ✅ AES-256-GCM authenticated encryption
- 🚧 TUN interface for IP packet tunneling
- 🚧 Performance benchmarking

## Requirements

- Ubuntu 22.04 or similar Linux distribution
- liboqs 0.8.0+
- OpenSSL 3.0+
- GCC 11+

## Installation
```bash
# Clone repository
git clone <your-repo-url>
cd pqvpn

# Build
make all

# Run tests
make test
```

## Project Structure
```
pqvpn/
├── src/
│   ├── common/         # Shared utilities and crypto
│   ├── vpn/           # VPN implementation
│   ├── chat/          # Original chat prototype
│   └── tests/         # Test programs
├── bin/               # Compiled binaries
├── docs/              # Documentation
└── benchmarks/        # Performance tests
```

## Development Timeline

- Week 1-2: Foundation & Learning ✅
- Week 3-4: Basic VPN Implementation 🚧
- Week 5-6: Features & Stability
- Week 7-8: Benchmarking & Analysis
- Week 9-10: Documentation & Thesis

## Author

[Your Name] - MSc Computer Science  
[Your University]  
[Year]

## License

Educational/Research Project

