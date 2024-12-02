# Changelog

All notable changes to iroh will be documented in this file.

## [0.2.0](https://github.com/n0-computer/iroh/compare/v0.28.1..0.2.0) - 2024-12-02

### ⛰️  Features

- *(iroh-net)* Allow the underlying UdpSockets to be rebound ([#2946](https://github.com/n0-computer/iroh/issues/2946)) - ([9c9c954](https://github.com/n0-computer/iroh/commit/9c9c9549ef508d81f49b22e583604a5542983ac0))

### 🐛 Bug Fixes

- *(netwatch)* BSD rebind socket on errors ([#2913](https://github.com/n0-computer/iroh/issues/2913)) - ([b9d22b8](https://github.com/n0-computer/iroh/commit/b9d22b872c592202f1a8380e5b2b9ef99b9ab3a0))
- *(netwatch)* Hold on to netmon sender reference in android ([#2923](https://github.com/n0-computer/iroh/issues/2923)) - ([6109abc](https://github.com/n0-computer/iroh/commit/6109abc16ecfd6bc39cab323dd6fa86718b72258))

### 🚜 Refactor

- Cleanup internal dependency references ([#2976](https://github.com/n0-computer/iroh/issues/2976)) - ([a0698e9](https://github.com/n0-computer/iroh/commit/a0698e9aa4030f2dd89ce5a95f52a36e03e7d27b))
- Extract iroh-metrics into its own repo ([#2989](https://github.com/n0-computer/iroh/issues/2989)) - ([245a22c](https://github.com/n0-computer/iroh/commit/245a22c3d754cc1ee21de56838eb6ba0f6a8b684))

### 📚 Documentation

- Format code in doc comments ([#2895](https://github.com/n0-computer/iroh/issues/2895)) - ([b6dd868](https://github.com/n0-computer/iroh/commit/b6dd868cd44ebfb0a018aeaccc54b92515ba21ac))

### ⚙️ Miscellaneous Tasks

- Prune some deps ([#2932](https://github.com/n0-computer/iroh/issues/2932)) - ([a8d70ee](https://github.com/n0-computer/iroh/commit/a8d70eea5e148538fa820a15146fc9d8bb6f9c75))
- Add relevant files - ([8eae2f8](https://github.com/n0-computer/iroh/commit/8eae2f8f8f56596e8c106f674d1dbb1a0657729d))
- Cleanup workspace setup - ([43a6d87](https://github.com/n0-computer/iroh/commit/43a6d8708e23e01af13d823c380480130754d84f))

## [0.28.1] - 2024-11-04

### 🐛 Bug Fixes

- *(portmapper)* Enforce timeouts for upnp ([#2877](https://github.com/n0-computer/iroh/issues/2877)) - ([6f36964](https://github.com/n0-computer/iroh/commit/6f369649e06e065f9debb32abc1c11ec6e5045ca))

### 🚜 Refactor

- *(iroh-net)* Portmapper and network monitor are crates ([#2855](https://github.com/n0-computer/iroh/issues/2855)) - ([585ed7b](https://github.com/n0-computer/iroh/commit/585ed7bff79254cd502719ca86a66d365fbea196))

### 🧪 Testing

- *(netwatch)* Simplify dev-deps - ([22d46e4](https://github.com/n0-computer/iroh/commit/22d46e4a11bfb3ccbba6c7b54b484efd50c1d1a0))


