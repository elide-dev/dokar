# Changelog

## [0.3.1](https://github.com/elide-dev/bemo/compare/v0.3.0...v0.3.1) (2026-10-10)


### Bug Fixes

* **h2:** force-reset freed streams stalled by withheld flow-control credit ([#31](https://github.com/elide-dev/bemo/issues/31)) ([9092110](https://github.com/elide-dev/bemo/commit/9092110b2fbb83c5ea269d3aae1439868053865f))
* **release:** forward secrets through reusable Central publisher ([0eca65f](https://github.com/elide-dev/bemo/commit/0eca65f8be68d18b6e185678e9d6b32b792d7e60))
* **serving:** drop stale shard.connections entry on individual socket close ([#30](https://github.com/elide-dev/bemo/issues/30)) ([f5176b3](https://github.com/elide-dev/bemo/commit/f5176b3b821e325890a00516b619ce3993a64da3))


### Performance Improvements

* reuse initialized TLS output and retain benchmark symbols ([#17](https://github.com/elide-dev/bemo/issues/17)) ([a45d50b](https://github.com/elide-dev/bemo/commit/a45d50bf7548eed8798ece0f1023b65cd50fd751))
* stop exact-capacity pool scans at recent matches ([#18](https://github.com/elide-dev/bemo/issues/18)) ([16805b3](https://github.com/elide-dev/bemo/commit/16805b3bbc01d1ae6bd5d79376a929392a27c483))

## [0.3.0](https://github.com/elide-dev/bemo/compare/v0.2.0...v0.3.0) (2026-10-08)


### Features

* add framework samples and matched-level benchmark evidence ([571da0e](https://github.com/elide-dev/bemo/commit/571da0e40ed638ddf044d4c95da7baed467ee71f))
* add Ktor examples and Maven Central publishing tooling ([be68a14](https://github.com/elide-dev/bemo/commit/be68a1420d6e06092316ddb6ab6dc0e1a68647e1))
* complete Maven Central release publishing workflow ([0262b07](https://github.com/elide-dev/bemo/commit/0262b077742d1efa3019eeba37a73f1818011379))
* **release:** publish verified Release Please releases to Central ([1e1c30f](https://github.com/elide-dev/bemo/commit/1e1c30f2ee727105420b61cbe706d16de8bd19c6))


### Bug Fixes

* require native Netty and tcnative benchmark baselines ([1d3ca12](https://github.com/elide-dev/bemo/commit/1d3ca121bd44d456cdbdadda5a2d46e5328d8517))


### Performance Improvements

* **abi:** improve handle fingerprints and shared lease bookkeeping ([#11](https://github.com/elide-dev/bemo/issues/11)) ([a0537b4](https://github.com/elide-dev/bemo/commit/a0537b44c9d17ac312e18adb08500cd1069913ed))
* batch TLS output and borrow vectored Netty writes ([#15](https://github.com/elide-dev/bemo/issues/15)) ([03ef4a7](https://github.com/elide-dev/bemo/commit/03ef4a7d768b38f1459c589c7ee76baa27013b40))
* **buffer:** reuse idle allocation storage and descriptors ([#9](https://github.com/elide-dev/bemo/issues/9)) ([dec2571](https://github.com/elide-dev/bemo/commit/dec2571b8a28fee7c781c52e35f2d9523ff07b89))
* **gzip:** integrate native zlib-rs with pinned teardown fix ([75c4300](https://github.com/elide-dev/bemo/commit/75c4300168f01a93831816694dd0a5d1e06f3bac))
* **gzip:** select qualified level 1 for native HTTP compression ([639a551](https://github.com/elide-dev/bemo/commit/639a55168df8a6fae94c7a35dba2a17aaee693bb))
* **http:** encode response heads directly into native storage ([8b45daf](https://github.com/elide-dev/bemo/commit/8b45daf04f6912346fe922e23262747c73fc5b4f))
* **http:** fill TLS records across retained response parts ([24dccce](https://github.com/elide-dev/bemo/commit/24dccce6300593af3ed7cf6bf9c0a351c4157a9f))
* **http:** retain immutable response bodies without copying ([#8](https://github.com/elide-dev/bemo/issues/8)) ([df611db](https://github.com/elide-dev/bemo/commit/df611db2bffbca53b44ac96aa242202700dd7645))
* **http:** retain validated line progress across fragmented heads ([#10](https://github.com/elide-dev/bemo/issues/10)) ([d112e24](https://github.com/elide-dev/bemo/commit/d112e2448dfe10d197fd35b00009a72bde2a5fb3))
* refresh benchmarks against native Netty and tcnative ([5062d97](https://github.com/elide-dev/bemo/commit/5062d97947b14a33f0296ec241f2ae7df496ba1e))
* reuse dynamic gzip state and compare compression backends ([#7](https://github.com/elide-dev/bemo/issues/7)) ([b38bd5b](https://github.com/elide-dev/bemo/commit/b38bd5bcccc4adee8dd56b39b748413a1745deb4))
* **tls:** stage retained parts only when coalescing saves records ([d42af3c](https://github.com/elide-dev/bemo/commit/d42af3c177eeea6e0ff1a186946d56237a4402c2))

## [0.2.0](https://github.com/elide-dev/bemo/compare/v0.1.0...v0.2.0) (2026-10-06)


### Features

* extract native transport core and preserve Elide C ABI ([8eb55a2](https://github.com/elide-dev/bemo/commit/8eb55a22552e139f881452b971d4ff6fef44569a))
* migrate Netty transport bindings and verify JVM distributions ([d99f693](https://github.com/elide-dev/bemo/commit/d99f6937892ff44177a5c64f358d3b3125138948))
* **publish:** deploy verified Maven artifacts to GitHub Packages ([9573153](https://github.com/elide-dev/bemo/commit/95731539c1ff52bc2aeaec0a788bb7a3a90b409d))
* unify Dokar namespaces and load native libraries from resources ([7aa1b7b](https://github.com/elide-dev/bemo/commit/7aa1b7bb74e89f211c63f148b85e59143ad78c8c))


### Bug Fixes

* address cross-platform transport CI failures ([f6c4627](https://github.com/elide-dev/bemo/commit/f6c46275a470965e589706ca7f8ed8e63aa505ba))
* **bench:** exclude generated Criterion reports from source fingerprints ([30ae12e](https://github.com/elide-dev/bemo/commit/30ae12e27a5b2fc2260c06b648df1a110dc3fbfb))
* **ci:** complete Linux lint coverage and bootstrap benchmark Rust ([4ccfa44](https://github.com/elide-dev/bemo/commit/4ccfa44e57c73f2c2e87d00671d0252cd3774f72))
* **ci:** install Native Image alongside stock benchmark JVM ([bb33992](https://github.com/elide-dev/bemo/commit/bb339926946f41126381dc9d8b877ad86ea77e63))
* omit Unix cancel replacement on Windows ([ad42a64](https://github.com/elide-dev/bemo/commit/ad42a64d02f7e8ab581252936a09e0b95e0bbd72))
* **publish:** resolve classifiers from shared snapshot metadata ([e69a09f](https://github.com/elide-dev/bemo/commit/e69a09f75f57b3b9bce4d8ce1ae660431e392ae3))
* **release:** keep fuzz lockfile version in sync ([3a79435](https://github.com/elide-dev/bemo/commit/3a79435034a6fb3c831b96a6ab6ef9a40242ba23))
* **release:** resolve drafts by ID and reset unpublished version ([#2](https://github.com/elide-dev/bemo/issues/2)) ([c45102c](https://github.com/elide-dev/bemo/commit/c45102ce1f7573041d32b3fa293105ccd8edbaa6))
* **release:** verify immutability without an admin-only settings API ([47eaab6](https://github.com/elide-dev/bemo/commit/47eaab6a5956ed65b51d04915fe10014055b8bdb))
* **test:** authenticate pending TLS close after H2 shutdown ([857eb96](https://github.com/elide-dev/bemo/commit/857eb96a45a97619b1752ecf34c08367965f65a0))
