
# Simple transfer tutorial for Rust ckb-sdk

```bash
git clone https://github.com/TheWaWaR/ckb-sdk-transfer-tutorial.git
cd ckb-sdk-transfer-tutorial

cargo run --release -- gen-key
cargo run --release -- query --address <address>
cargo run --release -- transfer --sender-key <key-hex> --receiver <address> --capacity 200.0
cargo run --release -- query-tx-status --tx-hash <hash>
```
