#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
RUST_TEST_THREADS=1 cargo test --locked --all-targets
node --check web/app.js
node scripts/test_web_editor.cjs web/app.js
node scripts/test_web_http2.cjs web/app.js
node scripts/test_web_mptcp.cjs web/app.js
node scripts/test_web_smtp.cjs web/app.js
node scripts/test_web_views.cjs web/index.html web/app.js
python3 -m py_compile scripts/*.py
python3 -m py_compile scripts/deployment/*.py scripts/tests/*.py
# Deployment tests exercise distributable artifacts. Linux debug binaries can
# exceed the signed-bundle size limit even though the release binary is small.
if [ -z "${RELAY_TEST_BINARY:-}" ]; then
    cargo build --locked --release --bin relay
    RELAY_TEST_BINARY="${CARGO_TARGET_DIR:-target}/release/relay"
    export RELAY_TEST_BINARY
fi
python3 -m unittest discover -s scripts/tests -p 'test_*.py' -v
