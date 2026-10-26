#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
node --check web/app.js
node scripts/test_web_editor.cjs web/app.js
node scripts/test_web_views.cjs web/index.html web/app.js
python3 -m py_compile scripts/*.py
python3 -m py_compile scripts/deployment/*.py scripts/tests/*.py
python3 -m unittest discover -s scripts/tests -p 'test_*.py' -v
