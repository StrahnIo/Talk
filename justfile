# Talk daemon dev tasks
set shell := ["bash", "-uc"]

default: build

# Build the whole workspace
build:
    cargo build --workspace

# Run all tests
test:
    cargo nextest run --workspace

# Run lint + format checks
lint:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings

# Run the daemon with the example config
run:
    cargo run -p talkd -- --config config.example.toml

# Format everything (non-check)
fmt:
    cargo fmt --all
