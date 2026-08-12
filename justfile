set positional-arguments

# List targets.
default:
    @just --list

# Install npm dependencies from the lockfile.
install:
    npm ci

# Build dist/cli.cjs.
build:
    npm run build

# Type-check sources and tests.
typecheck:
    npm run typecheck

# Run all project linters
lint: typecheck

# Run the unit tests.
test:
    npm test

# Run the CLI from source, e.g. `just run manifest --help`.
run *args:
    @npm run --silent start -- "$@"

# Evaluate the flake and build the package, tests included.
nix-check:
    nix flake check
