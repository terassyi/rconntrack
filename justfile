
default:
	@just --list

build:
	cargo build

lint:
	cargo clippy

format:
	cargo clippy --fix

# Run tests, optionally for a specific package
test package='':
  #!/usr/bin/env bash
  if [ -z "{{package}}" ]; then
    echo "Running tests for all packages"
    cargo test
  else
    echo "Running tests for package: {{package}}"
    cargo test --package {{package}}
  fi

privileged-test package='':
  #!/usr/bin/env bash
  files=$(cargo test --no-run 2>&1 | grep -o 'target/debug/deps/[^)]*' | tr ' ' '\n')

  echo "Test binaries found:"
  echo "$files"

  if [ -z "$files" ]; then
    echo "No test binaries found. Ensure tests are properly compiled." >&2
    exit 1
  fi

  if [ -z "{{package}}" ]; then
    echo "Running tests for all packages with privileged permissions."
    for f in $files; do
      echo "Running: sudo ./$f --ignored"
      sudo ./$f --ignored
    done
  else
    echo "Running tests for package: {{package}}"
    for f in $files; do
      if echo $f | grep -q "target/debug/deps/{{package}}"; then
        echo "Running: sudo ./$file --ignored"
        sudo ./$f --ignored
      fi
    done
  fi

clean:
  cargo clean
