
default:
	@just --list

build:
	cargo build

lint:
	cargo clippy

format:
	cargo clippy --fix

