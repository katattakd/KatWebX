set -ex

main() {
	cross build --target $TARGET --release

	if [ ! -z $DISABLE_TESTS ]; then
		return
	fi

	cross test --target $TARGET --release

	# Clippy doesn't currently work with cross-compiling: https://github.com/rust-embedded/cross/issues/176
	if [ $TARGET == 'x86_64-unknown-linux-musl' ]; then
		rustup component add clippy-preview
		cross clippy --target $TARGET --release
	fi
}

if [ -z $TRAVIS_TAG ]; then
	main
fi
