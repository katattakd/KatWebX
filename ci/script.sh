set -ex

main() {
	if [ $TARGET == 'x86_64-unknown-linux-musl' ]; then
		rustup component add clippy-preview
		cargo clippy --target $TARGET --release
	fi

	cross build --target $TARGET --release

	if [ ! -z $DISABLE_TESTS ]; then
		return
	fi

	cross test --target $TARGET --release

	# Clippy doesn't currently work with cross-compiling: https://github.com/rust-embedded/cross/issues/176
	#rustup component add clippy-preview
	#cross clippy --target $TARGET --release
}

if [ -z $TRAVIS_TAG ]; then
	main
fi
