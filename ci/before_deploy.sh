set -ex

main() {
	local src=$(pwd) \
      	stage=

	case $TRAVIS_OS_NAME in
		linux)
			stage=$(mktemp -d)
			;;
		osx)
            	stage=$(mktemp -d -t tmp)
            	;;
	esac

	test -f Cargo.lock || cargo generate-lockfile

	cp target/$TARGET/release/katwebx $stage/
	cp -r html $stage/
	cp -r src $stage/
	cp -r ssl $stage/

	cd $stage
	tar czf $src/$CRATE_NAME-$TRAVIS_TAG-$TARGET.tar.gz *
	cd $src

	rm -rf $stage
}

main
