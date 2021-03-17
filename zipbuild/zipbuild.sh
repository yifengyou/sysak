#!/bin/bash


build_zip() {
ZIP_BUILD_ROOT=BUILD
mkdir -p $ZIP_BUILD_ROOT
cat > $ZIP_BUILD_ROOT/config.json <<EOF
{
  "name": "ecs_tools_sysak",
  "arch": "x64",
  "osType": "linux"
  "runPath": "sysak"
  "timeout": "300"
  "publisher": "aliyun",
  "version": $ZIP_VERSION
}

EOF

SOURCE_DIR=`realpath $BASE/../`
BUILD_DIR=`realpath $BASE/../out`

for version in $LINUX_VERSION; do
	make -C $SOURCE_DIR KERNEL_VERSION=$version clean_middle
	make -C $SOURCE_DIR KERNEL_VERSION=$version -j
done

/bin/cp -rf $BUILD_DIR/.sysak_compoents $ZIP_BUILD_ROOT/
/bin/cp -rf $BUILD_DIR/sysak $ZIP_BUILD_ROOT/
cd $ZIP_BUILD_ROOT/
zip -r -q -o sysak-$ZIP_VERSION.zip .[!.]* *
}

#ALL_SYS_VERSIONS="4.19.91-008.ali4000.alios7.x86_64 \
#		 3.10.0-327.ali2016.alios7.x86_64 \
#		 3.10.0-327.ali2014.alios7.x86_64 \
ALL_SYS_VERSIONS="4.19.91-19.1.al7.x86_64 \
		 3.10.0-1160.11.1.el7.x86_64 \
		 3.10.0-1160.el7.x86_64"

main() {
	export BASE=`pwd`
	export ZIP_VERSION=$1
	local SYSTEM_SUPPORT=$2

	if [ $SYSTEM_SUPPORT = "all" ]; then
		export LINUX_VERSION=$ALL_SYS_VERSIONS
	else
		export LINUX_VERSION=$SYSTEM_SUPPORT
	fi

	build_zip
}

main 0.1 all
