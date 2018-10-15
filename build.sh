#!/bin/bash
BUILD_FOLDER=build
VERSION="1.0"


bin_dep() {
    BIN=$1
    which $BIN > /dev/null || { echo "@ Dependency $BIN not found !"; exit 1; }
}

host_dep() {
    HOST=$1
    ping -c 1 $HOST > /dev/null || { echo "@ Virtual machine host $HOST not visible !"; exit 1; }
}

create_exe_archive() {
    bin_dep 'zip'

    OUTPUT=$1

    echo "@ Creating archive $OUTPUT ..."
    zip -j "$OUTPUT" subfinder.exe ../README.md ../LICENSE > /dev/null
    rm -rf subfinder subfinder.exe
}

create_archive() {
    bin_dep 'zip'

    OUTPUT=$1

    echo "@ Creating archive $OUTPUT ..."
    zip -j "$OUTPUT" subfinder ../README.md ../LICENSE.md > /dev/null
    rm -rf subfinder subfinder.exe
}

build_linux_amd64() {
    echo "@ Building linux/amd64 ..."
    go build -o subfinder ..
}

build_linux_arm7_static() {
    OLD=$(pwd)

    echo "@ Building linux/arm7 ..."
    cd "$OLD"
    env CC=arm-linux-gnueabi-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm GOARM=7 CGO_LDFLAGS="$CROSS_LIB" go build -o subfinder ..
}

build_linux_arm7hf_static() {
    OLD=$(pwd)

    echo "@ Building linux/arm7hf ..."
    cd "$OLD"
    env CC=arm-linux-gnueabihf-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm GOARM=7 CGO_LDFLAGS="$CROSS_LIB" go build -o subfinder ..
}

build_linux_mips_static() {
    OLD=$(pwd)

    echo "@ Building linux/mips ..."
    cd "$OLD"
    env CC=mips-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=mips CGO_LDFLAGS="$CROSS_LIB" go build -o subfinder ..
}

build_linux_mipsle_static() {
    OLD=$(pwd)

    echo "@ Building linux/mipsle ..."
    cd "$OLD"
    env CC=mipsel-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=mipsle CGO_LDFLAGS="$CROSS_LIB" go build -o subfinder ..
}

build_linux_mips64_static() {
    OLD=$(pwd)

    echo "@ Building linux/mips64 ..."
    cd "$OLD"
    env CC=mips64-linux-gnuabi64-gcc CGO_ENABLED=1 GOOS=linux GOARCH=mips64 CGO_LDFLAGS="$CROSS_LIB" go build -o subfinder ..
}

build_linux_mips64le_static() {
    OLD=$(pwd)

    echo "@ Building linux/mips64le ..."
    cd "$OLD"
    env CC=mips64el-linux-gnuabi64-gcc CGO_ENABLED=1 GOOS=linux GOARCH=mips64le CGO_LDFLAGS="$CROSS_LIB" go build -o subfinder ..
}

build_macos_amd64() {
    host_dep 'osxvm'

    DIR=/root/go/src/github.com/Ice3man543/subfinder

    echo "@ Updating repo on MacOS VM ..."
    ssh osxvm "cd $DIR && rm -rf '$OUTPUT' && git pull" > /dev/null

    echo "@ Building darwin/amd64 ..."
    ssh osxvm "export GOPATH=/Users/evilsocket/gocode && cd '$DIR' && PATH=$PATH:/usr/local/bin && go get ./... && go build -o subfinder ." > /dev/null

    scp -C osxvm:$DIR/subfinder . > /dev/null
}

build_windows_amd64() {
    host_dep 'winvm'

    DIR=c:/Users/codingo/gopath/src/github.com/subfinder/subfinder

    echo "@ Updating repo on Windows VM ..."
    ssh winvm "cd $DIR && git pull && go get ./..." > /dev/null

    echo "@ Building windows/amd64 ..."
    ssh winvm "cd $DIR && go build -o subfinder.exe ." > /dev/null

    scp -C winvm:$DIR/subfinder.exe . > /dev/null
}

build_android_arm() {
    host_dep 'shield'

    DIR=/data/data/com.termux/files/home/go/src/github.com/subfinder/subfinder

    echo "@ Updating repo on Android host ..."
    ssh -p 8022 root@shield "cd "$DIR" && rm -rf subfinder* && git pull && go get ./..."

    echo "@ Building android/arm ..."
    ssh -p 8022 root@shield "cd $DIR && go build -o subfinder ."

    echo "@ Downloading subfinder ..."
    scp -C -P 8022 root@shield:$DIR/subfinder . 
}

rm -rf $BUILD_FOLDER
mkdir $BUILD_FOLDER
cd $BUILD_FOLDER


build_linux_amd64 && create_archive subfinder_linux_amd64_$VERSION.zip
#build_macos_amd64 && create_archive subfinder_macos_amd64_$VERSION.zip
#build_android_arm && create_archive subfinder_android_arm_$VERSION.zip
#build_windows_amd64 && create_exe_archive subfinder_windows_amd64_$VERSION.zip
build_linux_arm7_static && create_archive subfinder_linux_arm7_$VERSION.zip
# build_linux_arm7hf_static && create_archive subfinder_linux_arm7hf_$VERSION.zip
build_linux_mips_static && create_archive subfinder_linux_mips_$VERSION.zip
build_linux_mipsle_static && create_archive subfinder_linux_mipsle_$VERSION.zip
build_linux_mips64_static && create_archive subfinder_linux_mips64_$VERSION.zip
build_linux_mips64le_static && create_archive subfinder_linux_mips64le_$VERSION.zip
sha256sum * > checksums.txt

echo
echo
du -sh *

cd --
