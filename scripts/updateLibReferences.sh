#!/usr/bin/env bash


sedi=(-i)
case "$(uname)" in
  # For macOS, use two parameters
  Darwin*) sedi=(-i "" -e)
esac

#for i in *; do
#    if [ "${i}" != "${i%.${EXT}}" ];then
#    fi
for file in $(find $1 -name "build.gradle"); do
	sed "${sedi[@]}" "s/project(':fido')/\"com.yubico.yubikit:fido:\$fidoVersion\"/g" $file
	sed "${sedi[@]}" "s/project(':yubikit')/\"com.yubico.yubikit:yubikit:\$yubikitVersion\"/g" $file
	sed "${sedi[@]}" "s/project(':oath')/\"com.yubico.yubikit:oath:\$oathVersion\"/g" $file
	sed "${sedi[@]}" "s/project(':otp')/\"com.yubico.yubikit:otp:\$otpVersion\"/g" $file
	sed "${sedi[@]}" "s/project(':management')/\"com.yubico.yubikit:mgmt:\$mgmtVersion\"/g" $file

    echo "sample sed ${sedi[@]} \"s/project(':fido')/\"com.yubico.yubikit:yubikit:\yubikit\"/g\" $file"
    cat $file
done