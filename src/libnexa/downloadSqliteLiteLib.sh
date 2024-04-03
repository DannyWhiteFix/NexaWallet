#!/bin/bash

version=3430000
echo "Retreiving boost $version..."

set -eu

dir_name=sqlite-amalgamation-${version}
archive=sqlite-amalgamation-${version}.zip
if [ ! -f "$archive" ]; then
    wget -O $archive "https://www.sqlite.org/2023/sqlite-amalgamation-$version.zip"
else
  echo "Archive $archive already downloaded"
fi

echo "bb5849ae4d7129c09d20596379a0b3f7b1ac59cf9998eba5ef283ea9b6c000a5 sqlite-amalgamation-3430000.zip" | sha256sum --check || { echo "sha256sum of sqlite3 failed"; exit 1; }

echo "Extracting..."
if [ ! -d "$dir_name" ]; then
  unzip $archive
else
  echo "Archive $archive already unpacked into $dir_name"
fi

if [ -d sqlite ]; then
    rm -rf sqlite
fi
mv $dir_name sqlite

echo "Done!"
