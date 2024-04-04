#!/bin/bash

version=3450200
echo "Retrieving SQlite $version..."

set -eu

dir_name=sqlite-amalgamation-${version}
archive=sqlite-amalgamation-${version}.zip
if [ ! -f "$archive" ]; then
    curl -L "https://www.sqlite.org/2024/sqlite-amalgamation-$version.zip" -o $archive
    # wget -O $archive "https://www.sqlite.org/2023/sqlite-amalgamation-$version.zip"
else
  echo "Archive $archive already downloaded"
fi

echo "65230414820d43a6d1445d1d98cfe57e8eb9f7ac0d6a96ad6932e0647cce51db sqlite-amalgamation-3450200.zip" | sha256sum --check || { echo "sha256sum of sqlite3 failed"; exit 1; }

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
