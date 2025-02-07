#!/bin/bash

version=3480000
echo "Retrieving SQlite $version..."

set -eu

dir_name=sqlite-amalgamation-${version}
archive=sqlite-amalgamation-${version}.zip
if [ ! -f "$archive" ]; then
    curl -L "https://www.sqlite.org/2025/sqlite-amalgamation-$version.zip" -o $archive
    # wget -O $archive "https://www.sqlite.org/2023/sqlite-amalgamation-$version.zip"
else
  echo "Archive $archive already downloaded"
fi

if [[ "$(uname -s)" == "Darwin" ]]; then
    echo "skipping checksum check on macos"
else
    echo "d9a15a42db7c78f88fe3d3c5945acce2f4bfe9e4da9f685cd19f6ea1d40aa884 sqlite-amalgamation-3480000.zip" | sha256sum --check || { echo "sha256sum of sqlite3 failed"; exit 1; }
fi

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
