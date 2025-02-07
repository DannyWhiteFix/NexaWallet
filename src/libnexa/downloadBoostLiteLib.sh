#!/bin/bash
# script modified from: https://gist.github.com/enh/b2dc8e2cbbce7fffffde2135271b10fd

version=1.87.0
echo "Retrieving boost $version..."

set -eu

dir_name=boost_$(sed 's#\.#_#g' <<< $version)
archive=${dir_name}.tar.bz2
if [ ! -f "$archive" ]; then
    curl -L "https://archives.boost.io/release/$version/source/$archive" -o $archive
    # wget -O $archive "https://boostorg.jfrog.io/artifactory/main/release/$version/source/$archive" 
else
  echo "Archive $archive already downloaded"
fi

if [[ "$(uname -s)" == "Darwin" ]]; then
    echo "skipping checksum check on macos"
else
    echo "af57be25cb4c4f4b413ed692fe378affb4352ea50fbe294a11ef548f4d527d89  boost_1_87_0.tar.bz2" | sha256sum --check || { echo "sha256sum of boost failed"; exit 1; }
fi


echo "Extracting..."
if [ ! -d "$dir_name" ]; then
  tar xf $archive
else
  echo "Archive $archive already unpacked into $dir_name"
fi

# Redo the symlink because it might point to the wrong boost version
#if [ -L boost ]; then
#  rm boost
#fi
#ln -s $dir_name boost
if [ -d boost ]; then
    rm -rf boost
fi
mv $dir_name boost

echo "Done!"
