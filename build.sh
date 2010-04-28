#!/bin/sh

if [ ! -d "release" ]; then
	mkdir "release"
fi

YUI="gij -jar tools/yuicompressor-2.4.2.jar --type js"

# Compress server and client code
echo '<!doctype html><script type="text/javascript">' > release/server.html
$YUI src/server.js >> release/server.html
echo '</script>' >> release/server.html

$YUI src/xauth.js > release/xauth.js

# Copy rest of static files
cp -R src/info release
cp -R src/spec release
cp src/index.html release

find ./release -name '.svn' -exec rm -r -f {} \;
find ./release -name '.git' -exec rm -r -f {} \;
