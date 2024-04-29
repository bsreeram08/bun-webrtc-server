#!/bin/bash

rm -rf ./build/stun-server
bun build packages/stun-server/main.ts --minify --target node --outdir ./build/stun-server
cp packages/stun-server/package.json ./build/stun-server/package.json
cp ./DockerFile.node ./build/stun-server/DockerFile
