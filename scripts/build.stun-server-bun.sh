#!/bin/bash

rm -rf ./build/stun-server
bun build packages/stun-server/main.ts --minify --target bun --outdir ./build/stun-server
cp packages/stun-server/package.json ./build/stun-server/package.json
cp ./DockerFile.bun ./build/stun-server/DockerFile
cp ./bun.lockb ./build/stun-server/bun.lockb
