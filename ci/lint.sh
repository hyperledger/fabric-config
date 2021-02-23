#!/bin/bash

# Copyright the Hyperledger Fabric contributors. All rights reserved.
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

go_files=()
while IFS=$'\n' read -r filename; do
  go_files+=("$filename")
done < <(find . -type f -name '*.go'| grep -v '.pb.go$')

## Import management
echo "running goimports..."
goimports_output="$(goimports -l  "${go_files[@]}")"
if [ -n "$goimports_output" ]; then
    echo "The following files contain goimport errors:"
    echo "$goimports_output"
    echo "Please run 'goimports -l -w' for these files."
    exit 1
fi

## Formatting
echo "running gofumpt..."
gofumpt_output="$(gofumpt -l -s "${go_files[@]}")"
if [ -n "$gofumpt_output" ]; then
    echo "The following files contain gofumpt errors:"
    echo "$gofumpt_output"
    echo "Please run 'gofumpt -s -w' for these files."
    exit 1
fi

## go vet
echo "running go vet..."
go vet ./...

## golint
# TODO also lint protolator
echo "running golint..."
go list ./... | grep -v 'protolator' | xargs -d '\n' golint -set_exit_status

## Protobuf decoration
# TODO verify protolator decorates all config protobuf messages
