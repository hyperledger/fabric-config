#!/bin/bash

# Copyright the Hyperledger Fabric contributors. All rights reserved.
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

go_files=$(find . -type f -name '*.go'| grep -v "/vendor/") # filter out vendor

## Formatting
echo "running gofmt..."
gofmt_output="$(gofmt -l -s $go_files)"
if [ -n "$gofmt_output" ]; then
    echo "The following files contain gofmt errors:"
    echo "$gofmt_output"
    echo "Please run 'gofmt -l -s -w' for these files."
    exit 1
fi

## Import management
echo "running goimports..."
goimports_output="$(goimports -l  $go_files)"
if [ -n "$goimports_output" ]; then
    echo "The following files contain goimport errors:"
    echo "$goimports_output"
    echo "Please run 'goimports -l -w' for these files."
    exit 1
fi

## go vet
echo "running go vet..."
go vet ./...

## golint
echo "running golint..."
golint -set_exit_status $(go list ./... | grep -v "/vendor/" | grep -v "protolator")
# TODO also lint protolator

## Protobuf decoration
# TODO verify protolator decorates all config protobuf messages
