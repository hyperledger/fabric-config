#!/bin/bash

# Copyright the Hyperledger Fabric contributors. All rights reserved.
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

cd "$(dirname "$0")/tools"
export GO111MODULE=on
go install -tags tools golang.org/x/lint/golint
go install -tags tools golang.org/x/tools/cmd/goimports
go install -tags tools mvdan.cc/gofumpt
