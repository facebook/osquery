#!/usr/bin/env bash

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

set -e

function fatal() {
  echo "[!] $1"
  exit 1
}

function usage() {
  fatal "Usage: $0 [options] OUTPUT_PKG
    The pkgbuild arguments are:
      [--root PATH] path to local prefix
      [--identifier ID] package identifier
      [--scripts PATH] optional path to package scripts
      [--version VERSION] package version
      [--install-location PATH] relative path to install prefix

    The productbuild arguments are:
      [--distribution XML] path to distribution config
      [--package-path] path to embedded pkgs
      [--resources] path to optional resources
  "
}

function parse_args() {
  while [ "$1" != "" ]; do
    case $1 in
      --root )              shift
                            PKG_ROOT=$1
                            ;;
      --indentifier )       shift
                            PKG_IDENTIFIER=$1
                            ;;
      --scripts )           shift
                            PKG_SCRIPTS=$1
                            ;;
      --version )           shift
                            PKG_VERSION=$1
                            ;;
      --install-location )  shift
                            PKG_INSTALL_LOCATION=$1
                            ;;
      --distribution )      shift
                            PKG_DISTRIBUTION=$1
                            ;;
      --package-path )      shift
                            PKG_PACKAGE_PATH=$1
                            ;;
      --resources )         shift
                            PKG_RESOURCE=$1
                            ;;
    esac
    LAST=$1
    shift
  done

  # Final positional argument.
  PKG_OUTPUT=$LAST

  if [[ -z "$PKG_OUTPUT" ]]; then
    echo "Output package path not found"
    usage
  fi
}

function root_build() {
  pkgbuild \
    --root "$PKG_ROOT" \
    --identifier "$PKG_IDENTIFIER" \
    --scripts "$PKG_SCRIPTS" \
    --version "$PKG_VERSION" \
    --install-location "$PKG_INSTALL_LOCATION" \
    "$PKG_OUTPUT"
}

function distribution_build() {
  # Instead of falling-through to productbuild, move the package.
  # $PKG_PACKAGE_PATH + "osquery-" + $PKG_VERSION + "-osquery.pkg"
  # Move this to $PKG_OUTPUT.
  cp "${PKG_PACKAGE_PATH}/osquery-${PKG_VERSION}-osquery.pkg" "$PKG_OUTPUT"
}

function main() {
  parse_args $@

  # Overwrite the package identifier.
  PKG_IDENTIFIER="io.osquery.agent"

  if [[ ! -z "$PKG_DISTRIBUTION" ]]; then
    distribution_build
  else
    root_build
  fi
}

main $@
