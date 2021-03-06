#
# Copyright 2020 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

# shellcheck shell=bash

check_rust() {
  if ! which rustup > /dev/null && [[ -d ~/.cargo/bin ]]; then
    # Try to find rustup in its default per-user install location.
    # This will be important when running from inside Xcode,
    # which does not run in a login shell context.
    PATH=~/.cargo/bin:$PATH
  fi

  if ! which rustup > /dev/null; then
    if ! which cargo > /dev/null; then
      echo 'error: cargo not found in PATH; do you have Rust installed?' >&2
      echo 'note: we recommend installing Rust via rustup from https://rustup.rs/' >&2
      exit 1
    fi

    echo 'warning: rustup not found in PATH; using cargo at' "$(which cargo)" >&2
    echo 'note: this project uses Rust toolchain' "'$(cat ./rust-toolchain)'" >&2
    return
  fi

  if [[ -n "${CARGO_BUILD_TARGET:-}" ]] && ! (rustup target list --installed | grep -q "${CARGO_BUILD_TARGET:-}"); then
    echo "error: Rust target ${CARGO_BUILD_TARGET} not installed" >&2
    echo 'note: get it by running' >&2
    printf "\n\t%s\n\n" "rustup +${RUSTUP_TOOLCHAIN:-$(cat ./rust-toolchain)} target add ${CARGO_BUILD_TARGET}" >&2
    exit 1
  fi
}

echo_then_run() {
  echo "$@"
  "$@"
}
