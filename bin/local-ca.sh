#!/bin/sh
CA_ARGV0="$0"
CA_DIR="/usr/local/etc/ca"
export CA_ARGV0 CA_DIR
if [ -x "${0%/*}/openssl-ca" ]; then
  exec "${0%/*}/openssl-ca" "$@"
else
  exec "${0%/*}/openssl-ca.bash" "$@"
fi
