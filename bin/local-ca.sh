#!/bin/sh
CA_ARGV0="$0"
CA_DIR="/usr/local/etc/ca"
export CA_ARGV0 CA_DIR
exec "/usr/local/bin/openssl-ca" "$@"
