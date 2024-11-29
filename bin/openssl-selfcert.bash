#!/bin/bash
##
## OpenSSL: Create a self-signed certificate with X.509 extensions
##
## SPDX-FileCopyrightText: 2015-2024 SATOH Fumiyasu @ OSSTech Corp., Japan
## SPDX-License-Identifier: GPL-3.0-or-later
##
## WARNING: This software comes with ABSOLUTELY NO WARRANTY
##
## References:
##   * x509v3_config(5)
##   * RFC 5280
##     Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile
##     https://tools.ietf.org/html/rfc5280
##   * Code Kills : Adventures in X.509: The Utterly Ignored nameConstraints
##     http://blog.codekills.net/2012/04/08/adventures-in-x509-the-utterly-ignored-nameconstraints/
##   * Generate self-signed x509 certificates valid for multiple URLs/IPs
##     https://github.com/frntn/x509-san
##

set -u
set -o pipefail || exit $?
umask 0077

run() {
  echo "$*" 1>&2
  "$@"
}

perr() {
  echo "$0: ERROR: $1" 1>&2
}

pdie() {
  perr "$1"
  exit "${2-1}"
}

CA_type_of_value() {
  local value="$1"; shift
  local value_lower="${value,,}"

  if  [[ $value_lower =~ ^[a-z_][a-z_0-9\-]*(\+[a-z_][a-z_0-9\-]*)*:// ]]; then
    echo 'URI'
    return 0
  fi

  if  [[
    $value =~ ^((25[0-5]|(2[0-4]|1{,1}[0-9]){,1}[0-9])\.){3}(25[0-5]|(2[0-4]|1{,1}[0-9]){,1}[0-9])$
    || $value =~ ^([0-9A-Fa-f]{1,4}:){7,7}[0-9A-Fa-f]{1,4}$
    || $value =~ ^([0-9A-Fa-f]{1,4}:){1,7}:$
    || $value =~ ^([0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}$
    || $value =~ ^([0-9A-Fa-f]{1,4}:){1,5}(:[0-9A-Fa-f]{1,4}){1,2}$
    || $value =~ ^([0-9A-Fa-f]{1,4}:){1,4}(:[0-9A-Fa-f]{1,4}){1,3}$
    || $value =~ ^([0-9A-Fa-f]{1,4}:){1,3}(:[0-9A-Fa-f]{1,4}){1,4}$
    || $value =~ ^([0-9A-Fa-f]{1,4}:){1,2}(:[0-9A-Fa-f]{1,4}){1,5}$
    || $value =~ ^[0-9A-Fa-f]{1,4}:((:[0-9A-Fa-f]{1,4}){1,6})$
    || $value =~ ^:((:[0-9A-Fa-f]{1,4}){1,7}|:)$
  ]]; then
    echo 'IP'
    return 0
  fi

  if  [[ $value_lower =~ ^(([a-z0-9][a-z0-9\-]+|[a-z])+\.)*([a-z0-9][a-z0-9\-]+|[a-z])$ ]]; then
    echo 'DNS'
    return 0
  fi

  if  [[ $value_lower =~ ^[^@]+@(([a-z0-9][a-z0-9\-]+|[a-z])+\.)+([a-z0-9][a-z0-9\-]+|[a-z])$ ]]; then
    echo 'email'
    return 0
  fi

  return 1
}

## ======================================================================

rsa_bits="4096"
sha_bits="384"
crt_days="3650"

usage="\
Usage: $0 NAME [ALTERNATIVE NAMES ...]

Examples:
  \$ $0 www.example.jp
  \$ $0 ldap.example.com master.ldap.example.com slave.ldap.example.com
  \$ $0 foo@example.jp
  \$ $0 bar@example.com+UID=bar
"

## ----------------------------------------------------------------------

if  [[ $# -lt 1 ]]; then
  echo -n "$usage"
  exit 1
fi

cn="$1"; shift

## ======================================================================

altnames=()
nameconstraints=()

## All service identity names MUST be in subjectAltNames (RFC 9525)
for altname in "$cn" "$@"; do
  altname_type=$(CA_type_of_value "$altname")
  if [[ -z $altname_type ]]; then
    pdie "Invalid name or unknown type of name: $altname"
  fi

  altnames+=("$altname_type:$altname")

  nameconstraint="permitted;$altname_type:$altname"
  if [[ $altname_type == "IP" ]]; then
    if [[ $altname == *.* ]]; then
      nameconstraint+="/255.255.255.255"
    else
      nameconstraint+="/FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"
    fi
  fi
  nameconstraints+=("$nameconstraint")
done

## ----------------------------------------------------------------------

openssl_req_opts=(
  -addext "basicConstraints=CA:true"
  -addext "authorityKeyIdentifier=keyid:always, issuer"
  -addext "subjectKeyIdentifier=hash"
)

if [[ ${#nameconstraints[@]} -gt 0 ]]; then
  nameconstraints_ext="${nameconstraints[*]}"
  openssl_req_opts+=(-addext "nameConstraints=critical,${nameconstraints_ext// /, }")
fi

if [[ ${#altnames[@]} -gt 0 ]]; then
  altnames_ext="${altnames[*]}"
  openssl_req_opts+=(-addext "subjectAltName=${altnames_ext// /, }")
fi

## ----------------------------------------------------------------------

run openssl req \
  -batch \
  -config /dev/null \
  -new \
  -x509 \
  -subj "/CN=$cn" \
  -multivalue-rdn \
  -newkey "rsa:$rsa_bits" \
  -sha"$sha_bits" \
  -days "$crt_days" \
  -out "$cn.crt" \
  -keyout "$cn.key" \
  -nodes \
  "${openssl_req_opts[@]}" \
|| exit $?

## ----------------------------------------------------------------------

chmod -w "$cn.crt" "$cn.key" || exit $?
ls -l "$cn.crt" "$cn.key" || exit $?

exit 0
