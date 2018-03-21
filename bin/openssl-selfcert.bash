#!/bin/bash
##
## OpenSSL: Create a self-signed certificate with X.509 extensions
## Copyright (c) 2015-2018 SATOH Fumiyasu @ OSS Technology Corp., Japan
##
## License: GNU General Public License version 3
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
set -o pipefail
umask 0077

run() {
  echo "$*" 1>&2
  "$@"
}

## ======================================================================

rsa_bits="4096"
sha_bits="384"
crt_days="3650"

cn="$1"; shift

## ======================================================================

altnames=()
nameconstraints=()

## CN should be in subjectAltNames too (RFC 6125)
for altname in "$cn" "$@"; do
  altname_type=""
  if [[ $altname =~ ^[0-9.]*$ ]]; then
    altname_type="IP"
    altname_nodes=(${altname//./ })
    if [[ ${#altname_nodes[@]} != 4 ]]; then
      altname_type=""
    else
      for altname_node in "${altname_nodes[@]}"; do
	if [[ $altname_node -gt 255 ]]; then
	  altname_type=""
	  break
	fi
      done
    fi
  fi

  altname="${altname_type:-DNS} $altname"
  altnames+=("$altname")

  nameconstraint="permitted;$altname"
  if [[ $altname_type == "IP" ]]; then
    nameconstraint+="/255.255.255.255"
  fi
  nameconstraints+=("$nameconstraint")
done

## ----------------------------------------------------------------------

(
  echo "## openssl.cnf"
  echo "[req]"
  echo "distinguished_name = req_distinguished_name"
  echo "x509_extensions = v3_ca"
  echo "[req_distinguished_name]"
  echo "[v3_ca]"
  echo "subjectKeyIdentifier = hash"
  echo "authorityKeyIdentifier = keyid:always,issuer"
  echo "basicConstraints = CA:true"

  if [[ ${#altnames[@]} -gt 0 ]]; then
    echo "[v3_ca]"
    echo "subjectAltName = @altnames"
    echo '[altnames]'
    for altname in "${altnames[@]}"; do
      echo "$altname"
    done |awk '{ print $1"."NR" = "$2 }'
  fi

  echo "## NOTE: Following name constraints does NOT affect by OpenSSL and GnuTLS."
  echo "[v3_ca]"
  echo "nameConstraints = critical, @nameconstraints"
  echo "[nameconstraints_dirname]"
  echo "CN = $cn"
  echo "[nameconstraints]"
  echo "permitted;dirName = nameconstraints_dirname"
  echo "## NOTE: Following name constraints does NOT affect by OpenSSL, GnuTLS and NSS."
  echo "permitted;DNS.0 = $cn"
  if [[ ${#nameconstraints[@]} -gt 0 ]]; then
    for nameconstraint in "${nameconstraints[@]}"; do
      echo "$nameconstraint"
    done |awk '{ print $1"."NR" = "$2 }'
  fi
) \
|tee -a /dev/stderr \
|run openssl req \
  -batch \
  -config /dev/stdin \
  -new \
  -x509 \
  -subj "/CN=$cn" \
  -newkey "rsa:$rsa_bits" \
  -sha"$sha_bits" \
  -days "$crt_days" \
  -out "$cn.crt" \
  -keyout "$cn.key" \
  -nodes \
|| exit 1

## ----------------------------------------------------------------------

chmod -w "$cn.crt" "$cn.key" || exit 1
ls -l "$cn.crt" "$cn.key" || exit 1

exit 0

