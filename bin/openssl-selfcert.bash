#!/bin/bash
##
## OpenSSL: Create a self-signed certificate with X.509 extensions (subjectAltName, nameConstraints)
## Copyright (c) 2015 SATOH Fumiyasu @ OSS Technology Corp., Japan
##
## License: GNU General Public License version 3
##
## References:
##   * x509v3_config(5)
##   * RFC 5280
##     Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile
##     https://tools.ietf.org/html/rfc5280
##   * Code Kills : Adventures in X.509: The Utterly Ignored nameConstraints
##     http://blog.codekills.net/2012/04/08/adventures-in-x509-the-utterly-ignored-nameconstraints/
##

set -u
set -o pipefail
umask 0077

run() {
  echo "$*" 1>&2
  "$@"
}

## ======================================================================

rsa_bits="2048"
sha_bits="256"
crt_days="3650"

cn="$1"; shift

## ======================================================================

altnames=()
nameconstraints=()
for altname in "$@"; do
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

  if [[ ${#altnames[@]} > 0 ]]; then
    echo "[v3_ca]"
    echo "subjectAltName = @altnames"
    echo '[altnames]'
    for altname in "${altnames[@]}"; do
      echo "$altname"
    done |awk '{ print $1"."NR" = "$2 }'
  fi

  echo "[v3_ca]"
  echo "nameConstraints = critical, @nameconstraints"
  echo "[nameconstraints_dirname]"
  echo "CN = $cn"
  echo "[nameconstraints]"
  echo "permitted;dirName = nameconstraints_dirname"
  echo "## NOTE: Following name constraints does NOT affect by OpenSSL and GnuTLS."
  echo "## See:  http://blog.codekills.net/2012/04/08/adventures-in-x509-the-utterly-ignored-nameconstraints/"
  echo "permitted;DNS.0 = $cn"
  if [[ ${#nameconstraints[@]} > 0 ]]; then
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
