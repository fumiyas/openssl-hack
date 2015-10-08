#!/bin/bash
##
## OpenSSL: Simple CA implementation
##
## Copyright (c) 2015 SATOH Fumiyasu @ OSS Technology Corp., Japan
##
## License: GNU General Public License version 3
##

set -u
set -C

export CA_KEY_BITS="${CA_KEY_BITS:-4096}"
export CA_DIGEST_ALGORITHM="${CA_DIGEST_ALGORITHM:-sha384}"
export CA_CERT_DAYS="${CA_CERT_DAYS:-3650}"
export CA_CRL_DAYS="${CA_CRL_DAYS:-365}"

CA_die() {
  echo "$0: ERROR: $*" 1>&2
  exit "${2-1}"
}

CA_init() {
  local cn="$1"; shift
  local ca_dir="$1"; shift

  mkdir -m 0700 \
    "$ca_dir" \
    "$ca_dir/private" \
  || return 1 \
  ;
  mkdir -m 0755 \
    "$ca_dir/etc" \
    "$ca_dir/certs" \
    "$ca_dir/signed" \
    "$ca_dir/csr" \
    "$ca_dir/crl" \
  || return 1 \
  ;
  echo 100000 >"$ca_dir/serial" || return 1
  echo 00 >"$ca_dir/crlnumber" || return 1
  touch "$ca_dir/index.txt" || return 1

  cat >"$ca_dir/etc/openssl.cnf" <<'EOF' || return 1
[ ca ]
## ======================================================================

default_ca=		CA_default

[ CA_default ]
## ======================================================================

dir=			.

private_key=		$dir/private/ca.key
certificate=		$dir/certs/ca.crt

serial=			$dir/serial
certs=			$dir/certs
new_certs_dir=		$dir/signed
crl_dir=		$dir/crl
database=		$dir/index.txt

crlnumber=		$dir/crlnumber
crl=			$dir/crl.pem
RANDFILE=		$dir/private/random

default_days=		$ENV::CA_CERT_DAYS
default_crl_days=	$ENV::CA_CRL_DAYS
default_md=		$ENV::CA_DIGEST_ALGORITHM
x509_extensions=	client_cert

policy=			policy_anything

[ policy_anything ]
## ======================================================================

countryName=		optional
stateOrProvinceName=	optional
localityName=		optional
organizationName=	optional
organizationalUnitName=	optional
commonName=		supplied
emailAddress=		optional

[ req ]
## ======================================================================

default_bits=		$ENV::CA_KEY_BITS
default_md=		$ENV::CA_DIGEST_ALGORITHM
x509_extensions=	v3_ca

distinguished_name=	req_distinguished_name
attributes=		req_attributes

[ req_distinguished_name ]
## ======================================================================

[ req_attributes ]
## ======================================================================

[ v3_ca ]
## ======================================================================

basicConstraints=	CA:true

subjectKeyIdentifier=	hash
authorityKeyIdentifier=	keyid:always,issuer

[ v3_req ]
## ======================================================================

basicConstraints=	CA:false

keyUsage=		nonRepudiation, digitalSignature, keyEncipherment

[ server_cert ]
## ======================================================================

basicConstraints=	CA:false
nsComment=		"OpenSSL Simple CA Generated Server Certificate"

subjectKeyIdentifier=	hash
authorityKeyIdentifier=	keyid,issuer:always
keyUsage=		digitalSignature, keyEncipherment
extendedKeyUsage=	serverAuth

[ client_cert ]
## ======================================================================

basicConstraints=	CA:false
nsComment=		"OpenSSL Simple CA Generated Client Certificate"

subjectKeyIdentifier=	hash
authorityKeyIdentifier=	keyid,issuer:always
keyUsage=		digitalSignature
extendedKeyUsage=	clientAuth

[ crl_ext ]
## ======================================================================

authorityKeyIdentifier=	keyid:always,issuer:always
EOF

  openssl req \
    -config "$ca_dir/etc/openssl.cnf" \
    -new \
    -x509 \
    -subj "/CN=$cn" \
    -extensions v3_ca \
    -days "$CA_CERT_DAYS" \
    -nodes \
    -keyout "$ca_dir/private/ca.key" \
    -out "$ca_dir/certs/ca.crt" \
  || return 1 \
  ;
  chmod 0400 "$ca_dir/private/ca.key" || return 1
  chmod 0444 "$ca_dir/certs/ca.crt" || return 1
}

CA_openssl() {
  local cmd="$1"; shift

  openssl \
    "$cmd" \
    -config "etc/openssl.cnf" \
    "$@" \
  ;
}

CA_key() {
  local cn="$1"; shift
  local key="private/$cn.key"

  openssl genrsa \
    "$CA_KEY_BITS" \
  >"$key" \
  || return 1 \
  ;
  chmod 0444 "$key" || return 1
}

CA_csr() {
  local req_cn="$1"; shift

  local req_key
  if [[ -f "$req_cn" ]]; then
    req_key="$req_cn"
    req_cn="${req_cn##*/}"
    req_cn="${req_cn%.key}"
  else
    req_key="private/$req_cn.key"
  fi
  local req_csr="csr/$req_cn.csr"

  CA_openssl req \
    -utf8 \
    -new \
    -key "$req_key" \
    -subj "/CN=$req_cn" \
  >"$req_csr" \
  ;
}

CA_openssl_ca() {
  CA_openssl ca \
    -utf8 \
    -batch \
    "$@" \
  2> >(sed '/^Using configuration from etc\/openssl\.cnf$/d' 1>&2) \
  ;
}

CA_sign() {
  local req_cn="$1"; shift

  local req_csr
  if [[ -f "$req_cn" ]]; then
    req_csr="$req_cn"
    req_cn="${req_cn##*/}"
    req_cn="${req_cn%.csr}"
  else
    req_csr="csr/$req_cn.csr"
  fi

  local req_cert="signed/$req_cn.crt"

  local req_altnames=""
  local req_altname
  for req_altname in "$@"; do
    ## FIXME: Support IP:192.168.0.1 and so on
    req_altnames="${req_altnames:+$req_altnames,}DNS:$req_altname"
  done

  CA_openssl_ca \
    -in "$req_csr" \
    -out "$req_cert" \
    -extfile <(echo ${req_altnames:+subjectAltName="$req_altnames"}) \
  ;
}

CA_status() {
  ## FIXME: Get serial number from certificate
  local serial="$1"; shift

  CA_openssl_ca \
    -status "$serial" \
  ;
}

CA_revoke() {
  local req_cn="$1"; shift

  local req_cert
  if [[ -f "$req_cn" ]]; then
    req_cert="$req_cn"
    req_cn="${req_cn##*/}"
    req_cn="${req_cn%.crt}"
  else
    req_cert="signed/$req_cn.crt"
  fi

  CA_openssl_ca \
    -revoke "$req_cert" \
  ;
}

CA_crl() {
  CA_openssl_ca \
    -gencrl \
  ;
}

if [[ ${#BASH_SOURCE[@]} -eq 1 ]]; then
  cmd_name="${1//-/_}"; shift
  if ! PATH= type "CA_$cmd_name" >/dev/null 2>&1; then
    CA_die "Invalid command: $cmd_name"
  fi

  [[ $cmd_name != init && -f etc/ca.env ]] && . etc/ca.env >/dev/null 2>&1
  "CA_$cmd_name" "$@"
  exit "$?"
fi

return 0

