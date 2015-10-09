#!/bin/bash
##
## OpenSSL: Simple CA implementation
## Copyright (c) 2015 SATOH Fumiyasu @ OSS Technology Corp., Japan
##
## License: GNU General Public License version 3
##
## WARNING: This software comes with ABSOLUTELY NO WARRANTY
##

set -u
set -C

export CA_TITLE="${CA_TITLE:-OpenSSL Simple CA (${0##*/})}"
export CA_KEY_BITS="${CA_KEY_BITS:-4096}"
export CA_DIGEST_ALGORITHM="${CA_DIGEST_ALGORITHM:-sha384}"
export CA_CERT_ALTNAMES=""
export CA_CERT_DAYS="${CA_CERT_DAYS:-3650}"
export CA_CRL_DAYS="${CA_CRL_DAYS:-365}"

CA_die() {
  echo "$0: ERROR: $*" 1>&2
  exit "${2-1}"
}

CA_init() {
  if [[ $# -lt 1 || $# -gt 2 ]]; then
    CA_die "Usage: init CA_DIR [CA_TITLE]"
    return 1
  fi

  local ca_dir="$1"; shift
  local ca_title="${1:-$CA_TITLE}"; ${1+shift}

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

  cat >"$ca_dir/etc/CA.env" <<EOF || return 1
CA_TITLE="$ca_title"
CA_KEY_BITS="$CA_KEY_BITS"
CA_DIGEST_ALGORITHM="$CA_DIGEST_ALGORITHM"
CA_CERT_DAYS="$CA_CERT_DAYS"
CA_CRL_DAYS="$CA_CRL_DAYS"
EOF

  cat >"$ca_dir/etc/openssl.cnf" <<'EOF' || return 1
[ ca ]
## ======================================================================

default_ca=		CA_default

[ CA_default ]
## ======================================================================

dir=			.

private_key=		$dir/private/CA.key
certificate=		$dir/certs/CA.crt

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
nsComment=		$ENV::CA_TITLE Generated Server Certificate

subjectKeyIdentifier=	hash
authorityKeyIdentifier=	keyid,issuer:always
keyUsage=		digitalSignature, keyEncipherment
extendedKeyUsage=	serverAuth

subjectAltName=		$ENV::CA_CERT_ALTNAMES

[ client_cert ]
## ======================================================================

basicConstraints=	CA:false
nsComment=		$ENV::CA_TITLE Generated Client Certificate

subjectKeyIdentifier=	hash
authorityKeyIdentifier=	keyid,issuer:always
keyUsage=		digitalSignature
extendedKeyUsage=	clientAuth

subjectAltName=		$ENV::CA_CERT_ALTNAMES

[ crl_ext ]
## ======================================================================

authorityKeyIdentifier=	keyid:always,issuer:always
EOF

  openssl req \
    -config "$ca_dir/etc/openssl.cnf" \
    -new \
    -x509 \
    -subj "/CN=$ca_title" \
    -extensions v3_ca \
    -days "$CA_CERT_DAYS" \
    -nodes \
    -keyout "$ca_dir/private/CA.key" \
    -out "$ca_dir/certs/CA.crt" \
  || return 1 \
  ;
  chmod 0400 "$ca_dir/private/CA.key" || return 1
  chmod 0444 "$ca_dir/certs/CA.crt" || return 1
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
  if [[ $# -ne 1 ]]; then
    CA_die "Usage: key CN"
    return 1
  fi

  local cn="${1,,}"; shift
  local key="private/$cn.key"
  local key_tmp="$key.$$.tmp"

  (
    umask 0277
    openssl genrsa \
      "$CA_KEY_BITS" \
    >"$key_tmp" \
    ;
  ) || {
    rm -f "$key_tmp"
    return 1
  }

  mv "$key_tmp" "$key" || return 1
}

CA_csr() {
  if [[ $# -ne 1 ]]; then
    CA_die "Usage: csr CN"
    return 1
  fi

  local key_or_cn="$1"; shift

  local cn key
  if [[ -f "$key_or_cn" ]]; then
    key="$key_or_cn"
    cn="${key_or_cn##*/}"
    cn="${cn%.key}"
    cn="${cn,,}"
  else
    cn="$key_or_cn"
    key="private/$cn.key"
    if [[ ! -f "$key" ]]; then
      CA_key "$cn" || return $?
    fi
  fi
  local csr="csr/$cn.csr"
  local csr_tmp="$csr.$$.tmp"

  CA_openssl req \
    -utf8 \
    -new \
    -key "$key" \
    -subj "/CN=$cn" \
  >"$csr_tmp" \
  || {
    rm -f "$csr_tmp"
    return 1
  }

  mv "$csr_tmp" "$csr" || return 1
}

CA_openssl_ca() {
  CA_openssl ca \
    -utf8 \
    -batch \
    "$@" \
  2> >(sed '/^Using configuration from etc\/openssl\.cnf$/d' 1>&2) \
  || return 1 \
  ;
}

CA_sign() {
  if [[ $# -ne 1 ]]; then
    CA_die "Usage: sign CN"
    return 1
  fi

  local csr_or_cn="$1"; shift

  local cn csr
  if [[ -f "$csr_or_cn" ]]; then
    csr="$csr_or_cn"
    cn="${csr_or_cn##*/}"
    cn="${cn%.csr}"
    cn="${cn,,}"
  else
    cn="$csr_or_cn"
    csr="csr/$cn.csr"
    if [[ ! -f "$csr" ]]; then
      CA_csr "$cn" "$@" || return $?
    fi
  fi

  local cert="signed/$cn.crt"

  local altnames=""
  local altname
  for altname in "$cn" "$@"; do
    ## FIXME: Support IP:192.168.0.1 and so on
    altnames="${altnames:+$altnames,}DNS:$altname"
  done

  CA_CERT_ALTNAMES="$altnames" \
  CA_openssl_ca \
    -in "$csr" \
    -out "$cert" \
  ;
}

CA_status() {
  ## FIXME: Get serial number from certificate
  local serial_or_cert_or_cn="$1"; shift

  local serial
  if [[ -f signed/$serial_or_cert_or_cn.pem ]]; then
    serial="$serial_or_cert_or_cn"
  else
    local cert
    if [[ -f $serial_or_cert_or_cn ]]; then
      cert="$serial_or_cert_or_cn"
    else
      cert="signed/$serial_or_cert_or_cn.crt"
    fi
    serial=$(openssl x509 -serial -noout <"$cert") || return 1
    serial="${serial#*=}"
  fi

  CA_openssl_ca \
    -status "$serial" \
  ;
}

CA_revoke() {
  local cert_or_cn="$1"; shift

  local cn cert
  if [[ -f "$cert_or_cn" ]]; then
    cert="$cert_or_cn"
    cn="${cert_or_cn##*/}"
    cn="${cn%.crt}"
    cn="${cn,,}"
  else
    cn="$cert_or_cn"
    cert="signed/$cn.crt"
  fi

  CA_openssl_ca \
    -revoke "$cert" \
  ;
}

CA_crl() {
  local crl="crl/CA.crl"
  local crl_tmp="$crl.$$.tmp"

  CA_openssl_ca \
    -gencrl \
  >"$crl_tmp" \
  || {
    rm -f "$crl_tmp"
    return 1
  }

  mv "$crl_tmp" "$crl" || return 1
}

if [[ ${#BASH_SOURCE[@]} -eq 1 ]]; then
  cmd_name="${1//-/_}"; shift
  if ! PATH= type "CA_$cmd_name" >/dev/null 2>&1; then
    CA_die "Invalid command: $cmd_name"
  fi

  [[ $cmd_name != init && -f etc/CA.env ]] && . etc/CA.env >/dev/null 2>&1
  "CA_$cmd_name" "$@"
  exit "$?"
fi

return 0

