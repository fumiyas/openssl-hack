#!/bin/bash
##
## OpenSSL: Simple and Stupid CA implementation
## Copyright (c) 2015-2016 SATOH Fumiyasu @ OSS Technology Corp., Japan
##
## License: GNU General Public License version 3
##
## WARNING: This software comes with ABSOLUTELY NO WARRANTY
##

set -u
set -C

export CA_TITLE="${CA_TITLE:-OpenSSL Simple and Stupid CA (${0##*/})}"
export CA_KEY_BITS="${CA_KEY_BITS:-4096}"
export CA_DIGEST_ALGORITHM="${CA_DIGEST_ALGORITHM:-sha384}"
export CA_CERT_DAYS="${CA_CERT_DAYS:-3650}"
export CA_CRL_DAYS="${CA_CRL_DAYS:-365}"

export CA_CERT_ALTNAMES=""

CA_die() {
  echo "$0: ERROR: $*" 1>&2
  exit "${2-1}"
}

CA_usage() {
  local n="${0##*/}"

  cat <<EOF
Initialization:
  $n init /srv/ca 'Demo CA (NO WARRANTY)' .example.jp

Usage:
  cd /srv/ca
  $n key www.example.jp
  $n csr www.example.jp
  $n sign www.example.jp [altname.example.com ...]
  $n revoke www.example.jp
  $n status www.example.jp
  $n crl

Files in CA directory:
  etc/*				CA's configurations
  private/CA.key		CA's private key
  certs/CA.crt			CA's certificate
  crl/CA.crl			CA's CRL
  csr/*.csr			Generated or received CSRs
  private/*.key			Generated private keys
  signed/*.crt			Signed certificates
EOF
}

CA_init() {
  if [[ $# -lt 3 ]]; then
    CA_die "Usage: init CA_DIR CA_TITLE NAME_CONSTRAINTS [...]"
    return 1
  fi

  local ca_dir="$1"; shift
  local ca_title="${1:-$CA_TITLE}"; ${1+shift}
  local ca_name_constraints=()

  local name name_type name_nodes name_constraint
  for name in "$@"; do
    name_type=""
    if [[ $name =~ ^[0-9.]*$ ]]; then
      name_type="IP"
      name_nodes=(${name//./ })
      if [[ ${#name_nodes[@]} != 4 ]]; then
	name_type=""
      else
	for name_node in "${name_nodes[@]}"; do
	  if [[ $name_node -gt 255 ]]; then
	    name_type=""
	    break
	  fi
	done
      fi
    fi

    name="${name_type:-DNS} $name"

    name_constraint="permitted;$name"
    if [[ $name_type == "IP" ]]; then
      name_constraint+="/255.255.255.255"
    fi
    ca_name_constraints+=("$name_constraint")
  done

  mkdir -m 0755 "$ca_dir" || return 1
  mkdir -m 0750 "$ca_dir/private" || return 1
  mkdir -m 0755 \
    "$ca_dir/etc" \
    "$ca_dir/certs" \
    "$ca_dir/signed" \
    "$ca_dir/csr" \
    "$ca_dir/crl" \
  || return 1 \
  ;
  touch "$ca_dir/index.txt" || return 1
  echo 100000 >"$ca_dir/serial.txt" || return 1
  echo 00 >"$ca_dir/crlnumber.txt" || return 1

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

serial=			$dir/serial.txt
certs=			$dir/certs
new_certs_dir=		$dir/signed
crl_dir=		$dir/crl
database=		$dir/index.txt

crlnumber=		$dir/crlnumber.txt
crl=			$dir/crl.pem
RANDFILE=		$dir/private/random

default_days=		$ENV::CA_CERT_DAYS
default_crl_days=	$ENV::CA_CRL_DAYS
default_md=		$ENV::CA_DIGEST_ALGORITHM
x509_extensions=	server_cert

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
#x509_extensions=	ca_ext
#req_extensions=	req_ext

distinguished_name=	req_distinguished_name
attributes=		req_attributes

[ req_distinguished_name ]
## ======================================================================

[ req_attributes ]
## ======================================================================

[ ca_ext ]
## ======================================================================

basicConstraints=	critical,CA:true
nameConstraints=	critical,@ca_name_constraints

subjectKeyIdentifier=	hash
authorityKeyIdentifier=	keyid:always,issuer

[ ca_name_constraints ]
EOF

  for name_constraint in "${ca_name_constraints[@]}"; do
    echo "$name_constraint"
  done |awk '{ print $1"."NR" = "$2 }' \
  >>"$ca_dir/etc/openssl.cnf" \
  ;

  cat >>"$ca_dir/etc/openssl.cnf" <<'EOF' || return 1

[ req_ext ]
## ======================================================================

basicConstraints=	critical,CA:false

keyUsage=		nonRepudiation, digitalSignature, keyEncipherment

[ server_cert ]
## ======================================================================

basicConstraints=	critical,CA:false
nsComment=		$ENV::CA_TITLE Generated Server Certificate

subjectKeyIdentifier=	hash
authorityKeyIdentifier=	keyid,issuer:always
keyUsage=		digitalSignature, keyEncipherment
extendedKeyUsage=	serverAuth

subjectAltName=		$ENV::CA_CERT_ALTNAMES

[ client_cert ]
## ======================================================================

basicConstraints=	critical,CA:false
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
    -extensions ca_ext \
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

CA_openssl_ca() {
  CA_openssl ca \
    -utf8 \
    -batch \
    "$@" \
  2> >(sed '/^Using configuration from etc\/openssl\.cnf$/d' 1>&2) \
  || return 1 \
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
    umask 0227
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

  ## FIXME: How to specify other attributes, such as C(ountry)?
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

CA_sign() {
  if [[ $# -ne 1 ]]; then
    CA_die "Usage: sign CN [ALTNAME ...]"
    return 1
  fi

  ## FIXME: How to specify a policy?
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

CA_command() {
  if [[ -z ${1-} ]]; then
    CA_usage
    exit 1
  fi

  local cmd_name="${1//-/_}"; shift
  if ! PATH= type "CA_$cmd_name" >/dev/null 2>&1; then
    CA_die "Invalid command: $cmd_name"
  fi

  [[ $cmd_name != init && -f etc/CA.env ]] && . etc/CA.env >/dev/null 2>&1

  "CA_$cmd_name" "$@"
  exit "$?"
}

if [[ ${#BASH_SOURCE[@]} -eq 1 ]]; then
  CA_command "$@"
fi

return 0

