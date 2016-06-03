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

export CA_ARGV0="${CA_ARGV0:-$0}"
export CA_DIR="${CA_DIR:-.}"
export CA_TITLE="${CA_TITLE:-OpenSSL Simple and Stupid CA (${CA_ARGV0##*/})}"
export CA_KEY_BITS="${CA_KEY_BITS:-4096}"
export CA_DIGEST_ALGORITHM="${CA_DIGEST_ALGORITHM:-sha384}"
export CA_CERT_DAYS="${CA_CERT_DAYS:-3650}"
export CA_CRL_DAYS="${CA_CRL_DAYS:-365}"

export CA_CERT_ALTNAMES=""

CA_caller_name() {
  local caller="${FUNCNAME[2]}"

  if [[ -z ${CA_MODULE_SOURCED+set} ]]; then
    caller="${CA_ARGV0##*/} ${caller#CA_}"
  fi

  echo "$caller"
}

CA_error() {
  echo "$(CA_caller_name): ERROR: $*" 1>&2
}

CA_function_usage() {
  local args="$1"; shift

  echo "Usage: $(CA_caller_name) $args"
}

CA_command_usage() {
  local n="${CA_ARGV0##*/}"

  cat <<EOF
Initialization:
EOF

  if [[ $CA_ARGV0 == "$0" ]]; then
    cat <<EOF
  CA_DIR=/srv/ca $n init 'Demo CA (NO WARRANTY)' .example.jp
    or
  $n init /srv/ca 'Demo CA (NO WARRANTY)' .example.jp
EOF
  else
    cat <<EOF
  $n init 'Demo CA (NO WARRANTY)' .example.jp
EOF
  fi

  cat <<EOF

Usage:
EOF

  if [[ $CA_ARGV0 == "$0" ]]; then
    cat <<EOF
  export CA_DIR=/srv/ca
    or
  cd /srv/ca
    and then
EOF
  fi

  cat <<EOF
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
  if [[ $# -lt 2 ]]; then
    CA_error "Invalid argument(s)"
    CA_function_usage "[CA_DIR] CA_TITLE NAME_CONSTRAINTS [...]"
    return 1
  fi

  if [[ $1 == /* ]];then
    CA_DIR="$1"; shift
  fi
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

  mkdir -m 0755 "$CA_DIR" || return 1
  mkdir -m 0750 "$CA_DIR/private" || return 1
  mkdir -m 0755 \
    "$CA_DIR/etc" \
    "$CA_DIR/certs" \
    "$CA_DIR/signed" \
    "$CA_DIR/csr" \
    "$CA_DIR/crl" \
    "$CA_DIR/revoked" \
  || return 1 \
  ;
  touch "$CA_DIR/index.txt" || return 1
  echo 100000 >"$CA_DIR/serial.txt" || return 1
  echo 00 >"$CA_DIR/crlnumber.txt" || return 1

  cat >"$CA_DIR/etc/CA.env" <<EOF || return 1
CA_TITLE="$ca_title"
CA_KEY_BITS="$CA_KEY_BITS"
CA_DIGEST_ALGORITHM="$CA_DIGEST_ALGORITHM"
CA_CERT_DAYS="$CA_CERT_DAYS"
CA_CRL_DAYS="$CA_CRL_DAYS"
EOF

  cat >"$CA_DIR/etc/openssl.cnf" <<'EOF' || return 1
[ ca ]
## ======================================================================

default_ca=		CA_default

[ CA_default ]
## ======================================================================

dir=			$ENV::CA_DIR

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
  >>"$CA_DIR/etc/openssl.cnf" \
  ;

  cat >>"$CA_DIR/etc/openssl.cnf" <<'EOF' || return 1

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
    -config "$CA_DIR/etc/openssl.cnf" \
    -new \
    -x509 \
    -subj "/host=$(uname -n)/SN=L=${CA_ARGV0//\//\\\/}/givenName=${CA_DIR//\//\\\/}/CN=$ca_title" \
    -extensions ca_ext \
    -days "$CA_CERT_DAYS" \
    -nodes \
    -keyout "$CA_DIR/private/CA.key" \
    -out "$CA_DIR/certs/CA.crt" \
  || return 1 \
  ;
  chmod 0400 "$CA_DIR/private/CA.key" || return 1
  chmod 0444 "$CA_DIR/certs/CA.crt" || return 1
}

CA_openssl() {
  local cmd="$1"; shift
  local args=()

  if [[ $cmd != x509 ]]; then
    args+=(-config "$CA_DIR/etc/openssl.cnf")
  fi

  openssl \
    "$cmd" \
    ${args[@]+"${args[@]}"} \
    "$@" \
  ;
}

CA_openssl_ca() {
  CA_openssl ca \
    -utf8 \
    -batch \
    "$@" \
  2> >(sed '/^Using configuration from .*\/etc\/openssl\.cnf$/d' 1>&2) \
  || return 1 \
  ;
}

CA_serial() {
  local serial_or_cert_or_cn="$1"; shift

  local serial
  if [[ -f signed/$serial_or_cert_or_cn.pem ]]; then
    serial="$serial_or_cert_or_cn"
  else
    local cert
    if [[ -f $serial_or_cert_or_cn ]]; then
      cert="$serial_or_cert_or_cn"
    else
      cert="$CA_DIR/signed/$serial_or_cert_or_cn.crt"
      if [[ ! -f $cert ]]; then
	cert="$CA_DIR/revoked/$serial_or_cert_or_cn.crt"
      fi
    fi

    if [[ ! -f "$cert" ]]; then
      CA_error "No certificate found: $serial_or_cert_or_cn"
      return 1
    fi

    serial=$(CA_openssl x509 -in "$cert" -serial -noout) || return 1
    serial="${serial#*=}"
  fi

  echo "$serial"
}

CA_key() {
  if [[ $# -ne 1 ]]; then
    CA_error "Invalid argument(s)"
    CA_function_usage "CN"
    return 1
  fi

  local cn="${1,,}"; shift
  local key="$CA_DIR/private/$cn.key"
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
    CA_error "Invalid argument(s)"
    CA_function_usage "CN"
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
    key="$CA_DIR/private/$cn.key"
    if [[ ! -f "$key" ]]; then
      CA_key "$cn" || return $?
    fi
  fi
  local csr="$CA_DIR/csr/$cn.csr"
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
  if [[ $# -lt 1 ]]; then
    CA_error "Invalid argument(s)"
    CA_function_usage "CN [ALTNAME ...]"
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
    csr="$CA_DIR/csr/$cn.csr"
    if [[ ! -f "$csr" ]]; then
      CA_csr "$cn" || return $?
    fi
  fi

  local cert="$CA_DIR/signed/$cn.crt"
  if [[ -f $cert ]]; then
    CA_error "Certificate already exists: $cert"
    return 1
  fi

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
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    rm -f "$cert"
    return $rc
  fi

  local serial
  serial=$(CA_serial "$cert")
  ln -sf "../signed/$serial.pem" "$cert"
}

CA_status() {
  local serial_or_cert_or_cn="$1"; shift

  local serial
  serial=$(CA_serial "$serial_or_cert_or_cn")
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    return $rc
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
    cert="$CA_DIR/signed/$cn.crt"
  fi

  if [[ ! -f "$cert" ]]; then
    CA_error "No valid certificate found: $cert_or_cn"
    return 1
  fi

  CA_openssl_ca \
    -revoke "$cert" \
  || return $? \
  ;

  mv "$cert" "$CA_DIR/revoked/"
}

CA_crl() {
  local crl="$CA_DIR/crl/CA.crl"
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
    CA_command_usage
    return 1
  fi

  local cmd_name="${1//-/_}"; shift
  if ! PATH= type "CA_$cmd_name" >/dev/null 2>&1; then
    CA_error "Invalid command: $cmd_name"
    return 1
  fi

  if [[ $cmd_name != init && -f $CA_DIR/etc/CA.env ]]; then
    . "$CA_DIR/etc/CA.env" >/dev/null 2>&1
  fi

  "CA_$cmd_name" "$@"
  return "$?"
}

if [[ ${#BASH_SOURCE[@]} -eq 1 ]]; then
  unset CA_MODULE_SOURCED
  CA_command "$@"
  exit "$?"
fi

CA_MODULE_SOURCED="set"

return 0

