#!/bin/bash
##
## OpenSSL: Simple and Stupid CA implementation
## Copyright (c) 2015-2019 SATOH Fumiyasu @ OSS Technology Corp., Japan
##
## License: GNU General Public License version 3
##
## WARNING: This software comes with ABSOLUTELY NO WARRANTY
##

set -u
set -C

export CA_ARGV0="${CA_ARGV0:-$0}"
export CA_DIR="${CA_DIR:-.}"
export CA_TITLE="${CA_TITLE:-OpenSSL Simple and Stupid CA (NO WARRANTY)}"
export CA_KEY_BITS="${CA_KEY_BITS:-4096}"
export CA_DIGEST_ALGORITHM="${CA_DIGEST_ALGORITHM:-sha384}"
export CA_CERT_DAYS="${CA_CERT_DAYS:-3650}"
export CA_CRL_DAYS="${CA_CRL_DAYS:-365}"

export CA_REQ_ALTNAMES=""
export CA_CERT_ALTNAMES=""

## ======================================================================

## From nid_objs[] in openssl-1.1.1/crypto/objects/obj_dat.h
CA_CANONICAL_CASE_ATTRIBUTE_NAMES=(
  CN	commonName
  UID	userId
  mail	rfc822Mailbox
	emailAddress
  GN	givenName
  SN	surname
	title
	serialNumber
	host
  DC	domainComponent
  OU	organizationalUnitName
  O	organizationName
  L	localityName
  ST	stateOrProvinceName
  C	countryName
)

typeset -A CA_CANONICAL_CASE_ATTRIBUTE_NAMES_BY_LOWER_NAME

_CA_prepare() {
  local name name_lower
  for name in "${CA_CANONICAL_CASE_ATTRIBUTE_NAMES[@]}"; do
    CA_CANONICAL_CASE_ATTRIBUTE_NAMES_BY_LOWER_NAME[${name,,}]="$name"
  done

  return 0
}

_CA_prepare || return $?

## ======================================================================

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

CA_warn() {
  echo "$(CA_caller_name): WARNING: $*" 1>&2
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
  $n csr www.example.jp [altname.example.jp ...] [uid=foo ...]
  $n sign www.example.jp [altname.example.jp ...] [uid=foo ...]
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
  revoked/*.crt			Revoked certificates
EOF
}

CA_quote_shell() {
  local sq="'"
  local str="${1//$sq/$sq\\$sq$sq}"; shift

  echo "$sq$str$sq"
}

## openssl(1) recognizes attribute names case-sensitively in subjects
CA_canonicalize_attribute_name() {
  local name_lower="${1,,}"; shift

  echo "${CA_CANONICAL_CASE_ATTRIBUTE_NAMES_BY_LOWER_NAME[$name_lower]-}"
}

## Escape an attribute value for OpenSSL oneline format
## (/type0=value0/type1=value1/type2=...)
CA_escape_value_oneline() {
  local value="${1//\\/\\\\}"; shift

  value="${value//\//\\\/}"
  value="${value//+/\\+}"

  echo "$value"
}

## Escape an attribute name and value for OpenSSL oneline format
## (/type0=value0/type1=value1/type2=...)
CA_escape_attribute_oneline() {
  local attr="$1"; shift

  local name="${attr%%=*}"
  local value="${attr#*=}"

  local name_canon="$(CA_canonicalize_attribute_name "$name")"
  if [[ -z $name_canon ]]; then
    return 1
  fi

  echo "$name_canon=$(CA_escape_value_oneline "$value")"
}

CA_type_of_value() {
  local value="$1"; shift
  local value_lower="${value,,}"

  if  [[ $value_lower =~ ^[a-z_][a-z_0-9\-]*(\+[a-z_][a-z_0-9\-]*)*:// ]]; then
    echo 'URI'
    return 0
  fi

  ## FIXME: Support IPv6 addresses
  if  [[ $value =~ ^(([12][0-9]|[1-9])?[0-9]\.){3}([12][0-9]|[1-9])?[0-9]$ ]]; then
    if  [[ ! $value =~ 25[6-9] && ! $value =~ 2[6-9][0-9] ]]; then
      echo 'IP'
      return 0
    fi
  fi

  if  [[ $value_lower =~ ^(([a-z0-9][a-z0-9\-]+|[a-z])+\.)+([a-z0-9][a-z0-9\-]+|[a-z])+$ ]]; then
    echo 'DNS'
    return 0
  fi

  if  [[ $value_lower =~ ^[^@]+@(([a-z0-9][a-z0-9\-]+|[a-z])+\.)+([a-z0-9][a-z0-9\-]+|[a-z])+$ ]]; then
    echo 'email'
    return 0
  fi

  return 1
}

CA_name_to_typed_altname() {
  local value="$1"; shift

  local type="$(CA_type_of_value "$value")"
  if [[ -z $type ]]; then
    return 1
  fi

  ## FIXME: Escape $value
  echo "$type:$value"
}

## ======================================================================

CA_init() {
  if [[ ${1-} == /* ]];then
    CA_DIR="$1"; shift
  fi
  if [[ $# -lt 2 ]]; then
    CA_error "Invalid argument(s)"
    CA_function_usage "[/CA_DIR] CA_TITLE NAME_CONSTRAINTS [...]"
    return 1
  fi

  local ca_title="${1:-$CA_TITLE}"; ${1+shift}
  local ca_name_constraints=()

  local name name_type name_nodes name_constraint
  ## FIXME: Support e-mail address
  for name in "$@"; do
    name_type="$(CA_type_of_value "$name")"
    if [[ -z $name_type ]]; then
      CA_error "Unknown name type: $name"
      return 1
    fi

    if [[ $name_type == "DNS" ]]; then
      ## Remove a leading "." if any
      name="${name#.}"
    fi

    name_constraint="permitted;$name_type $name"
    if [[ $name_type == "IP" ]]; then
      ## FIXME: Support custom netmask
      name_constraint+="/255.255.255.0"
    fi
    ca_name_constraints+=("$name_constraint")
  done

  local ca_host=$(uname -n)
  local ca_sn="${CA_ARGV0//\//.}"; ca_sn="${ca_sn#.}"
  local ca_gn="${ca_title//\//.}"; ca_gn="${ca_gn#.}"
  local ca_cn="${CA_DIR//\//.}"; ca_cn="${ca_cn#.}"

  local ca_subject attr attr_oneline
  for attr in "host=$ca_host" "SN=$ca_sn" "GN=$ca_gn" "CN=$ca_cn"; do
    attr_oneline="$(CA_escape_attribute_oneline "$attr")"
    if [[ -z $attr_oneline ]]; then
      CA_error "Unknown attribute name: $attr"
      return 1
    fi
    ca_subject+="/$attr_oneline"
  done

  mkdir -m 0755 "$CA_DIR" || return $?
  mkdir -m 0750 "$CA_DIR/private" || return $?
  mkdir -m 0755 \
    "$CA_DIR/etc" \
    "$CA_DIR/certs" \
    "$CA_DIR/signed" \
    "$CA_DIR/csr" \
    "$CA_DIR/crl" \
    "$CA_DIR/revoked" \
  || return $? \
  ;
  touch "$CA_DIR/index.txt" || return $?
  touch "$CA_DIR/index.txt.attr" || return $?
  echo 100000 >"$CA_DIR/serial.txt" || return $?
  echo 00 >"$CA_DIR/crlnumber.txt" || return $?

  cat >"$CA_DIR/etc/CA.env" <<EOF || return $?
CA_TITLE="$ca_title"
CA_KEY_BITS="$CA_KEY_BITS"
CA_DIGEST_ALGORITHM="$CA_DIGEST_ALGORITHM"
CA_CERT_DAYS="$CA_CERT_DAYS"
CA_CRL_DAYS="$CA_CRL_DAYS"
EOF

  cat >"$CA_DIR/etc/openssl.cnf" <<'EOF' || return $?
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
#x509_extensions=	server_cert_ext

policy=			policy_anything

[ policy_anything ]
## ======================================================================

commonName=		supplied

userId=			optional
mail=			optional
emailAddress=		optional

givenName=		optional
surname=		optional

domainComponent=	optional

organizationalUnitName=	optional
organizationName=	optional
localityName=		optional
stateOrProvinceName=	optional
countryName=		optional

[ req ]
## ======================================================================

default_bits=		$ENV::CA_KEY_BITS
default_md=		$ENV::CA_DIGEST_ALGORITHM
#x509_extensions=	ca_ext
req_extensions=		req_ext

distinguished_name=	req_distinguished_name
attributes=		req_attributes

[ req_distinguished_name ]
## ======================================================================

[ req_attributes ]
## ======================================================================

[ ca_ext ]
## ======================================================================

basicConstraints=	critical,CA:true,pathlen:1
nameConstraints=	critical,@ca_name_constraints

subjectKeyIdentifier=	hash
authorityKeyIdentifier=	keyid:always,issuer
keyUsage=		keyCertSign, cRLSign

[ ca_name_constraints ]
EOF

  for name_constraint in "${ca_name_constraints[@]}"; do
    echo "$name_constraint"
  done |awk '{ n[$1]++; print $1"."n[$1]" = "$2 }' \
  >>"$CA_DIR/etc/openssl.cnf" \
  ;

  cat >>"$CA_DIR/etc/openssl.cnf" <<'EOF' || return $?

[ req_ext ]
## ======================================================================

basicConstraints=	critical,CA:false

keyUsage=		nonRepudiation, digitalSignature, keyEncipherment

subjectAltName=		$ENV::CA_REQ_ALTNAMES

[ server_cert_ext ]
## ======================================================================

basicConstraints=	critical,CA:false
nsComment=		$ENV::CA_TITLE Generated Server Certificate

subjectKeyIdentifier=	hash
authorityKeyIdentifier=	keyid,issuer:always
keyUsage=		digitalSignature, keyEncipherment
extendedKeyUsage=	serverAuth

subjectAltName=		$ENV::CA_CERT_ALTNAMES

[ client_cert_ext ]
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

  CA_REQ_ALTNAMES="DNS:$ca_cn" \
  openssl req \
    -config "$CA_DIR/etc/openssl.cnf" \
    -new \
    -x509 \
    -subj "$ca_subject" \
    -extensions ca_ext \
    -days "$CA_CERT_DAYS" \
    -nodes \
    -keyout "$CA_DIR/private/CA.key" \
    -out "$CA_DIR/certs/CA.crt" \
  || return $? \
  ;
  chmod 0400 "$CA_DIR/private/CA.key" || return $?
  chmod 0444 "$CA_DIR/certs/CA.crt" || return $?
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
    -multivalue-rdn \
    "$@" \
  2> >(sed '/^Using configuration from .*\/etc\/openssl\.cnf$/d' 1>&2) \
  || return $? \
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
    fi

    if [[ ! -f "$cert" ]]; then
      CA_error "No certificate found: $serial_or_cert_or_cn"
      return 1
    fi

    serial=$(CA_openssl x509 -in "$cert" -serial -noout) || return $?
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
  local key_file="$CA_DIR/private/$cn.key"
  local key_tmp="$key_file.$$.tmp"

  (
    umask 0227
    openssl genrsa \
      "$CA_KEY_BITS" \
    >"$key_tmp" \
    ;
  ) || {
    local rc=$?
    rm -f "$key_tmp"
    return $rc
  }

  mv "$key_tmp" "$key_file" || return $?
}

CA_csr() {
  if [[ $# -lt 1 ]]; then
    CA_error "Invalid argument(s)"
    CA_function_usage "CN"
    return 1
  fi

  local key_file_or_cn="$1"; shift

  local cn key_file
  if [[ -f "$key_file_or_cn" ]]; then
    key_file="$key_file_or_cn"
    cn="${key_file_or_cn##*/}"
    cn="${cn%.key}"
    cn="${cn,,}"
  else
    cn="$key_file_or_cn"
    key_file="$CA_DIR/private/$cn.key"
    if [[ ! -f "$key_file" ]]; then
      CA_key "$cn" || return $?
    fi
  fi

  local subject="/CN=$(CA_escape_value_oneline "$cn")"
  local altnames_csv="$(CA_name_to_typed_altname "$cn")"
  local altname_or_rdn altname altname_with_type
  local rdn rdn_oneline
  while [[ $# -gt 0 ]]; do
    altname_or_rdn="$1"; shift
    if [[ $altname_or_rdn == -- ]]; then
      break
    elif [[ $altname_or_rdn == *=* ]]; then
      rdn="$altname_or_rdn"
      rdn_oneline="$(CA_escape_attribute_oneline "$rdn")"
      if [[ -z $rdn_oneline ]]; then
	CA_error "Unknown attribute name: $rdn"
	return 1
      fi
      subject+="+$rdn_oneline"
    else
      altname="$altname_or_rdn"
      altname_with_type="$(CA_name_to_typed_altname "$altname")"
      if [[ -z $altname_with_type ]]; then
	CA_error "Unknown name type: $altname"
	return 1
      fi
      altnames_csv+=",$altname_with_type"
    fi
  done

  ## Construct suffix in the subject
  local suffix suffix_oneline
  while [[ $# -gt 0 ]]; do
    suffix="$1"; shift
    suffix_oneline="$(CA_escape_attribute_oneline "$suffix")"
    if [[ -z $suffix_oneline ]]; then
      CA_error "Unknown attribute name: $suffix"
      return 1
    fi
    subject="/$suffix_oneline$subject"
  done

  local csr_file="$CA_DIR/csr/$cn.csr"
  local csr_tmp="$csr_file.$$.tmp"
  rm -f "$csr_tmp" || return $?
  echo '#!/bin/sh' >>"$csr_tmp"
  echo "cn=$(CA_quote_shell "$cn")" >>"$csr_tmp"
  echo "subject=$(CA_quote_shell "$subject")" >>"$csr_tmp"
  echo "altnames_csv=$(CA_quote_shell "$altnames_csv")" >>"$csr_tmp"
  echo 'csr="\' >>"$csr_tmp"
  CA_REQ_ALTNAMES="$altnames_csv" \
  CA_openssl req \
    -utf8 \
    -new \
    -key "$key_file" \
    -subj "$subject" \
    -multivalue-rdn \
  >>"$csr_tmp" \
  || {
    local rc=$?
    rm -f "$csr_tmp"
    return $rc
  }
  echo '"' >>"$csr_tmp"

  mv "$csr_tmp" "$csr_file" || return $?
}

CA_sign() {
  local cert_type="server"
  if [[ $1 == --* ]]; then
    cert_type="${1#--}"
    shift
  fi
  case "$cert_type" in
  server|client)
    ## OK
    ;;
  *)
    CA_error "Invalid certificate type: $cert_type"
    return 1
    ;;
  esac

  if [[ $# -lt 1 ]]; then
    CA_error "Invalid argument(s)"
    CA_function_usage "CN [ALTNAME ...]"
    return 1
  fi

  ## FIXME: How to specify a policy?
  local csr_file_or_cn="$1"; shift

  local cn csr_file csr_file_has_info_p
  if [[ -f "$csr_file_or_cn" ]]; then
    csr_file="$csr_file_or_cn"
    cn="${csr_file_or_cn##*/}"
    cn="${cn%.csr}"
    cn="${cn,,}"
    ## New style CSR file has additional information not only CSR
    if file "$csr_file" |grep 'shell script' >/dev/null; then
      csr_file_has_info_p=set
    fi
  else
    cn="$csr_file_or_cn"
    csr_file="$CA_DIR/csr/$cn.csr"
    csr_file_has_info_p=set
  fi

  local cert_file="$CA_DIR/signed/$cn.crt"
  if [[ -f $cert_file ]]; then
    CA_error "Certificate already exists: $cert_file"
    return 1
  fi

  if [[ ! -f "$csr_file" ]]; then
    CA_csr "$cn" "$@" || return $?
    shift $#
  fi

  local subject altnames_csv csr
  if [[ -n $csr_file_has_info_p ]]; then
    if [[ $# -gt 0 ]]; then
      CA_warn "Ignore alternative names and attributes in arguments"
    fi
    . "$csr_file" || return $?
  else
    subject="/CN=$(CA_escape_attribute_oneline "$cn")"
    altnames_csv="DNS:$cn"
    local altname altname_with_type
    for altname in "$@"; do
      altname_with_type="$(CA_name_to_typed_altname "$altname")"
      if [[ -z $altname_with_type ]]; then
	CA_error "Unknown name type: $altname"
	return 1
      fi
      altnames_csv+=",$altname_with_type"
    done
  fi

  CA_CERT_ALTNAMES="$altnames_csv" \
  CA_openssl_ca \
    -subj "$subject" \
    -in "$csr_file" \
    -out "$cert_file" \
    -extensions "${cert_type}_cert_ext" \
  ;
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    rm -f "$cert_file"
    return $rc
  fi

  local serial
  serial=$(CA_serial "$cert_file") || return $?
  ln -sf "../signed/$serial.pem" "$cert_file"
}

CA_status() {
  local serial_or_cert_or_cn="$1"; shift

  local serial
  serial=$(CA_serial "$serial_or_cert_or_cn") || return $?

  CA_openssl_ca \
    -status "$serial" \
  ;
}

CA_revoke() {
  local cert_file_or_cn="$1"; shift

  local cn cert_file
  if [[ -f "$cert_file_or_cn" ]]; then
    cert_file="$cert_file_or_cn"
    cn="${cert_file_or_cn##*/}"
    cn="${cn%.crt}"
    cn="${cn,,}"
  else
    cn="$cert_file_or_cn"
    cert_file="$CA_DIR/signed/$cn.crt"
  fi
  local key_file="$CA_DIR/private/$cn.key"
  local csr_file="$CA_DIR/csr/$cn.csr"

  if [[ ! -f "$cert_file" ]]; then
    CA_error "No valid certificate found: $cert_file_or_cn"
    return 1
  fi

  local serial
  serial=$(CA_serial "$cert_file") || return $?

  CA_openssl_ca \
    -revoke "$cert_file" \
  || return $? \
  ;

  mv "$cert_file" "$CA_DIR/revoked/$serial.$cn.crt"
  if [[ -f $key_file ]]; then
    mv "$key_file" "$CA_DIR/revoked/$serial.$cn.key"
  fi
  if [[ -f $csr_file ]]; then
    mv "$csr_file" "$CA_DIR/revoked/$serial.$cn.csr"
  fi
}

CA_crl() {
  local crl="$CA_DIR/crl/CA.crl"
  local crl_tmp="$crl.$$.tmp"

  CA_openssl_ca \
    -gencrl \
  >"$crl_tmp" \
  || {
    local rc=$?
    rm -f "$crl_tmp"
    return $rc
  }

  mv "$crl_tmp" "$crl" || return $?
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
