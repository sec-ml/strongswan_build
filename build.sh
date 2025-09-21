#!/usr/bin/env bash
# roadwarrior.sh — minimal IKEv2 VPN build for Debian 13 LXC

set -euo pipefail

### ====== Settings ======
VPN_DOMAIN="${VPN_DOMAIN:-vpn.example.com}"
ORG_NAME="${ORG_NAME:-Example Org}"
POOL_V4="${POOL_V4:-10.10.11.193/26}"
DNS_CSV="${DNS_CSV:-1.1.1.1,9.9.9.9}"
IKE_PROPOSALS="${IKE_PROPOSALS:-aes256gcm16-prfsha384-ecp384}"
ESP_PROPOSALS="${ESP_PROPOSALS:-aes256gcm16-ecp384}"
FULL_TUNNEL="${FULL_TUNNEL:-1}"
LOCAL_SUBNETS="${LOCAL_SUBNETS:-10.10.10.0/22}"
ENABLE_NAT="${ENABLE_NAT:-1}"

### ====== Paths ======
SWAN_DIR="/etc/swanctl"
CA_KEY="$SWAN_DIR/private/ca.key"
CA_CRT="$SWAN_DIR/x509ca/ca.crt"
SRV_KEY="$SWAN_DIR/private/server.key"
SRV_CRT="$SWAN_DIR/x509/server.crt"
CLIENTS_BASE="/var/lib/roadwarrior/clients"
SYSCTL_FILE="/etc/sysctl.d/99-roadwarrior.conf"

### ====== Helpers ======
info(){ echo -e "\033[1;32m[+] $*\033[0m"; }
warn(){ echo -e "\033[1;33m[!] $*\033[0m"; }
die(){ echo -e "\033[1;31m[✗] $*\033[0m"; exit 1; }

ensure_packages() {
  info "Installing packages…"
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    strongswan-starter strongswan-swanctl strongswan-pki \
    libstrongswan-standard-plugins libstrongswan-extra-plugins openssl uuid-runtime \
    iptables-persistent ca-certificates
}

write_strongswan_conf() {
  info "Writing /etc/strongswan.conf …"
  cat >/etc/strongswan.conf <<EOF
charon {
    load_modular = yes
    plugins {
      vici {
          load = yes
      }
      include strongswan.d/charon/*.conf
    }
    filelog {
        charon-log {
            path = /var/log/charon.log
            default = 1
            ike = 2
            knl = 1
        }
        stderr {
            default = 1
            ike = 1
        }
    }
}
EOF
}

enable_forwarding() {
  info "Enabling IPv4 forwarding…"
  cat >"$SYSCTL_FILE" <<EOF
net.ipv4.ip_forward=1
# net.ipv6.conf.all.forwarding=1
EOF
  sysctl -q -p "$SYSCTL_FILE" || true
}

ensure_dirs() {
  mkdir -p "$SWAN_DIR"/{x509ca,x509,private} "$CLIENTS_BASE"
}

ensure_ca_and_server() {
  info "Ensuring CA and server certs…"
  if [[ ! -f "$CA_KEY" ]]; then
    pki --gen --type rsa --size 4096 --outform pem > "$CA_KEY"
  fi
  if [[ ! -f "$CA_CRT" ]]; then
    pki --self --ca --lifetime 3650 --in "$CA_KEY" --type rsa \
      --dn "CN=${ORG_NAME} VPN CA" --outform pem > "$CA_CRT"
  fi
  if [[ ! -f "$SRV_KEY" ]]; then
    pki --gen --type rsa --size 4096 --outform pem > "$SRV_KEY"
  fi
  if [[ ! -f "$SRV_CRT" ]]; then
    TMP_CSR="$(mktemp)"
    pki --req --type rsa --in "$SRV_KEY" \
      --dn "CN=${VPN_DOMAIN}" --san "${VPN_DOMAIN}" --outform pem > "$TMP_CSR"
    pki --issue --cacert "$CA_CRT" --cakey "$CA_KEY" --type rsa --lifetime 1825 \
      --in "$TMP_CSR" --flag serverAuth --flag ikeIntermediate --san "${VPN_DOMAIN}" \
      --outform pem > "$SRV_CRT"
    rm -f "$TMP_CSR"
  fi
}

write_swanctl_conf() {
  local local_ts
  if [[ "$FULL_TUNNEL" == "1" ]]; then
    local_ts="0.0.0.0/0,::/0"
  else
    local_ts="$LOCAL_SUBNETS"
  fi
  info "Writing $SWAN_DIR/swanctl.conf …"
  cat >"$SWAN_DIR/swanctl.conf" <<EOF
connections {
  ikev2-rw {
    version = 2
    local_addrs = %any
    proposals = ${IKE_PROPOSALS}
    unique = keep

    local { auth = pubkey; certs = server.crt; id = @${VPN_DOMAIN} }
    remote { auth = pubkey; id = %any; revocation = strict }

    children {
      net {
        local_ts = ${local_ts}
        start_action = trap
        dpd_action   = trap
        esp_proposals = ${ESP_PROPOSALS}
      }
    }

    pools = rw_pool_v4
    send_cert = always
  }
}
pools {
  rw_pool_v4 {
    addrs = ${POOL_V4}
    dns = ${DNS_CSV}
  }
}
authorities { local_ca { cacert = ca.crt } }
EOF
}

start_and_load() {
  info "Starting strongSwan and loading config…"
  systemctl enable --now strongswan-starter
  swanctl --load-all
}

ensure_nat() {
  [[ "$ENABLE_NAT" == "1" ]] || return 0
  local iface
  iface="$(ip route show default | awk '/default/ {print $5; exit}')"
  if [[ -n "$iface" ]]; then
    info "Adding MASQUERADE for ${POOL_V4} out of ${iface}…"
    if ! iptables -t nat -C POSTROUTING -s "${POOL_V4}" -o "${iface}" -j MASQUERADE 2>/dev/null; then
      iptables -t nat -A POSTROUTING -s "${POOL_V4}" -o "${iface}" -j MASQUERADE
      netfilter-persistent save || true
    fi
  fi
}

add_client() {
  local name="${1:?client NAME required}"
  local local_id="${2:-$1}"
  local cdir="$CLIENTS_BASE/$name"
  mkdir -p "$cdir"

  info "Creating client '$name' (ID: $local_id)…"
  pki --gen --type rsa --size 4096 --outform pem > "$cdir/key.pem"
  pki --req --type rsa --in "$cdir/key.pem" --dn "CN=${name}" --san "$local_id" --outform pem > "$cdir/req.csr"
  pki --issue --cacert "$CA_CRT" --cakey "$CA_KEY" --type rsa --lifetime 730 \
      --in "$cdir/req.csr" --flag clientAuth --outform pem > "$cdir/cert.pem"

  openssl pkcs12 -export -legacy -descert \
    -name "$name" -inkey "$cdir/key.pem" -in "$cdir/cert.pem" -certfile "$CA_CRT" \
    -passout pass: -out "$cdir/$name.p12"

  local uuid_profile uuid_p12 uuid_vpn p12_b64
  uuid_profile="$(uuidgen)"; uuid_p12="$(uuidgen)"; uuid_vpn="$(uuidgen)"
  p12_b64="$(base64 -w0 "$cdir/$name.p12")"

  cat >"$cdir/$name.mobileconfig" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadIdentifier</key><string>${VPN_DOMAIN}.vpn.${name}</string>
  <key>PayloadDisplayName</key><string>${ORG_NAME} VPN (${name})</string>
  <key>PayloadUUID</key><string>${uuid_profile}</string>
  <key>PayloadContent</key><array>
    <dict>
      <key>PayloadType</key><string>com.apple.security.pkcs12</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadIdentifier</key><string>${VPN_DOMAIN}.p12.${name}</string>
      <key>PayloadUUID</key><string>${uuid_p12}</string>
      <key>PayloadDisplayName</key><string>${name} Identity</string>
      <key>PayloadContent</key><data>${p12_b64}</data>
    </dict>
    <dict>
      <key>PayloadType</key><string>com.apple.vpn.managed</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadIdentifier</key><string>${VPN_DOMAIN}.vpn.ikev2.${name}</string>
      <key>PayloadUUID</key><string>${uuid_vpn}</string>
      <key>PayloadDisplayName</key><string>${ORG_NAME} VPN</string>
      <key>UserDefinedName</key><string>${ORG_NAME} VPN</string>
      <key>VPNType</key><string>IKEv2</string>
      <key>IKEv2</key><dict>
        <key>RemoteAddress</key><string>${VPN_DOMAIN}</string>
        <key>RemoteIdentifier</key><string>${VPN_DOMAIN}</string>
        <key>LocalIdentifier</key><string>${local_id}</string>
        <key>ServerCertificateCommonName</key><string>${VPN_DOMAIN}</string>
        <key>AuthenticationMethod</key><string>Certificate</string>
        <key>PayloadCertificateUUID</key><string>${uuid_p12}</string>
      </dict>
    </dict>
  </array></dict></plist>
EOF

  info "Client created: $cdir"
  ls -1 "$cdir"
}

reload_swan() { swanctl --load-all; }
show_status() {
  systemctl status strongswan-starter --no-pager || true
  swanctl --list-conns || true
  swanctl --list-pools || true
}

main() {
  local cmd="${1:-setup}"
  case "$cmd" in
    setup) ensure_packages; write_strongswan_conf; enable_forwarding; ensure_dirs; ensure_ca_and_server; write_swanctl_conf; start_and_load; ensure_nat ;;
    add-client) shift; add_client "$@" ;;
    reload) reload_swan ;;
    status) show_status ;;
    *) die "Unknown command: $cmd" ;;
  esac
}
main "$@"
