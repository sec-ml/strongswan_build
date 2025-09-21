#!/usr/bin/env bash

# roadwarrior.sh — minimal IKEv2 VPN build for Debian 13 LXC
# Based on sec-ml/strongswan_build with fixes

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
info(){
    echo -e "\033[1;32m[+] $*\033[0m"
}

warn(){
    echo -e "\033[1;33m[!] $*\033[0m"
}

die(){
    echo -e "\033[1;31m[✗] $*\033[0m"
    exit 1
}

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
    cat >/etc/strongswan.conf <<'EOF'
charon {
    load_modular = yes
    plugins {
        vici {
            load = yes
        }
        tpm {
            load = no
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
net.ipv6.conf.all.forwarding=0
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1
EOF
    sysctl -p "$SYSCTL_FILE"
}

ensure_dirs() {
    info "Creating directories…"
    mkdir -p "$SWAN_DIR"/{private,x509ca,x509} "$CLIENTS_BASE"
    chmod 700 "$SWAN_DIR/private"
    
    # Clean up any corrupted files
    info "Cleaning up any corrupted certificate files..."
    rm -f "$SWAN_DIR"/*.srl
    rm -f "$SWAN_DIR"/x509ca/*.srl
    rm -f "$SWAN_DIR"/x509/*.srl
}

ensure_ca_and_server() {
    info "Generating CA and server certificates…"
    
    if [[ ! -f "$CA_KEY" ]]; then
        info "Generating CA private key..."
        if ! pki --gen --type rsa --size 4096 --outform pem --builder rsa > "$CA_KEY" 2>/dev/null; then
            info "PKI failed, using OpenSSL for CA key generation..."
            openssl genrsa -out "$CA_KEY" 4096
        fi
        chmod 600 "$CA_KEY"
    fi
    
    if [[ ! -f "$CA_CRT" ]]; then
        info "Generating CA certificate..."
        if ! pki --self --ca --lifetime 3650 --in "$CA_KEY" --type rsa --builder rsa \
            --dn "CN=${ORG_NAME} VPN CA" --outform pem > "$CA_CRT" 2>/dev/null; then
            info "PKI failed, using OpenSSL for CA certificate generation..."
            openssl req -new -x509 -key "$CA_KEY" -out "$CA_CRT" -days 3650 \
                -subj "/CN=${ORG_NAME} VPN CA"
        fi
        chmod 644 "$CA_CRT"
    fi
    
    if [[ ! -f "$SRV_KEY" ]]; then
        info "Generating server private key..."
        if ! pki --gen --type rsa --size 4096 --outform pem --builder rsa > "$SRV_KEY" 2>/dev/null; then
            info "PKI failed, using OpenSSL for server key generation..."
            openssl genrsa -out "$SRV_KEY" 4096
        fi
        chmod 600 "$SRV_KEY"
    fi
    
    if [[ ! -f "$SRV_CRT" ]]; then
        info "Generating server certificate..."
        TMP_CSR="$(mktemp)"
        if ! pki --req --type rsa --in "$SRV_KEY" --builder rsa \
            --dn "CN=${VPN_DOMAIN}" --san "${VPN_DOMAIN}" --outform pem > "$TMP_CSR" 2>/dev/null; then
            info "PKI failed, using OpenSSL for server certificate request..."
            openssl req -new -key "$SRV_KEY" -out "$TMP_CSR" \
                -subj "/CN=${VPN_DOMAIN}" -addext "subjectAltName=DNS:${VPN_DOMAIN}"
        fi
        
        if ! pki --issue --cacert "$CA_CRT" --cakey "$CA_KEY" --type rsa --builder rsa --lifetime 1825 \
            --in "$TMP_CSR" --flag serverAuth --flag ikeIntermediate --san "${VPN_DOMAIN}" \
            --outform pem > "$SRV_CRT" 2>/dev/null; then
            info "PKI failed, using OpenSSL for server certificate issuance..."
            openssl x509 -req -in "$TMP_CSR" -CA "$CA_CRT" -CAkey "$CA_KEY" \
                -out "$SRV_CRT" -days 1825 -CAcreateserial \
                -extensions v3_req -extfile <(echo -e "[v3_req]\nsubjectAltName=DNS:${VPN_DOMAIN}\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth")
        fi
        chmod 644 "$SRV_CRT"
        rm -f "$TMP_CSR"
    fi
    
    # Verify the keys and certificates are valid
    info "Verifying generated keys and certificates..."
    if ! pki --print --in "$CA_KEY" >/dev/null 2>&1 && ! openssl rsa -in "$CA_KEY" -check -noout >/dev/null 2>&1; then
        die "CA key verification failed"
    fi
    if ! pki --print --in "$SRV_KEY" >/dev/null 2>&1 && ! openssl rsa -in "$SRV_KEY" -check -noout >/dev/null 2>&1; then
        die "Server key verification failed"
    fi
    
    # Verify certificates exist and are valid
    if [ ! -s "$CA_CRT" ]; then
        die "CA certificate is missing or empty"
    fi
    if [ ! -s "$SRV_CRT" ]; then
        die "Server certificate is missing or empty"
    fi
    
    # Test certificate validity
    if ! openssl x509 -in "$CA_CRT" -noout >/dev/null 2>&1; then
        die "CA certificate is invalid"
    fi
    if ! openssl x509 -in "$SRV_CRT" -noout >/dev/null 2>&1; then
        die "Server certificate is invalid"
    fi
    
    # Create symlinks in the main swanctl directory for compatibility
    info "Creating certificate symlinks..."
    ln -sf "$CA_CRT" "$SWAN_DIR/ca.crt"
    ln -sf "$SRV_CRT" "$SWAN_DIR/server.crt"
    ln -sf "$CA_KEY" "$SWAN_DIR/ca.key"
    ln -sf "$SRV_KEY" "$SWAN_DIR/server.key"
    
    info "All certificates and keys verified successfully"
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
    ikev2 {
        local_addrs = 0.0.0.0
        remote_addrs = %any
        local {
            auth = pubkey
            certs = server.crt
        }
        remote {
            auth = pubkey
        }
        children {
            roadwarrior {
                local_ts = $local_ts
                remote_ts = 0.0.0.0/0,::/0
                updown = /usr/lib/strongswan/updown/updown iptables
                esp_proposals = $ESP_PROPOSALS
            }
        }
        version = 2
        proposals = $IKE_PROPOSALS
    }
}

pools {
    rw_pool {
        addrs = $POOL_V4
        dns = $DNS_CSV
    }
}

secrets {
    private {
        file = server.key
    }
}
EOF
}

start_and_load() {
    info "Starting strongSwan and loading configuration…"
    systemctl enable strongswan-starter
    systemctl start strongswan-starter
    
    # Wait for charon to be ready
    info "Waiting for charon daemon to start..."
    local retries=0
    while [ $retries -lt 30 ]; do
        if systemctl is-active --quiet strongswan-starter && [ -S /var/run/charon.vici ]; then
            break
        fi
        sleep 1
        retries=$((retries + 1))
    done
    
    if [ $retries -eq 30 ]; then
        warn "charon daemon may not be ready, but continuing..."
    fi
    
    # Load configuration
    info "Loading swanctl configuration..."
    swanctl --load-all || warn "Failed to load configuration, but continuing..."
}

ensure_nat() {
    if [[ "$ENABLE_NAT" == "1" ]]; then
        info "Setting up NAT…"
        local iface
        iface="$(ip route | grep default | awk '{print $5}' | head -n1)"
        if [[ -n "$iface" ]] && iptables -t nat -C POSTROUTING -s "${POOL_V4}" -o "${iface}" -j MASQUERADE 2>/dev/null; then
            info "NAT rule already exists"
        elif [[ -n "$iface" ]]; then
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
    
    info "Generating client private key..."
    if ! pki --gen --type rsa --size 4096 --outform pem --builder rsa > "$cdir/key.pem" 2>/dev/null; then
        info "PKI failed, using OpenSSL for client key generation..."
        openssl genrsa -out "$cdir/key.pem" 4096
    fi
    chmod 600 "$cdir/key.pem"
    
    info "Generating client certificate request..."
    if ! pki --req --type rsa --in "$cdir/key.pem" --builder rsa --dn "CN=${name}" --san "$local_id" --outform pem > "$cdir/req.csr" 2>/dev/null; then
        info "PKI failed, using OpenSSL for client certificate request..."
        openssl req -new -key "$cdir/key.pem" -out "$cdir/req.csr" \
            -subj "/CN=${name}" -addext "subjectAltName=DNS:${local_id}"
    fi
    
    info "Issuing client certificate..."
    if ! pki --issue --cacert "$CA_CRT" --cakey "$CA_KEY" --type rsa --builder rsa --lifetime 730 \
        --in "$cdir/req.csr" --flag clientAuth --outform pem > "$cdir/cert.pem" 2>/dev/null; then
        info "PKI failed, using OpenSSL for client certificate issuance..."
        openssl x509 -req -in "$cdir/req.csr" -CA "$CA_CRT" -CAkey "$CA_KEY" \
            -out "$cdir/cert.pem" -days 730 -CAcreateserial \
            -extensions v3_req -extfile <(echo -e "[v3_req]\nsubjectAltName=DNS:${local_id}\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth")
    fi
    chmod 644 "$cdir/cert.pem"
    
    # Verify the client key is valid
    if ! pki --print --in "$cdir/key.pem" >/dev/null 2>&1 && ! openssl rsa -in "$cdir/key.pem" -check -noout >/dev/null 2>&1; then
        die "Client key verification failed"
    fi
    
    openssl pkcs12 -export -legacy -descert \
        -name "$name" -inkey "$cdir/key.pem" -in "$cdir/cert.pem" -certfile "$CA_CRT" \
        -passout pass: -out "$cdir/$name.p12"
    
    local uuid_profile uuid_p12 uuid_vpn p12_b64
    uuid_profile="$(uuidgen)"; uuid_p12="$(uuidgen)"; uuid_vpn="$(uuidgen)"
    p12_b64="$(base64 -w0 "$cdir/$name.p12")"
    
    cat >"$cdir/$name.mobileconfig" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadType</key>
            <string>com.apple.security.pkcs12</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>${VPN_DOMAIN}.p12.${name}</string>
            <key>PayloadUUID</key>
            <string>${uuid_p12}</string>
            <key>PayloadDisplayName</key>
            <string>${name}</string>
            <key>Identity</key>
            <data>${p12_b64}</data>
        </dict>
        <dict>
            <key>PayloadType</key>
            <string>com.apple.vpn.managed</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>${VPN_DOMAIN}.vpn.ikev2.${name}</string>
            <key>PayloadUUID</key>
            <string>${uuid_vpn}</string>
            <key>PayloadDisplayName</key>
            <string>${ORG_NAME} VPN</string>
            <key>UserDefinedName</key>
            <string>${ORG_NAME} VPN</string>
            <key>VPNType</key>
            <string>IKEv2</string>
            <key>IKEv2</key>
            <dict>
                <key>RemoteAddress</key>
                <string>${VPN_DOMAIN}</string>
                <key>RemoteIdentifier</key>
                <string>${VPN_DOMAIN}</string>
                <key>LocalIdentifier</key>
                <string>${local_id}</string>
                <key>ServerCertificateCommonName</key>
                <string>${VPN_DOMAIN}</string>
                <key>AuthenticationMethod</key>
                <string>Certificate</string>
                <key>PayloadCertificateUUID</key>
                <string>${uuid_p12}</string>
            </dict>
        </dict>
    </array>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadIdentifier</key>
    <string>${VPN_DOMAIN}.vpn.${name}</string>
    <key>PayloadDisplayName</key>
    <string>${ORG_NAME} VPN (${name})</string>
    <key>PayloadUUID</key>
    <string>${uuid_profile}</string>
</dict>
</plist>
EOF
    
    info "Client created: $cdir"
    ls -1 "$cdir"
}

reload_swan() {
    info "Reloading strongSwan configuration..."
    if [ -S /var/run/charon.vici ]; then
        swanctl --load-all
        info "Configuration reloaded successfully"
    else
        warn "VICI socket not available, starting strongSwan first..."
        systemctl start strongswan-starter
        sleep 3
        if [ -S /var/run/charon.vici ]; then
            swanctl --load-all
            info "Configuration loaded successfully"
        else
            die "Failed to start strongSwan or load configuration"
        fi
    fi
}

show_status() {
    echo "=== StrongSwan Service Status ==="
    systemctl status strongswan-starter --no-pager || true
    
    echo -e "\n=== VICI Socket Status ==="
    if [ -S /var/run/charon.vici ]; then
        echo "✅ VICI socket is available"
    else
        echo "❌ VICI socket not found"
    fi
    
    echo -e "\n=== Connections ==="
    swanctl --list-conns || true
    
    echo -e "\n=== Pools ==="
    swanctl --list-pools || true
    
    echo -e "\n=== Secrets ==="
    swanctl --list-secrets || true
}

show_help() {
    cat <<EOF
StrongSwan IKEv2 VPN Setup Script

USAGE:
    $0 [COMMAND] [OPTIONS]

COMMANDS:
    setup                 Set up strongSwan VPN server (default)
    add-client <name>     Add a new VPN client
    reload                Reload strongSwan configuration
    status                Show strongSwan status and connections
    help                  Show this help message

EXAMPLES:
    $0 setup                    # Initial setup
    $0 add-client john          # Add client named 'john'
    $0 add-client jane jane-id  # Add client with custom ID
    $0 reload                   # Reload configuration
    $0 status                   # Check status

ENVIRONMENT VARIABLES:
    VPN_DOMAIN          VPN server domain (default: vpn.example.com)
    ORG_NAME            Organization name (default: Example Org)
    POOL_V4             Client IP pool (default: 10.10.11.193/26)
    DNS_CSV             DNS servers (default: 1.1.1.1,9.9.9.9)
    IKE_PROPOSALS       IKE proposals (default: aes256gcm16-prfsha384-ecp384)
    ESP_PROPOSALS       ESP proposals (default: aes256gcm16-ecp384)
    FULL_TUNNEL         Full tunnel mode (default: 1)
    LOCAL_SUBNETS       Local subnets to route (default: 10.10.10.0/22)
    ENABLE_NAT          Enable NAT (default: 1)

FILES:
    /etc/swanctl/swanctl.conf           Main configuration
    /etc/swanctl/private/               Private keys
    /etc/swanctl/x509ca/                CA certificates
    /etc/swanctl/x509/                  Server certificates
    /var/lib/roadwarrior/clients/       Client certificates

For more information, see: https://github.com/sec-ml/strongswan_build
EOF
}

main() {
    local cmd="${1:-setup}"
    
    case "$cmd" in
        setup)
            ensure_packages
            write_strongswan_conf
            enable_forwarding
            ensure_dirs
            ensure_ca_and_server
            write_swanctl_conf
            start_and_load
            ensure_nat
            ;;
        add-client)
            shift
            add_client "$@"
            ;;
        reload)
            reload_swan
            ;;
        status)
            show_status
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            echo "Unknown command: $cmd"
            echo "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
}

main "$@"
