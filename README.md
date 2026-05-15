# RouteGhost 👻

A security-focused Python application to temporarily expose local services (Jellyfin, Sonarr, etc.) to the internet using rotating subdomains, dynamic Traefik routing, and automated firewall control. Integrates with **Cloudflare**, **UniFi UDM Pro**, **Traefik (Redis)**, **MQTT**, and **Home Assistant**.

**Note: This project was created with the assistance of AI. Use with caution.**

## ✨ Features

*   **Dynamic Access**: Rotating subdomains and random port generation (1024-65535) for every session.
*   **Security First**: Passkey (WebAuthn) authentication, 2FA (TOTP), and automated firewall toggling.
*   **Routing Flexibility**: Choose between **Cloudflare Proxy** (Standard) or **VPS Gateway** (Ghost Mode) via WireGuard, configurable **per-service**.
*   **Centralized Control**: Manage multiple services from a single dashboard.
*   **Integrations**:
    *   **Cloudflare**: Automated DNS and Origin Rules.
    *   **Traefik**: Dynamic routing via Redis.
    *   **UniFi**: Automatic Port Forwarding management.
    *   **MQTT**: Real-time state updates and Home Assistant Auto Discovery.
*   **Diagnostics**: Built-in tools to verify DNS, Traefik, and Firewall status.

## 🚀 Quick Start

### Docker Compose

1. Clone the repository:
```bash
git clone https://github.com/m1ckyb/RouteGhost.git
cd RouteGhost
```

2.  **Run**:
    ```bash
    docker-compose up -d
    ```

3.  **Initial Setup (5-minute window)**:
    *   Access `http://localhost:5001`.
    *   Register the admin account using a **Passkey** (FaceID, TouchID, YubiKey, or PIN).
    *   Navigate to **Settings** to configure your API keys and integrations.

### Manual Run
```bash
pip install -r requirements.txt
python3 main.py serve
```

## 🔀 Routing Modes

RouteGhost supports two distinct architectural modes for exposing your services:

### 1. Cloudflare Proxy + UniFi (Legacy)
The classic method using Cloudflare's global edge network.
*   **Traffic Flow:** User -> Cloudflare (Orange Cloud) -> UniFi WAN (Port Forward) -> RouteGhost.
*   **Pros:** DDOS protection, hides home IP behind Cloudflare.
*   **Cons:** Requires opening ports on your firewall (automatically managed), relies on Cloudflare decryption.

### 2. VPS Gateway + WireGuard (Ghost Mode)
Bypasses Cloudflare's proxy and your local firewall ingress entirely by tunneling traffic through a remote VPS.
*   **Traffic Flow:** User -> VPS (Port Forward) -> WireGuard Tunnel -> RouteGhost.
*   **Pros:** **Zero open ports** on home firewall, complete bypassing of residential CGNAT, encrypted tunnel, "Grey Cloud" DNS.
*   **Cons:** Requires a Linux VPS (e.g., DigitalOcean, Hetzner).

#### 👻 Ghost Mode Setup Guide

**1. Prepare your VPS**
*   Get a VPS (Ubuntu/Debian recommended).
*   Install WireGuard: `apt install wireguard`.
*   Enable IP Forwarding in `/etc/sysctl.conf`: `net.ipv4.ip_forward=1`.
*   Ensure SSH access is enabled (Key-based auth recommended).

**2. Configure RouteGhost**
*   Go to **Settings** -> **Infrastructure**.
*   **VPS Connection**: Enter Host IP, User (e.g., `root`), and paste your **SSH Private Key**.
*   **WireGuard**:
    *   **Local IP**: `10.0.0.2/24` (or any subnet unused by your networks).
    *   **Local Private Key**: Generate one (`wg genkey`).
    *   **Remote Endpoint**: `YOUR_VPS_IP:51820`.
    *   **Remote Public Key**: The public key of the VPS WireGuard interface.
*   **Per-Service Setup**: When adding or editing a **Service**, select **Routing Mode**: `VPS Gateway (WireGuard)`.

**3. Configure VPS WireGuard Peer**
On your VPS, add RouteGhost as a peer in `/etc/wireguard/wg0.conf`:
```ini
[Peer]
PublicKey = <RouteGhost_Public_Key_From_Settings>
AllowedIPs = 10.0.0.2/32
```
(Restart WireGuard on VPS: `systemctl restart wg-quick@wg0`)

RouteGhost will now automatically connect the tunnel and manage `iptables` forwarding rules on the VPS whenever you turn on a service.

## 🔧 Configuration

Configure these in the Web UI (`/settings`):

| Category | Requirements |
|----------|--------------|
| **Cloudflare** | API Token (DNS/Zone edit), Zone ID, Domain Root, Origin Rule Name |
| **Traefik/Redis** | Host, Port, Password |
| **UniFi** | Host, Credentials, Port Forward Rule Name |
| **MQTT** | Host, Port, Username, Password, Discovery Prefix |

## 📖 Usage

### Web Interface
*   **Dashboard**: Toggle services on/off, rotate URLs, and view status (including Target and Route separation).
*   **Services**: Configure internal URLs, Traefik router names, subdomain prefixes, and **Routing Mode**.
*   **Diagnostics**: Run health checks on any service to verify connectivity.

### API
Authenticate via browser session or `X-API-Key` header.

*   `GET /api/status`: System status.
*   `POST /api/services/{id}/on`: Enable service.
*   `POST /api/services/{id}/off`: Disable service.
*   `POST /api/services/{id}/rotate`: Rotate subdomain/port.
*   `GET /api/services/{id}/diagnose`: Run deep health checks.

## 🔐 Security & Auth

*   **Passkeys**: Uses WebAuthn for passwordless, phishing-resistant login.
*   **Network**: Randomizes ports to evade scanners. Firewall rules are only active when services are enabled.
*   **Production**: If running behind a reverse proxy, set `RP_ID` (e.g., `example.com`) and `ORIGIN` (e.g., `https://example.com`) environment variables.

## 🏗️ Architecture

```
[Web UI] -> [Flask App] -> [SQLite]
               |
               +-> [Redis/Traefik]
               +-> [Cloudflare API]
               +-> [UniFi API]
               +-> [Home Assistant]
```

## 📁 Data Persistence

All configuration is stored in an SQLite database at `/app/data/config.db` inside the container. RouteGhost uses **Named Docker Volumes** (`routeghost_data`) by default to ensure reliability and performance, especially when running on Windows via WSL2.

```yaml
volumes:
  routeghost_data:
```

## 📄 License

This project is open source and available under the **GNU Affero General Public License v3.0 (AGPLv3)**.
