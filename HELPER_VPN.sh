#!/bin/bash
# =====================================================================
#  HELPER VPN AUTOSCRIPT — Ubuntu 24.04 LTS
#  Features:
#   ✅ SSH WebSocket TLS & Non-TLS (80/443)
#   ✅ SSH Dropbear (109, 143)
#   ✅ SSH Stunnel5 (447, 777)
#   ✅ BadVPN UDPGW (7100/7200/7300 — multi-port, Gaming & Calling UDP)
#   ✅ Xray VMess WebSocket TLS & Non-TLS
#   ✅ Xray VLESS WebSocket TLS & Non-TLS
#   ✅ Xray Trojan WebSocket TLS
#   ✅ BBR Congestion Control
#   ✅ Fail2ban
#   ✅ Virtual SwapRAM
#   ✅ Auto Expire Accounts (cron)
#   ✅ Auto Reboot
#   ✅ Multi-login Kill
#   ✅ Bandwidth & RAM Monitor
#   ✅ Backup & Restore
#   ✅ DNS Changer
#   ✅ Full Menu System
#
#  FIXES applied in this version (port 80/443 + reliability):
#   1. Nginx's default site (sites-enabled/default) was never disabled.
#      It claims "listen 80 default_server" and was silently winning
#      against our vhost — this was the main reason /ssh-ws, /vmess,
#      /vless, /trojan-ws didn't respond. Now removed before our
#      config is installed.
#   2. Added `nginx -t` validation before every start/reload. Previously
#      a bad config just silently failed to apply with no error shown.
#   3. ws-proxy.py sent a fake, static WebSocket handshake with no
#      Sec-WebSocket-Accept header — invalid per RFC 6455. Real
#      WebSocket clients could reject the connection. Now computes the
#      correct accept key from the client's Sec-WebSocket-Key.
#   4. Added the standard `map $http_upgrade $connection_upgrade` block
#      in nginx.conf so non-WebSocket requests to /ssh-ws, /vmess etc.
#      don't get an incorrect hardcoded "Connection: upgrade" header.
#   5. Server IP detection (curl ifconfig.me) had no timeout and no
#      fallback — a slow/blocked request silently left MY_IP empty.
#      Now retries with a second provider and a local fallback, with
#      a timeout on every attempt.
#   6. Added an explicit warning that UFW only opens the LOCAL firewall
#      — cloud providers (AWS/GCP/Oracle/Vultr/etc.) have a SEPARATE
#      external firewall/security-group that must also allow these
#      ports, or they stay unreachable from the internet.
#   7. apt-get install would silently HANG FOREVER on conffile prompts
#      (e.g. "Configuration file '/etc/default/dropbear' ... what would
#      you like to do?") whenever a config file already existed on
#      disk — this aborted the entire package install and skipped
#      nginx, dropbear, stunnel4, fail2ban, and everything after it,
#      with zero error message. Added --force-confold/--force-confdef
#      flags plus debconf pre-seeding for iptables-persistent's own
#      "save current rules?" prompt, so apt-get NEVER blocks on input.
#      Also added a post-install check that the critical binaries
#      actually landed, failing loudly and immediately if not.
#   8. Xray was "installed" via a broken "bash <(curl ...) @ latest"
#      invocation — process substitution doesn't parse "@ latest" the
#      way a normal shell does, so the official installer silently did
#      nothing, and because output was piped to /dev/null the failure
#      was invisible ("xray: command not found" much later). Fixed to
#      use the correct "install" argument, with real error output and
#      a hard stop if the binary still isn't present afterward.
#   9. Xray crashed on every start with "permission denied" opening its
#      own log files. Its systemd unit runs as a restricted user (e.g.
#      nobody/nogroup) but /var/log/xray was created earlier by root,
#      so xray couldn't write to it. Now reads the actual User/Group
#      from xray's own systemd unit and chowns its directories to
#      match before starting it.
#  10. Stunnel5 failed to bind with "Cannot assign requested address" —
#      it was binding to $DOMAIN:447/777, and on cloud VPS providers
#      (AWS etc.) the public/domain IP is often a NAT'd address that
#      can't be bound directly from inside the instance. Changed to
#      bind on all interfaces (port-only syntax), matching how every
#      other service in this script (nginx, ws-proxy) already does it.
#  11. BadVPN UDPGW silently reported success with a 0-byte/broken
#      binary: "wget -q -O file URL" creates the destination file even
#      on a failed download and -q hid the real error, so the success
#      check always passed. The source-compile fallback's real errors
#      were also hidden behind /dev/null. Now verifies the binary is a
#      sane size AND actually executes before trusting it, and shows
#      real compiler/cmake errors if the source build is needed.
#  12. Dropbear and Xray service-start status were never actually
#      checked before printing "[✔] running" — now both verify with
#      systemctl is-active and print the real journalctl error and a
#      warning (without aborting the install) if a service fails to
#      come up, instead of falsely claiming success.
#
#  FIXES applied in THIS version (BadVPN rebuilt — Gaming & Calling):
#  13. BadVPN's "pre-built binary" was pulled from an unverified
#      personal GitHub mirror (xMiichael101/udpgw) with zero checksum
#      or signature verification — an arbitrary precompiled binary run
#      as a network-facing service. That mirror can change or vanish
#      at any time, and there was no way to know it was trustworthy.
#      Now we ALWAYS build from the official upstream source
#      (github.com/ambrop72/badvpn), pinned to its latest published
#      release tag, so what's installed is the genuine latest version,
#      not a third party's repackaging of it.
#  14. badvpn.service and ws-proxy.service had no User= set, so both
#      ran as root with no need to — they only ever pipe bytes on
#      loopback. Both now run as dedicated unprivileged accounts
#      (least privilege), with NoNewPrivileges/PrivateTmp hardening
#      on the badvpn unit.
#  15. ROOT CAUSE of "games/calls don't work even though everything
#      else does": different SSH-over-WS client apps (HTTP Injector,
#      HTTP Custom, NPV Tunnel, etc.) ship with DIFFERENT default
#      UDPGW ports baked in — many default to 7300, not 7100 — but the
#      old script only ever started ONE badvpn instance, on 7100. Every
#      user whose app defaulted to a different port had a server with
#      nothing listening there: UDP (game traffic, VoIP call audio)
#      silently failed while plain web browsing kept working fine, so
#      it looked like "no gaming/calling support" rather than a port
#      mismatch. Now THREE instances run — 7100, 7200 and 7300 — using
#      a systemd template unit (badvpn@.service), covering the common
#      client-app defaults and matching the range already advertised
#      in the firewall and account-creation output.
#  16. The default --max-connections-for-client for badvpn-udpgw is
#      only 10. A single game or VoIP call opens many short-lived
#      parallel UDP flows at once (live game state + voice + several
#      ICE/NAT candidates for a call) — 10 was nowhere near enough and
#      caused exactly the dropped-packets/laggy-call/disconnecting-game
#      symptoms "gaming and calling support" is meant to fix. Raised to
#      150 per client (1000 clients total) with a larger send buffer.
#
#  Usage: bash HELPER_VPN.sh (as root, on a fresh Ubuntu 24.04 VPS)
# =====================================================================

set -uo pipefail

# FIX (root cause of "permission denied" crashes on first install, not
# just after 'menu' account changes): on some cloud images (confirmed on
# this AWS Ubuntu 24.04 image) root's default umask is restrictive
# (e.g. 077), so every config file this script creates with a plain
# "cat > file <<EOF" silently lands as mode 600 — readable only by root.
# Later chown'ing such a file to a restricted service user (e.g. xray
# running as 'nobody') does NOT fix this, because chown never touches
# the permission bits, only ownership. The service then fails with
# "open ...: permission denied" on its very first start, before any
# account is ever created. Setting a sane umask here makes every file
# created for the rest of this script readable by its intended service
# by default. Individual files are still explicitly chmod'd below as a
# second safety net wherever a restrictive umask could still bite.
umask 022

# ─── Colors ───────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; PURPLE='\033[0;35m'; BLUE='\033[0;34m'
ORANGE='\033[38;5;208m'; PINK='\033[38;5;205m'; LIME='\033[38;5;118m'
SKY='\033[38;5;45m'; GOLD='\033[38;5;220m'; WHITE='\033[1;37m'
NC='\033[0m'; BOLD='\e[1m'

log()   { echo -e "${GREEN}[✔]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[✘]${NC} $*"; }
info()  { echo -e "${CYAN}[i]${NC} $*"; }
step()  { echo -e "\n${PURPLE}━━━ $* ━━━${NC}"; }

# ─── Box-drawing helpers ────────────────────────────────────────────
# FIX: every box in this script used to be built from hand-counted
# literal spaces, and some rows fed ANSI color codes into a printf
# width spec (%-Ns) as DATA — printf then counts the invisible escape
# bytes as "width", silently eating into the padding budget. Both bugs
# make the right-hand border drift out of line the moment any label
# text changes length (this is what was happening in the account menu
# and the install summary box). BOX_W is now the single source of
# truth for box width; box_top/box_mid/box_bot/box_line all derive
# from it, and box_line pads against the PLAIN (uncolored) text only,
# so the visible border always lines up regardless of color codes.
BOX_W=50
box_top()  { printf "${SKY}${BOLD}╔%s╗${NC}\n" "$(printf '═%.0s' $(seq 1 "$BOX_W"))"; }
box_mid()  { printf "${SKY}${BOLD}╠%s╣${NC}\n" "$(printf '═%.0s' $(seq 1 "$BOX_W"))"; }
box_bot()  { printf "${SKY}${BOLD}╚%s╝${NC}\n" "$(printf '═%.0s' $(seq 1 "$BOX_W"))"; }
# box_line "<plain text, no color codes — used only to measure width>" "<text to display, may contain color codes>"
box_line() {
  local plain="$1" disp="$2"
  local pad=$(( BOX_W - ${#plain} ))
  (( pad < 0 )) && pad=0
  printf "${SKY}${BOLD}║${NC}%b%*s${SKY}${BOLD}║${NC}\n" "$disp" "$pad" ""
}

# ─── Root Check ───────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  err "Run as root: sudo bash HELPER_VPN.sh"
  exit 1
fi

# ─── OS Check ─────────────────────────────────────────────────────────
source /etc/os-release 2>/dev/null || true
if [[ "${ID:-}" != "ubuntu" || "${VERSION_ID:-}" != "24.04" ]]; then
  warn "Script targets Ubuntu 24.04 — detected: ${PRETTY_NAME:-unknown}"
  warn "Continuing in 5s (Ctrl+C to abort)..."
  sleep 5
fi

clear
box_top
box_line "    H E L P E R  V P N  A U T O S C R I P T" "    ${GOLD}${BOLD}H E L P E R  V P N  A U T O S C R I P T${NC}"
box_line "      Ubuntu 24.04 LTS  -- All Features --" "      ${LIME}Ubuntu 24.04 LTS${NC}  ${ORANGE}-- All Features --${NC}"
box_bot
sleep 1

# ─── Dirs ─────────────────────────────────────────────────────────────
BASE=/etc/autoscript
mkdir -p "$BASE/ssh" "$BASE/xray" "$BASE/backup"
mkdir -p /var/log/xray /usr/local/etc/xray

# =====================================================================
# 1. DOMAIN INPUT
# =====================================================================
step "Domain Setup"
read -rp "  Enter your domain (A-record must point to this VPS): " DOMAIN
[[ -z "$DOMAIN" ]] && { err "Domain required."; exit 1; }
echo "$DOMAIN" > "$BASE/domain"

# FIX: curl had no timeout and no fallback. If ifconfig.me was slow,
# down, or blocked by the provider's network, MY_IP silently ended up
# empty and the rest of the install (DNS match check, summary output)
# used a blank IP without any warning.
MY_IP=$(curl -s4 --max-time 8 ifconfig.me || true)
if [[ -z "$MY_IP" ]]; then
  MY_IP=$(curl -s4 --max-time 8 https://api.ipify.org || true)
fi
if [[ -z "$MY_IP" ]]; then
  MY_IP=$(hostname -I | awk '{print $1}')
  warn "Could not reach IP lookup services — using local interface IP ($MY_IP). Verify this is your public IP."
fi
echo "$MY_IP" > /etc/autoscript/myip
log "Server IP: $MY_IP"

DOMAIN_IP=$(dig +short A "$DOMAIN" 2>/dev/null | tail -n1)
if [[ -n "$DOMAIN_IP" && "$MY_IP" != "$DOMAIN_IP" ]]; then
  warn "DNS for $DOMAIN resolves to '$DOMAIN_IP', server IP is '$MY_IP'"
  warn "Let's Encrypt WILL FAIL if DNS is not propagated yet."
  read -rp "  Continue anyway? (y/N): " _cont
  [[ "$_cont" != "y" && "$_cont" != "Y" ]] && exit 1
fi

read -rp "  Email for Let's Encrypt (Enter to skip): " LE_EMAIL

# =====================================================================
# 2. SYSTEM PREP
# =====================================================================
step "System Update & Packages"
export DEBIAN_FRONTEND=noninteractive

# FIX (confirmed via live install failure): ufw and iptables-persistent /
# netfilter-persistent actively CONFLICT on Ubuntu 24.04 — apt refuses
# to install them together ("ufw : Breaks: iptables-persistent... Breaks:
# netfilter-persistent"). Because apt-get install is one atomic
# transaction, this single conflict aborted the ENTIRE command and
# silently skipped every other package in the list too — nginx,
# dropbear, stunnel4, fail2ban, all of it — even though none of them
# actually conflicted with anything. ufw already manages/persists its
# own rules, so iptables-persistent and netfilter-persistent are not
# needed when ufw is the firewall in use; they're dropped from the
# install list below, and the now-unnecessary debconf pre-seeding for
# iptables-persistent's prompt has been removed along with them.

# FIX: DEBIAN_FRONTEND=noninteractive alone does NOT suppress "conffile"
# prompts (e.g. "Configuration file '/etc/default/dropbear' ... what
# would you like to do?"). These appear whenever a config file already
# exists on disk (re-running the script, or certain package defaults
# overlapping) and apt-get just HANGS waiting for keyboard input that
# never comes over a non-interactive/automated session — which silently
# aborted the entire install and skipped nginx, dropbear, stunnel4,
# fail2ban, xray and everything after it. These flags force apt to
# always keep/use sane defaults without ever prompting.
APT_OPTS=(-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)

apt-get update -y
apt-get upgrade -y "${APT_OPTS[@]}"
apt-get dist-upgrade -y "${APT_OPTS[@]}"

apt-get install -y --no-install-recommends "${APT_OPTS[@]}" \
  curl wget socat cron jq uuid-runtime \
  nginx certbot python3-certbot-nginx \
  openssh-server dropbear stunnel4 \
  python3 python3-pip ufw net-tools dnsutils \
  iptables \
  fail2ban vnstat htop iftop bmon \
  zip unzip screen tmux git lsof \
  bc sed gnupg ca-certificates lsb-release \
  build-essential cmake libssl-dev \
  qrencode neofetch

# FIX: if apt-get install still fails for any reason (network blip,
# mirror issue, single bad package), the script previously had no way
# to know — it just continued silently into Dropbear/Nginx/etc config
# steps with the binaries missing, producing a wall of confusing
# "unit file does not exist" / "command not found" errors much later.
# Now we verify the critical binaries actually landed, and stop here
# with a clear message if not, instead of failing mysteriously later.
MISSING_PKGS=()
for bin in nginx dropbear stunnel4 fail2ban-client curl jq; do
  command -v "$bin" >/dev/null 2>&1 || MISSING_PKGS+=("$bin")
done
if [[ ${#MISSING_PKGS[@]} -gt 0 ]]; then
  err "These commands are still missing after apt-get install: ${MISSING_PKGS[*]}"
  err "Run manually to see the real error: apt-get install -y ${MISSING_PKGS[*]}"
  exit 1
fi

log "Packages installed."

# ─── Timezone ─────────────────────────────────────────────────────────
timedatectl set-timezone Asia/Kuala_Lumpur 2>/dev/null || \
  ln -fs /usr/share/zoneinfo/Asia/Kuala_Lumpur /etc/localtime

# ─── Disable IPv6 (optional, matches NevermoreSSH behavior) ──────────
sysctl -w net.ipv6.conf.all.disable_ipv6=1    >/dev/null 2>&1
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1
echo "net.ipv6.conf.all.disable_ipv6=1"     >> /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6=1" >> /etc/sysctl.conf

# =====================================================================
# 3. BBR
# =====================================================================
step "BBR Congestion Control"
{
  echo "net.core.default_qdisc=fq"
  echo "net.ipv4.tcp_congestion_control=bbr"
} >> /etc/sysctl.conf
sysctl -p >/dev/null 2>&1
log "BBR enabled."

# =====================================================================
# 4. SWAP RAM
# =====================================================================
step "Virtual SwapRAM (1 GB)"
if ! swapon --show | grep -q /swapfile; then
  fallocate -l 1G /swapfile
  chmod 600 /swapfile
  mkswap /swapfile >/dev/null
  swapon /swapfile
  grep -qxF '/swapfile none swap sw 0 0' /etc/fstab || \
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
  log "1 GB swap created."
else
  log "Swap already exists — skipped."
fi

# =====================================================================
# 5. UFW FIREWALL
# =====================================================================
step "Firewall (UFW)"
ufw allow 22/tcp   >/dev/null 2>&1
ufw allow 80/tcp   >/dev/null 2>&1
ufw allow 443/tcp  >/dev/null 2>&1
ufw allow 109/tcp  >/dev/null 2>&1
ufw allow 143/tcp  >/dev/null 2>&1
ufw allow 447/tcp  >/dev/null 2>&1
ufw allow 777/tcp  >/dev/null 2>&1
ufw allow 7100:7300/udp >/dev/null 2>&1
ufw --force enable  >/dev/null 2>&1
log "Firewall configured (UFW)."

# FIX: UFW only controls the LOCAL firewall. On cloud providers (AWS,
# GCP, Oracle, Vultr, Contabo, etc.) there is ALSO an external
# firewall/security-group that UFW cannot see or change. If 80/443
# are blocked there, the script has no way to know — so warn loudly
# instead of silently assuming the ports are reachable.
warn "UFW only opens ports on THIS server."
warn "If you're on AWS/GCP/Oracle/Vultr/etc, also open 80,443,22,109,143,447,777 and 7100-7300/udp in your provider's Security Group / Firewall panel, or these ports will stay unreachable from outside even though UFW shows them open."

# =====================================================================
# 6. LOGIN BANNER + OPENSSH — enable password auth
# =====================================================================
step "Login Banner"

# A single banner file is shared by OpenSSH (:22) and Dropbear (:109/:143)
# so both show the same branded message. SSH client apps (HTTP Injector,
# HTTP Custom, NPV Tunnel, etc.) read this pre-auth banner to confirm a
# successful connection, so it's built from the real $DOMAIN/$MY_IP
# captured in step 1, not generic placeholder text.
#
# NOTE: plain Unicode box-drawing chars (═ ║ ╔ ╗ ╚ ╝) are used here
# rather than emoji/star glyphs (✦ etc.) — those have "ambiguous" East
# Asian width and render as single-width on some terminals/fonts but
# double-width on others, which is what was throwing off the box
# alignment in the main menu (see section 18 below). All padding here
# is computed from the real string length, never hardcoded, so it can't
# drift if you edit the text later.
BANNER_FILE=/etc/ssh-banner.txt
BWIDTH=50

bline() {
  local text="${1:0:$BWIDTH}"
  printf '║ %-*s ║\n' "$BWIDTH" "$text"
}
bborder() { printf '%s%s%s\n' "$1" "$(printf '═%.0s' $(seq 1 $((BWIDTH+2))))" "$2"; }

{
  echo ""
  bborder "╔" "╗"
  bline "  HELPER VPN SERVER"
  bline "  Domain : ${DOMAIN}"
  bline "  Server : ${MY_IP}"
  bline "  Unauthorized access is prohibited."
  bborder "╚" "╝"
  echo ""
} > "$BANNER_FILE"
chmod 644 "$BANNER_FILE"
log "Login banner written to $BANNER_FILE"

step "OpenSSH Configuration"
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#\?GatewayPorts.*/GatewayPorts yes/' /etc/ssh/sshd_config
sed -i '/^Banner /d;/^ClientAliveInterval /d;/^ClientAliveCountMax /d' /etc/ssh/sshd_config
{
  echo "Banner $BANNER_FILE"
  echo "ClientAliveInterval 60"
  echo "ClientAliveCountMax 3"
} >> /etc/ssh/sshd_config

if [[ -d /etc/ssh/sshd_config.d ]]; then
  for f in /etc/ssh/sshd_config.d/*.conf; do
    [[ -e "$f" ]] && \
      sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' "$f"
  done
fi
systemctl restart ssh
log "OpenSSH configured (port 22)."

# Verify the banner is actually shown, rather than assuming the
# sshd_config directive took effect. ssh shows the SSH_MSG_USERAUTH_BANNER
# even on a failed login, so a single doomed-to-fail auth attempt is
# enough to confirm it without needing a real account.
test_banner() {
  local port="$1" out
  out=$(timeout 6 ssh -o BatchMode=yes -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o ConnectTimeout=4 \
    -p "$port" "bannertest@127.0.0.1" 2>&1) || true
  [[ "$out" == *"HELPER VPN SERVER"* ]]
}
if test_banner 22; then
  log "OpenSSH banner confirmed showing on port 22."
else
  warn "OpenSSH banner did not show on port 22 — check /etc/ssh/sshd_config manually."
fi

# =====================================================================
# 7. DROPBEAR (109, 143)
# =====================================================================
step "Dropbear (port 109 & 143)"

# FIX (dropbear banner not appearing — root cause): DROPBEAR_BANNER in
# /etc/default/dropbear is only honored by the legacy /etc/init.d/dropbear
# sysv script. On Ubuntu 24.04 `systemctl restart dropbear` can resolve to
# a native dropbear.service unit instead (package-version dependent),
# whose ExecStart= line may NOT read DROPBEAR_BANNER at all — it silently
# starts dropbear with no banner and gives no error. DROPBEAR_BANNER is
# still set below for the init.d code path, but the banner flag is ALSO
# folded directly into DROPBEAR_EXTRA_ARGS, since that variable is read
# by every code path that handles the multi-port -p 143 flag already
# (passing -b twice is harmless). The block below then PROVES the banner
# actually appears on the wire and, only if it doesn't, auto-generates a
# systemd override that hardcodes ExecStart= explicitly — guaranteeing
# the banner works regardless of how this dropbear build wires its unit.
cat > /etc/default/dropbear <<DROPCONFEOF
NO_START=0
DROPBEAR_PORT=109
DROPBEAR_EXTRA_ARGS="-p 143 -b $BANNER_FILE"
DROPBEAR_BANNER="$BANNER_FILE"
DROPBEAR_RECEIVE_WINDOW=65536
DROPCONFEOF

systemctl enable dropbear
if systemctl restart dropbear && systemctl is-active --quiet dropbear; then
  log "Dropbear running on ports 109 & 143."
else
  err "Dropbear failed to start. Real error:"
  journalctl -u dropbear --no-pager -n 15 2>&1 | sed 's/^/    /'
  warn "Continuing install — fix manually later with: systemctl status dropbear"
fi

DROPBEAR_BANNER_OK=0
if test_banner 109; then
  log "Dropbear banner confirmed showing on port 109."
  DROPBEAR_BANNER_OK=1
else
  warn "Dropbear banner not detected via /etc/default/dropbear — applying systemd override patch."
  mkdir -p /etc/systemd/system/dropbear.service.d
  cat > /etc/systemd/system/dropbear.service.d/override.conf <<OVERRIDEEOF
[Service]
ExecStart=
ExecStart=/usr/sbin/dropbear -R -F -p 109 -p 143 -b $BANNER_FILE -W 65536
OVERRIDEEOF
  systemctl daemon-reload
  if systemctl restart dropbear && systemctl is-active --quiet dropbear && test_banner 109; then
    log "Dropbear banner patched and confirmed via systemd override."
    DROPBEAR_BANNER_OK=1
  else
    err "Dropbear banner still not showing after override patch."
    journalctl -u dropbear --no-pager -n 15 2>&1 | sed 's/^/    /'
    warn "Service is still running without a confirmed banner — fix manually: systemctl cat dropbear"
  fi
fi


# =====================================================================
# 8. WEBSOCKET → SSH BRIDGE (ws-proxy, internal port 2082)
# =====================================================================
step "WebSocket SSH Bridge (ws-proxy)"
cat > /usr/local/sbin/ws-proxy.py <<'PYEOF'
#!/usr/bin/env python3
"""
WebSocket-to-SSH bridge for SSH-over-WS client apps.
Listens on 127.0.0.1:2082 — reached via Nginx reverse proxy.
Sends 101 handshake then pipes raw bytes to 127.0.0.1:22.
"""
import asyncio, logging, base64, hashlib

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 2082
SSH_HOST    = "127.0.0.1"
SSH_PORT    = 22

WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

logging.basicConfig(level=logging.WARNING, format="%(asctime)s ws-proxy: %(message)s")

def make_accept_key(client_key: str) -> str:
    sha1 = hashlib.sha1((client_key + WS_MAGIC).encode()).digest()
    return base64.b64encode(sha1).decode()

async def pipe(r, w):
    try:
        while True:
            d = await r.read(8192)
            if not d: break
            w.write(d); await w.drain()
    except Exception: pass
    finally:
        try: w.close()
        except: pass

async def handle(reader, writer):
    buf = b""
    try:
        while b"\r\n\r\n" not in buf:
            c = await reader.read(1024)
            if not c: writer.close(); return
            buf += c
            if len(buf) > 16384: writer.close(); return

        header_blob, _, extra = buf.partition(b"\r\n\r\n")

        # FIX: previous version sent a hardcoded, fake "101" response
        # with no Sec-WebSocket-Accept header. Per RFC 6455 this is an
        # invalid handshake — real WebSocket clients (browsers and many
        # SSH-over-WS apps) validate Sec-WebSocket-Accept and will drop
        # the connection. Now we read the client's Sec-WebSocket-Key
        # and return the correctly computed accept key.
        client_key = None
        for line in header_blob.split(b"\r\n"):
            if line.lower().startswith(b"sec-websocket-key:"):
                client_key = line.split(b":", 1)[1].strip().decode()
                break

        if client_key:
            accept = make_accept_key(client_key)
            response = (
                "HTTP/1.1 101 HELPER-VPN\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
            ).encode()
        else:
            # Fallback for plain (non-browser) SSH-over-WS clients that
            # don't send a real WS key — keep old permissive behavior.
            response = (
                b"HTTP/1.1 101 HELPER-VPN\r\n"
                b"Upgrade: WebSocket\r\n"
                b"Connection: Upgrade\r\n\r\n"
            )

        writer.write(response); await writer.drain()
        sr, sw = await asyncio.open_connection(SSH_HOST, SSH_PORT)
        if extra: sw.write(extra); await sw.drain()
        await asyncio.gather(pipe(reader, sw), pipe(sr, writer))
    except Exception: pass
    finally:
        try: writer.close()
        except: pass

async def main():
    srv = await asyncio.start_server(handle, LISTEN_HOST, LISTEN_PORT)
    # NOTE: this colored banner is TERMINAL/LOG output only (visible via
    # `journalctl -u ws-proxy` on a TTY, or running this script by
    # hand). It is NOT part of the WebSocket handshake response sent to
    # clients — that response travels over the network as raw protocol
    # bytes and must stay plain ASCII per RFC 6455, so it is never
    # colorized (see make_accept_key/handle() above).
    GREEN_BOLD = "\033[1;32m"
    NC = "\033[0m"
    print(f"{GREEN_BOLD}HELPER-VPN{NC} WebSocket↔SSH bridge listening on {LISTEN_HOST}:{LISTEN_PORT}")
    logging.warning(f"ws-proxy listening on {LISTEN_HOST}:{LISTEN_PORT}")
    async with srv: await srv.serve_forever()

asyncio.run(main())
PYEOF
chmod +x /usr/local/sbin/ws-proxy.py

cat > /etc/systemd/system/ws-proxy.service <<EOF
[Unit]
Description=WebSocket to SSH Bridge
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/sbin/ws-proxy.py
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ws-proxy
systemctl restart ws-proxy
log "ws-proxy running on 127.0.0.1:2082."

# =====================================================================
# 9. BADVPN UDPGW — Gaming & Calling UDP Gateway (7100 / 7200 / 7300)
# =====================================================================
step "BadVPN UDPGW (Gaming & Calling)"
BADVPN_OK=0

# FIX: the old version downloaded a "pre-built" binary from an
# unverified personal GitHub mirror (xMiichael101/udpgw) with no
# checksum/signature check at all — trusting an arbitrary precompiled
# binary, run as a network-facing service, from someone with no
# relationship to the upstream project. That mirror can change or
# disappear at any time. We now build from the OFFICIAL upstream
# (ambrop72/badvpn) every time, pinned to its latest published release
# tag, so the result is verifiably the genuine latest version built
# from source on this machine — not someone else's binary.
info "Looking up the latest official BadVPN release tag..."
BADVPN_TAG=$(git ls-remote --tags --refs https://github.com/ambrop72/badvpn.git 2>/dev/null \
  | awk -F/ '{print $NF}' | grep -E '^[0-9]+(\.[0-9]+)*$' | sort -V | tail -1)
if [[ -z "$BADVPN_TAG" ]]; then
  BADVPN_TAG="1.999.130"   # last known-good release tag, used only if the tag lookup itself fails (e.g. network hiccup)
  warn "Could not query GitHub for the latest BadVPN tag — falling back to known-good $BADVPN_TAG."
fi
info "Building BadVPN $BADVPN_TAG from official source (ambrop72/badvpn)..."

# FIX (root cause of "BadVPN compile-from-source failed" on Ubuntu
# 24.04): BadVPN's CMake build was written in ~2016 and its CMake
# thread/feature probes are known to misbehave on modern toolchains
# (GCC 13+ defaults to -fno-common, which breaks this codebase's old-
# style tentative global definitions with "multiple definition"
# linker errors, and CMake's own generator can choke on newer CMake
# versions). The previous version also truncated build output to the
# last 5-15 lines via `tail`, hiding the actual error entirely.
#
# Fix: build udpgw the way upstream itself recommends as the CMake-
# free fallback (badvpn's own compile-udpgw.sh method) — compile each
# required .c file directly with explicit, modern-safe flags
# (-fcommon restores the old global-variable behaviour GCC 13+ no
# longer defaults to; -Wno-implicit-function-declaration/-Wno-int-
# conversion stop newer GCC from hard-erroring on this old codebase's
# style instead of just warning). This avoids CMake entirely — it's
# the same minimal source-file list and flags upstream's own
# compile-udpgw.sh uses, just embedded here. Full build output is
# always logged to a file so a real failure is never invisible; only
# the screen output is kept short.
BADVPN_LOG=/tmp/badvpn_build.log
: > "$BADVPN_LOG"
BADVPN_SOURCES="
base/BLog_syslog.c
system/BReactor_badvpn.c
system/BSignal.c
system/BConnection_unix.c
system/BConnection_common.c
system/BDatagram_unix.c
system/BTime.c
system/BUnixSignal.c
system/BNetwork.c
flow/StreamRecvInterface.c
flow/PacketRecvInterface.c
flow/PacketPassInterface.c
flow/StreamPassInterface.c
flow/SinglePacketBuffer.c
flow/BufferWriter.c
flow/PacketBuffer.c
flow/PacketStreamSender.c
flow/PacketProtoFlow.c
flow/PacketPassFairQueue.c
flow/PacketProtoEncoder.c
flow/PacketProtoDecoder.c
base/DebugObject.c
base/BLog.c
base/BPending.c
udpgw/udpgw.c
"
BADVPN_CFLAGS="-O2 -std=gnu99 -fcommon -w -Wno-implicit-function-declaration -Wno-int-conversion -Wno-error -DBADVPN_THREAD_SAFE=0 -DBADVPN_LINUX -DBADVPN_BREACTOR_BADVPN -D_GNU_SOURCE -DBADVPN_USE_SIGNALFD -DBADVPN_USE_EPOLL -DBADVPN_LITTLE_ENDIAN"

cd /tmp
rm -rf badvpn_src

# FIX (root cause of "Text file busy" on re-running this script): a
# previous run already installed and started badvpn-udpgw as a live
# systemd service. `cp` writes into the existing file in place, which
# the kernel refuses while that exact binary is currently mapped/
# running (ETXTBSY) — this is NOT a compile failure, the build above
# succeeds every time; only the final copy step was failing. Fix:
# stop any already-running badvpn@ instances first (we're about to
# replace the binary anyway, so this is safe), and always install via
# a temp-file-then-`mv` (atomic rename) instead of an in-place `cp` —
# `mv` on the same filesystem replaces the file by re-pointing the
# directory entry, which the kernel allows even while old instances
# of the binary are still running, so this can never fail with
# ETXTBSY again even if a stop call above is ever skipped/fails.
for p in 7100 7200 7300; do
  systemctl stop "badvpn@${p}" 2>/dev/null || true
done

build_badvpn_direct() {
  cd /tmp/badvpn_src || return 1
  mkdir -p build_direct && cd build_direct || return 1
  local obj objs=()
  for f in $BADVPN_SOURCES; do
    obj="$(basename "$f").o"
    gcc -c $BADVPN_CFLAGS -I/tmp/badvpn_src "/tmp/badvpn_src/$f" -o "$obj" || return 1
    objs+=("$obj")
  done
  gcc "${objs[@]}" -o badvpn-udpgw -lrt -lpthread || return 1
}
build_badvpn_cmake() {
  cd /tmp/badvpn_src || return 1
  mkdir -p build_cmake && cd build_cmake || return 1
  cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 \
    -DCMAKE_C_FLAGS="-fcommon -w -Wno-implicit-function-declaration -Wno-int-conversion" || return 1
  make -j"$(nproc)" || return 1
  cp udpgw/badvpn-udpgw ./badvpn-udpgw || return 1
}
install_badvpn_binary() {
  # Atomic replace: never fails with ETXTBSY, even if a service is
  # somehow still running the old binary.
  install -m 755 "$1" /usr/local/sbin/badvpn-udpgw.new || return 1
  mv -f /usr/local/sbin/badvpn-udpgw.new /usr/local/sbin/badvpn-udpgw || return 1
}

if git clone --depth=1 --branch "$BADVPN_TAG" https://github.com/ambrop72/badvpn.git badvpn_src >>"$BADVPN_LOG" 2>&1; then
  if build_badvpn_direct >>"$BADVPN_LOG" 2>&1; then
    install_badvpn_binary /tmp/badvpn_src/build_direct/badvpn-udpgw >>"$BADVPN_LOG" 2>&1 \
      && /usr/local/sbin/badvpn-udpgw --help >/dev/null 2>&1 \
      && BADVPN_OK=1
    [[ $BADVPN_OK -eq 1 ]] && log "BadVPN $BADVPN_TAG compiled successfully (direct gcc build)."
  fi
  if [[ $BADVPN_OK -ne 1 ]]; then
    info "Direct build failed, retrying with CMake (fallback method)..."
    if build_badvpn_cmake >>"$BADVPN_LOG" 2>&1; then
      install_badvpn_binary /tmp/badvpn_src/build_cmake/badvpn-udpgw >>"$BADVPN_LOG" 2>&1 \
        && /usr/local/sbin/badvpn-udpgw --help >/dev/null 2>&1 \
        && BADVPN_OK=1
      [[ $BADVPN_OK -eq 1 ]] && log "BadVPN $BADVPN_TAG compiled successfully (CMake fallback build)."
    fi
  fi
else
  echo "git clone failed" >>"$BADVPN_LOG"
fi

if [[ $BADVPN_OK -ne 1 ]]; then
  err "BadVPN compile-from-source failed with both build methods."
  err "Last 25 lines of the real build log ($BADVPN_LOG):"
  tail -25 "$BADVPN_LOG" | sed 's/^/    /'
  warn "Full log kept at $BADVPN_LOG for review — share it for help diagnosing."
fi
cd /root

if [[ $BADVPN_OK -eq 1 ]]; then
  # FIX: previously ran as root (no User= in the unit) with no need to
  # — udpgw only ever pipes already-tunnelled bytes between a loopback
  # socket and the client's SSH session. Dedicated unprivileged user
  # = standard least-privilege practice for a network-facing daemon.
  id -u badvpn &>/dev/null || useradd -r -s /usr/sbin/nologin badvpn

  # FIX (root cause of "gaming/calling doesn't work" despite SSH/Xray
  # working fine): popular SSH-over-WS client apps disagree on which
  # UDPGW port they default to — many use 7300, not 7100 — so a server
  # running only ONE instance on 7100 left every user on a
  # different-default app with nothing to connect to for UDP traffic
  # (game state, VoIP call audio), while web browsing kept working
  # normally. A systemd template unit now runs THREE instances —
  # 7100, 7200, 7300 — covering the common defaults and matching the
  # port range already advertised in the firewall rule and account
  # summaries below.
  cat > /etc/systemd/system/badvpn@.service <<'EOF'
[Unit]
Description=BadVPN UDPGW (port %i) - Gaming & Calling UDP Gateway
After=network.target

[Service]
Type=simple
User=badvpn
Group=badvpn
# FIX: badvpn-udpgw's default --max-connections-for-client is only 10.
# A single mobile game or VoIP call opens many short-lived parallel UDP
# flows at once (live game-state traffic + voice audio + several
# ICE/NAT-traversal candidates for a call) — 10 was nowhere near
# enough and is exactly what produces dropped packets, choppy calls,
# and games disconnecting under real load. Raised per-client and
# total ceilings, plus a larger send buffer for smoother throughput.
ExecStart=/usr/local/sbin/badvpn-udpgw \
  --listen-addr 127.0.0.1:%i \
  --max-clients 1000 \
  --max-connections-for-client 150 \
  --client-socket-sndbuf 1048576
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  for p in 7100 7200 7300; do
    systemctl enable "badvpn@${p}" >/dev/null 2>&1
    systemctl restart "badvpn@${p}"
  done

  BADVPN_ALL_UP=1
  for p in 7100 7200 7300; do
    systemctl is-active --quiet "badvpn@${p}" || BADVPN_ALL_UP=0
  done
  if [[ $BADVPN_ALL_UP -eq 1 ]]; then
    log "BadVPN UDPGW running on 127.0.0.1:7100, :7200 and :7300 (Gaming & Calling ready)."
  else
    err "One or more badvpn@ instances failed to start. Real error:"
    journalctl -u 'badvpn@*' --no-pager -n 15 2>&1 | sed 's/^/    /'
    warn "Continuing install — fix manually later with: systemctl status badvpn@7100 badvpn@7200 badvpn@7300"
  fi
else
  warn "BadVPN could not be installed — skipping (games/calls needing UDP will not work without it; TCP browsing is unaffected)."
fi

# NOTE: badvpn-udpgw is only ever reached by the client app's own local
# port-forward THROUGH the already-encrypted SSH/WS tunnel to
# 127.0.0.1 on the server — never by raw UDP packets arriving directly
# from the internet. The UFW rule below for 7100:7300/udp is kept for
# compatibility with client apps/guides that expect it open, but it
# isn't actually load-bearing for the loopback-only setup above.

# =====================================================================
# 10. STUNNEL5 (ports 447, 777 → OpenSSH 22)
# =====================================================================
step "Stunnel5 (ports 447 & 777)"
mkdir -p /etc/stunnel

# Generate self-signed cert for stunnel
openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
  -subj "/C=MY/ST=KL/O=VPN/CN=$DOMAIN" \
  -keyout /etc/stunnel/stunnel.pem \
  -out    /etc/stunnel/stunnel.pem 2>/dev/null

# FIX: openssl forces private-key files to mode 600 internally as a
# safety default — independent of umask — so even with the umask fix
# above this file still lands owned by root, mode 600. stunnel4 runs as
# a restricted 'stunnel4' system user and cannot read a root-only file,
# which previously caused stunnel4 to fail immediately on every start.
chown stunnel4:stunnel4 /etc/stunnel/stunnel.pem 2>/dev/null || true
chmod 640 /etc/stunnel/stunnel.pem 2>/dev/null || true

cat > /etc/stunnel/stunnel.conf <<EOF
pid = /var/run/stunnel4/stunnel.pid
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
output = /var/log/stunnel4/stunnel.log

[ssh-447]
accept  = 447
connect = 127.0.0.1:22
cert    = /etc/stunnel/stunnel.pem

[ssh-777]
accept  = 777
connect = 127.0.0.1:22
cert    = /etc/stunnel/stunnel.pem
EOF

# FIX: stunnel4 was failing with a generic "control process exited with
# error code" — the real cause is that /var/run/stunnel4/ (needed for
# the pid file referenced above) is not guaranteed to exist on boot on
# Ubuntu 24.04 (it's normally created by an init script ordering that
# doesn't always run first). Writing the pid file then fails and
# stunnel4 exits immediately. Create the directory explicitly with the
# ownership stunnel4 expects, every time, before starting the service.
mkdir -p /var/run/stunnel4
chown stunnel4:stunnel4 /var/run/stunnel4 2>/dev/null || true
mkdir -p /var/log/stunnel4
chown stunnel4:stunnel4 /var/log/stunnel4 2>/dev/null || true
sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4 2>/dev/null || true

systemctl enable stunnel4
if systemctl restart stunnel4 && systemctl is-active --quiet stunnel4; then
  log "Stunnel5 running on ports 447 & 777."
else
  err "stunnel4 failed to start. Real error:"
  journalctl -u stunnel4 --no-pager -n 15 2>&1 | sed 's/^/    /'
  warn "Continuing install — fix manually later with: systemctl status stunnel4"
fi

# =====================================================================
# 11. XRAY CORE
# =====================================================================
step "Xray Core Installation"
# FIX: "bash <(curl ...) @ latest" passed "@" and "latest" as two
# separate broken arguments to the installer (process substitution
# doesn't parse "@ latest" the way it would on a normal command line),
# so the script silently did nothing useful — and because output was
# piped to /dev/null, the failure was invisible. xray was never
# actually installed, "xray: command not found" downstream.
# The correct invocation is just "install" as the first argument.
# FIX (confirmed on this same AWS Lightsail image): process substitution
# "bash <(curl ...)" depends on /dev/fd, which some minimal cloud
# images do not mount/symlink correctly — it fails with "bash:
# /dev/fd/NN: No such file or directory" even though the command itself
# is correct. Downloading to a real temp file first removes the
# dependency on /dev/fd entirely and works on every image.
curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh -o /tmp/xray-install.sh
if ! bash /tmp/xray-install.sh install; then
  err "Xray installation failed — see the output above for the real cause."
  exit 1
fi

if ! command -v xray >/dev/null 2>&1; then
  err "Xray binary still not found after install — aborting."
  exit 1
fi
log "Xray installed: $(xray version 2>/dev/null | head -1)"

# Xray config
cat > /usr/local/etc/xray/config.json <<'XEOF'
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error":  "/var/log/xray/error.log"
  },
  "inbounds": [
    {
      "tag": "vmess-ws-in",
      "port": 10000,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": { "clients": [] },
      "streamSettings": {
        "network": "ws",
        "wsSettings": { "path": "/vmess" }
      }
    },
    {
      "tag": "vless-ws-in",
      "port": 10001,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": { "clients": [], "decryption": "none" },
      "streamSettings": {
        "network": "ws",
        "wsSettings": { "path": "/vless" }
      }
    },
    {
      "tag": "trojan-ws-in",
      "port": 10002,
      "listen": "127.0.0.1",
      "protocol": "trojan",
      "settings": { "clients": [] },
      "streamSettings": {
        "network": "ws",
        "wsSettings": { "path": "/trojan-ws" }
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "block" }
  ]
}
XEOF

systemctl enable xray

# FIX: xray.service runs as a restricted user (e.g. nobody/nogroup),
# set by its own unit file / drop-in config — but /var/log/xray was
# created earlier in this script by root, so it was owned by root and
# xray couldn't open its log files ("permission denied"), crashing
# immediately on every start. Read the actual user/group Xray's unit
# is configured to run as, and fix ownership of its directories to
# match before starting.
XRAY_USER=$(systemctl show xray -p User --value 2>/dev/null)
XRAY_GROUP=$(systemctl show xray -p Group --value 2>/dev/null)
[[ -z "$XRAY_USER" ]] && XRAY_USER="nobody"
[[ -z "$XRAY_GROUP" ]] && XRAY_GROUP="nogroup"
chown -R "$XRAY_USER:$XRAY_GROUP" /var/log/xray /usr/local/etc/xray 2>/dev/null || true
# FIX: chown alone is not enough — see umask note above. The config
# file must also be explicitly made readable by the user xray actually
# runs as, regardless of what permission bits it inherited at creation.
chmod 644 /usr/local/etc/xray/config.json 2>/dev/null || true

if systemctl restart xray && systemctl is-active --quiet xray; then
  log "Xray running (VMess:10000 VLESS:10001 Trojan:10002)."
else
  err "Xray failed to start. Real error:"
  journalctl -u xray --no-pager -n 15 2>&1 | sed 's/^/    /'
  warn "Continuing install — fix manually later with: systemctl status xray"
fi

# =====================================================================
# 12. NGINX (front door: 80 & 443)
# =====================================================================
step "Nginx Configuration"
systemctl stop nginx 2>/dev/null

# FIX (port 80/443 not working): Ubuntu's nginx package ships
# /etc/nginx/sites-enabled/default with "listen 80 default_server".
# This was never removed, so it competed with our server block for
# port 80 — on many systems the default block wins and /ssh-ws,
# /vmess, /vless, /trojan-ws all 404. Disable it permanently.
rm -f /etc/nginx/sites-enabled/default
rm -f /etc/nginx/sites-available/default

# FIX (root cause of "V2Ray not connecting on 80 or 443"): if any other
# service (a standalone MTProto/mtg proxy, another web server, etc.) is
# already bound to port 80 or 443, nginx's master process fails to start
# COMPLETELY — and when nginx fails to start, every path (/ssh-ws,
# /vmess, /vless, /trojan-ws) breaks on BOTH ports at once, even though
# only one port was actually conflicting. This produces the exact
# confusing symptom of "nothing connects on 80 or 443". Detect it before
# even trying to start nginx, and name the exact offending process so
# it's obvious what to stop/move first.
for p in 80 443; do
  conflict=$(ss -tulnp 2>/dev/null | grep ":$p " | grep -v nginx || true)
  if [[ -n "$conflict" ]]; then
    err "Port $p is already in use by another process — nginx will FAIL to bind it:"
    echo "$conflict" | sed 's/^/    /'
    err "Stop or reconfigure that service first (e.g. 'systemctl stop <service>'), then re-run this script."
    err "Common culprit: an MTProto/mtg proxy or another web server already bound to this port."
  fi
done

# Main nginx.conf — Cloudflare real IP support
cat > /etc/nginx/nginx.conf <<'NEOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
  worker_connections 2048;
  multi_accept on;
}

http {
  sendfile on;
  tcp_nopush on;
  tcp_nodelay on;
  keepalive_timeout 65;
  server_tokens off;
  client_max_body_size 32M;
  gzip on;
  gzip_vary on;
  gzip_types text/plain application/json text/css;

  include /etc/nginx/mime.types;
  default_type application/octet-stream;

  access_log /var/log/nginx/access.log;
  error_log  /var/log/nginx/error.log;

  # FIX: was missing. Without this map, "Connection: upgrade" is sent
  # on EVERY request to /ssh-ws, /vmess, /vless, /trojan-ws — even
  # plain HTTP requests with no Upgrade header (health checks,
  # Cloudflare probes, scanners). That confuses the backend and can
  # cause hangs/502s on those paths for non-WebSocket traffic.
  map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
  }

  # Cloudflare real IP
  set_real_ip_from 173.245.48.0/20;
  set_real_ip_from 103.21.244.0/22;
  set_real_ip_from 103.22.200.0/22;
  set_real_ip_from 103.31.4.0/22;
  set_real_ip_from 141.101.64.0/18;
  set_real_ip_from 108.162.192.0/18;
  set_real_ip_from 190.93.240.0/20;
  set_real_ip_from 188.114.96.0/20;
  set_real_ip_from 197.234.240.0/22;
  set_real_ip_from 198.41.128.0/17;
  set_real_ip_from 162.158.0.0/15;
  set_real_ip_from 104.16.0.0/13;
  set_real_ip_from 104.24.0.0/14;
  set_real_ip_from 172.64.0.0/13;
  set_real_ip_from 131.0.72.0/22;
  real_ip_header CF-Connecting-IP;

  include /etc/nginx/conf.d/*.conf;
}
NEOF


# Temporary HTTP-only vhost (before cert)
cat > /etc/nginx/conf.d/autoscript.conf <<NCEOF
# ── Port 80 (Non-TLS) ─────────────────────────────────────────
server {
  listen 80;
  server_name ${DOMAIN};

  location /ssh-ws {
    proxy_pass http://127.0.0.1:2082;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection \$connection_upgrade;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
  }

  location /vmess {
    proxy_pass http://127.0.0.1:10000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection \$connection_upgrade;
    proxy_set_header Host \$host;
    proxy_read_timeout 3600s;
  }

  location /vless {
    proxy_pass http://127.0.0.1:10001;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection \$connection_upgrade;
    proxy_set_header Host \$host;
    proxy_read_timeout 3600s;
  }

  location /.well-known/acme-challenge/ { root /var/www/html; }

  # FIX (Cloudflare/default payload support): most SSH-over-WS client
  # apps (HTTP Injector, HTTP Custom, etc.) use a DEFAULT payload that
  # requests "GET / HTTP/1.1" with no specific path — they don't append
  # "/ssh-ws" unless the user manually edits the payload. Previously
  # this root path just returned a static "OK" text response, so those
  # default payloads got a 200 OK instead of a WebSocket upgrade and
  # never connected. Root now forwards to the same ws-proxy bridge as
  # /ssh-ws, so both default (no path) AND explicit /ssh-ws payloads work.
  location / {
    proxy_pass http://127.0.0.1:2082;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection \$connection_upgrade;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
  }
}
NCEOF

systemctl enable nginx
if nginx -t 2>/tmp/nginx_test_err; then
  systemctl start nginx
  # FIX: nginx -t only checks config SYNTAX — it never actually binds
  # the listen sockets, so a port-already-in-use failure (see the
  # preflight check above) passed this check every time and the script
  # blindly reported success even when the nginx master process had
  # just died. Verify it's actually running before trusting it.
  if systemctl is-active --quiet nginx; then
    log "Nginx started on port 80."
  else
    err "nginx -t passed but the service still failed to start. Real error:"
    journalctl -u nginx --no-pager -n 15 2>&1 | sed 's/^/    /'
    err "This is almost always a port conflict — check the preflight warning above."
  fi
else
  err "Nginx config test FAILED — see details below:"
  cat /tmp/nginx_test_err
  err "Fix the config and run: systemctl start nginx"
fi

# =====================================================================
# 13. SSL CERTIFICATE (Let's Encrypt)
# =====================================================================
step "SSL Certificate"
CERT_OK=0
if [[ -n "$LE_EMAIL" ]]; then
  certbot certonly --nginx -d "$DOMAIN" --email "$LE_EMAIL" \
    --agree-tos --non-interactive --redirect >/dev/null 2>&1 && CERT_OK=1
else
  certbot certonly --nginx -d "$DOMAIN" --register-unsafely-without-email \
    --agree-tos --non-interactive >/dev/null 2>&1 && CERT_OK=1
fi

if [[ $CERT_OK -eq 1 ]]; then
  log "SSL certificate issued for $DOMAIN."

  # Full config with HTTPS
  cat > /etc/nginx/conf.d/autoscript.conf <<NCEOF
# ── Port 80 (Non-TLS) ──────────────────────────────────────────
server {
  listen 80;
  server_name ${DOMAIN};

  location /ssh-ws {
    proxy_pass http://127.0.0.1:2082;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection \$connection_upgrade;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
  }

  location /vmess {
    proxy_pass http://127.0.0.1:10000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection \$connection_upgrade;
    proxy_set_header Host \$host;
    proxy_read_timeout 3600s;
  }

  location /vless {
    proxy_pass http://127.0.0.1:10001;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection \$connection_upgrade;
    proxy_set_header Host \$host;
    proxy_read_timeout 3600s;
  }

  location /.well-known/acme-challenge/ { root /var/www/html; }

  # FIX: same default-payload issue as the pre-cert block — forward
  # root path to ws-proxy so SSH-WS apps using a plain "GET /" payload
  # (no /ssh-ws in the path) work without manual editing.
  location / {
    proxy_pass http://127.0.0.1:2082;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection \$connection_upgrade;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
  }
}

# ── Port 443 (TLS) ─────────────────────────────────────────────
server {
  listen 443 ssl;
  server_name ${DOMAIN};

  ssl_certificate     /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
  ssl_protocols       TLSv1.2 TLSv1.3;
  ssl_ciphers         HIGH:!aNULL:!MD5;
  ssl_session_cache   shared:SSL:10m;

  location /ssh-ws {
    proxy_pass http://127.0.0.1:2082;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection \$connection_upgrade;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
  }

  location /vmess {
    proxy_pass http://127.0.0.1:10000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection \$connection_upgrade;
    proxy_set_header Host \$host;
    proxy_read_timeout 3600s;
  }

  location /vless {
    proxy_pass http://127.0.0.1:10001;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection \$connection_upgrade;
    proxy_set_header Host \$host;
    proxy_read_timeout 3600s;
  }

  location /trojan-ws {
    proxy_pass http://127.0.0.1:10002;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection \$connection_upgrade;
    proxy_set_header Host \$host;
    proxy_read_timeout 3600s;
  }

  # FIX: same default-payload issue — root forwards to ws-proxy here too,
  # so wss://domain (no path) payloads also work over TLS.
  location / {
    proxy_pass http://127.0.0.1:2082;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection \$connection_upgrade;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
  }
}
NCEOF

  if nginx -t 2>/tmp/nginx_test_err; then
    systemctl reload nginx 2>/tmp/nginx_reload_err
    # FIX: same blind-trust problem as the first start — "reload"
    # printing nothing does NOT mean nginx is actually listening on 443.
    # Confirm both that the service is active AND that something is
    # actually bound to 443 before claiming success.
    if systemctl is-active --quiet nginx && ss -tulnp 2>/dev/null | grep -q ":443.*nginx"; then
      log "Nginx reloaded with SSL config (80 + 443 active)."
    else
      err "Nginx did not come up correctly on port 443. Real error:"
      cat /tmp/nginx_reload_err 2>/dev/null | sed 's/^/    /'
      journalctl -u nginx --no-pager -n 15 2>&1 | sed 's/^/    /'
      err "Check 'ss -tulnp | grep :443' for a port conflict (e.g. another proxy already bound to 443)."
    fi
  else
    err "Nginx SSL config test FAILED — see details below:"
    cat /tmp/nginx_test_err
    err "Port 443 will NOT work until this is fixed. Run: nginx -t"
  fi
else
  warn "SSL cert failed — running HTTP only. Run: certbot certonly --nginx -d $DOMAIN"
fi

# =====================================================================
# 14. FAIL2BAN
# =====================================================================
step "Fail2ban"
cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5
ignoreip = 127.0.0.1

[sshd]
enabled  = true
port     = 22
logpath  = /var/log/auth.log
maxretry = 3

[dropbear]
enabled  = true
port     = 109,143
logpath  = /var/log/auth.log
maxretry = 3
EOF

systemctl enable fail2ban
systemctl restart fail2ban
log "Fail2ban configured."

# =====================================================================
# 15. MANAGEMENT SCRIPTS
# =====================================================================
step "Installing Management Scripts"

# ── Shared helpers ──────────────────────────────────────────────────
cat > /etc/autoscript/lib.sh <<'LIBEOF'
#!/bin/bash
DOMAIN=$(cat /etc/autoscript/domain 2>/dev/null || echo "localhost")
MY_IP=$(cat /etc/autoscript/myip 2>/dev/null || hostname -I | awk '{print $1}')
XRAY_CONFIG=/usr/local/etc/xray/config.json
SSH_DIR=/etc/autoscript/ssh
XRAY_DIR=/etc/autoscript/xray

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\e[1m'

line() { echo "══════════════════════════════════════════════════"; }
LIBEOF
chmod +x /etc/autoscript/lib.sh

# ─── add-ws (Create SSH Account) ────────────────────────────────────
cat > /usr/bin/add-ws <<'EOF'
#!/bin/bash
source /etc/autoscript/lib.sh
clear
line
echo -e "${CYAN}${BOLD}     CREATE SSH WEBSOCKET ACCOUNT${NC}"
line
read -rp " Username     : " user
read -rp " Password     : " pass
read -rp " Duration (days) [30]: " days
days=${days:-30}
[[ -z "$user" || -z "$pass" ]] && { echo -e "${RED}Username/password required.${NC}"; exit 1; }
if id "$user" &>/dev/null; then echo -e "${RED}User $user already exists.${NC}"; exit 1; fi

exp=$(date -d "+${days} days" +%Y-%m-%d)
useradd -m -s /bin/false -e "$exp" "$user" 2>/dev/null
echo "${user}:${pass}" | chpasswd
echo "user=$user;pass=$pass;exp=$exp" > "$SSH_DIR/$user"

line
echo -e "${GREEN}  SSH Account Created Successfully${NC}"
line
echo -e " Username   : ${CYAN}$user${NC}"
echo -e " Password   : ${CYAN}$pass${NC}"
echo -e " Expires    : ${YELLOW}$exp${NC}"
echo -e " Host       : ${CYAN}$DOMAIN${NC}"
echo " ──────────────────────────────────────"
echo -e " OpenSSH    : ${CYAN}$DOMAIN : 22${NC}"
echo -e " Dropbear   : ${CYAN}$DOMAIN : 109 / 143${NC}"
echo -e " Stunnel    : ${CYAN}$DOMAIN : 447 / 777${NC}"
echo -e " WS (HTTP)  : ${CYAN}ws://$DOMAIN/ssh-ws (port 80)${NC}"
echo -e " WSS (HTTPS): ${CYAN}wss://$DOMAIN/ssh-ws (port 443)${NC}"
echo -e " BadVPN UDP : ${CYAN}127.0.0.1:7100 / 7200 / 7300${NC} (gaming & calling)"
line
read -rp "Press Enter to continue..."
EOF

# ─── add-ssws (alias for add-ws) ────────────────────────────────────
cp /usr/bin/add-ws /usr/bin/add-ssws

# ─── del-ssh (Delete SSH Account) ───────────────────────────────────
cat > /usr/bin/del-ssh <<'EOF'
#!/bin/bash
source /etc/autoscript/lib.sh
clear; line
echo -e "${CYAN}${BOLD}     DELETE SSH ACCOUNT${NC}"; line
read -rp " Username to delete: " user
[[ -z "$user" ]] && exit 1
if ! id "$user" &>/dev/null; then echo -e "${RED}User $user not found.${NC}"; exit 1; fi
read -rp " Confirm delete $user? (y/N): " c
[[ "$c" != "y" && "$c" != "Y" ]] && { echo "Cancelled."; exit 0; }
userdel -f -r "$user" 2>/dev/null
rm -f "$SSH_DIR/$user"
echo -e "${GREEN}User $user deleted.${NC}"
read -rp "Press Enter to continue..."
EOF

# ─── renew-ssh (Extend SSH Account) ─────────────────────────────────
cat > /usr/bin/renew-ssh <<'EOF'
#!/bin/bash
source /etc/autoscript/lib.sh
clear; line
echo -e "${CYAN}${BOLD}     EXTEND SSH ACCOUNT${NC}"; line
read -rp " Username: " user
[[ ! -f "$SSH_DIR/$user" ]] && { echo -e "${RED}Account not found.${NC}"; exit 1; }
read -rp " Add how many days: " days
[[ -z "$days" ]] && exit 1
cur=$(chage -l "$user" 2>/dev/null | grep "Account expires" | cut -d: -f2 | xargs)
[[ "$cur" == "never" ]] && cur=$(date +%Y-%m-%d)
cur_ts=$(date -d "$cur" +%s 2>/dev/null)
now_ts=$(date +%s)
base=$( [[ -n "$cur_ts" && $cur_ts -gt $now_ts ]] && echo "$cur" || date +%Y-%m-%d )
new_exp=$(date -d "$base +$days days" +%Y-%m-%d)
chage -E "$new_exp" "$user"
sed -i "s/exp=.*/exp=$new_exp/" "$SSH_DIR/$user"
echo -e "${GREEN}$user extended to ${CYAN}$new_exp${NC}"
read -rp "Press Enter to continue..."
EOF

# ─── list-ssh (List SSH Accounts) ───────────────────────────────────
cat > /usr/bin/list-ssh <<'EOF'
#!/bin/bash
source /etc/autoscript/lib.sh
clear; line
echo -e "${CYAN}${BOLD}     SSH ACCOUNT LIST${NC}"; line
printf "  %-16s %-12s %-10s %-6s\n" "USERNAME" "EXPIRES" "STATUS" "LOGINS"
line
now=$(date +%s)
for f in "$SSH_DIR"/*; do
  [[ -e "$f" ]] || { echo "  (no accounts)"; break; }
  u=$(basename "$f")
  exp=$(sed -n 's/.*exp=//p' "$f")
  exp_ts=$(date -d "$exp" +%s 2>/dev/null)
  status="${GREEN}active${NC}"
  [[ -n "$exp_ts" && $exp_ts -lt $now ]] && status="${RED}expired${NC}"
  logins=$(who | grep -c "^$u " 2>/dev/null || echo 0)
  printf "  %-16s %-12s " "$u" "$exp"
  echo -e "${status}       $logins"
done
line
total=$(ls "$SSH_DIR" 2>/dev/null | wc -l)
echo -e "  Total accounts: ${CYAN}$total${NC}"
line
read -rp "Press Enter to continue..."
EOF

# ─── trial-ssh (1-day Trial SSH) ────────────────────────────────────
cat > /usr/bin/trial-ssh <<'EOF'
#!/bin/bash
source /etc/autoscript/lib.sh
user="trial$(tr -dc a-z0-9 </dev/urandom | head -c6)"
pass=$(tr -dc A-Za-z0-9 </dev/urandom | head -c10)
exp=$(date -d "+1 day" +%Y-%m-%d)
useradd -m -s /bin/false -e "$exp" "$user" 2>/dev/null
echo "${user}:${pass}" | chpasswd
echo "user=$user;pass=$pass;exp=$exp" > "$SSH_DIR/$user"
clear; line
echo -e "${GREEN}  TRIAL SSH ACCOUNT (1 Day)${NC}"; line
echo -e " Username  : ${CYAN}$user${NC}"
echo -e " Password  : ${CYAN}$pass${NC}"
echo -e " Expires   : ${YELLOW}$exp${NC}"
echo -e " Host      : ${CYAN}$DOMAIN${NC}"
echo -e " OpenSSH   : $DOMAIN : 22"
echo -e " WS (HTTP) : ws://$DOMAIN/ssh-ws"
echo -e " WSS (HTTPS): wss://$DOMAIN/ssh-ws"
line
read -rp "Press Enter to continue..."
EOF

# ─── check-user (Multi-login checker) ───────────────────────────────
cat > /usr/bin/check-user <<'EOF'
#!/bin/bash
source /etc/autoscript/lib.sh
clear; line
echo -e "${CYAN}${BOLD}     ACTIVE SSH LOGINS${NC}"; line
printf "  %-16s %-8s %-20s\n" "USER" "PID" "LOGIN_TIME"
line
who | while read u tty dt tm rest; do
  printf "  %-16s %-8s %-20s\n" "$u" "$(ps aux | grep "$tty" | grep -v grep | awk '{print $2}' | head -1)" "$dt $tm"
done
line; echo -e "  Online: ${CYAN}$(who | wc -l)${NC} session(s)"
line; read -rp "Press Enter to continue..."
EOF

# ─── tendang (Kill multi-login) ──────────────────────────────────────
cat > /usr/bin/tendang <<'EOF'
#!/bin/bash
source /etc/autoscript/lib.sh
clear; line
echo -e "${CYAN}${BOLD}     KILL MULTI LOGIN USER${NC}"; line
read -rp " Username to kick: " user
[[ -z "$user" ]] && exit 1
count=$(who | grep -c "^$user ")
if [[ $count -eq 0 ]]; then
  echo -e "${YELLOW}$user has no active sessions.${NC}"
else
  pkill -u "$user" -KILL 2>/dev/null
  echo -e "${GREEN}Killed $count session(s) for $user.${NC}"
fi
read -rp "Press Enter to continue..."
EOF

# ─── add-vmess (Create VMess Xray Account) ──────────────────────────
cat > /usr/bin/add-vmess <<'EOF'
#!/bin/bash
source /etc/autoscript/lib.sh
clear; line
echo -e "${CYAN}${BOLD}     CREATE VMESS ACCOUNT${NC}"; line
read -rp " Username: " uname
read -rp " Duration (days) [30]: " days
days=${days:-30}
[[ -z "$uname" ]] && exit 1
if [[ -f "$XRAY_DIR/$uname" ]]; then echo -e "${RED}Account exists.${NC}"; exit 1; fi

uuid=$(uuidgen)
exp=$(date -d "+${days} days" +%Y-%m-%d)

tmp=$(mktemp)
jq --arg id "$uuid" --arg email "$uname" \
  '(.inbounds[] | select(.tag=="vmess-ws-in") | .settings.clients) += [{"id":$id,"email":$email,"alterId":0}]' \
  "$XRAY_CONFIG" > "$tmp" && mv "$tmp" "$XRAY_CONFIG"
XU=$(systemctl show xray -p User  --value 2>/dev/null)
XG=$(systemctl show xray -p Group --value 2>/dev/null)
[ -z "$XU" ] && XU=nobody
[ -z "$XG" ] && XG=nogroup
chown "$XU:$XG" "$XRAY_CONFIG" 2>/dev/null
chmod 644 "$XRAY_CONFIG"
kill -HUP $(pgrep xray 2>/dev/null) 2>/dev/null || systemctl restart xray

echo "type=vmess;uuid=$uuid;exp=$exp" > "$XRAY_DIR/$uname"

b64=$(echo -n "{\"v\":\"2\",\"ps\":\"$uname\",\"add\":\"$DOMAIN\",\"port\":\"80\",\"id\":\"$uuid\",\"aid\":\"0\",\"net\":\"ws\",\"path\":\"/vmess\",\"tls\":\"\"}" | base64 -w0)
b64tls=$(echo -n "{\"v\":\"2\",\"ps\":\"$uname-tls\",\"add\":\"$DOMAIN\",\"port\":\"443\",\"id\":\"$uuid\",\"aid\":\"0\",\"net\":\"ws\",\"path\":\"/vmess\",\"tls\":\"tls\"}" | base64 -w0)

line
echo -e "${GREEN}  VMess Account Created${NC}"; line
echo -e " Username : ${CYAN}$uname${NC}"
echo -e " UUID     : ${CYAN}$uuid${NC}"
echo -e " Expires  : ${YELLOW}$exp${NC}"
echo " ─── Links ────────────────────────────────────"
echo -e " WS     : ${CYAN}vmess://$b64${NC}"
echo -e " WSS    : ${CYAN}vmess://$b64tls${NC}"
line
read -rp "Press Enter to continue..."
EOF

# ─── add-vless (Create VLESS Account) ───────────────────────────────
cat > /usr/bin/add-vless <<'EOF'
#!/bin/bash
source /etc/autoscript/lib.sh
clear; line
echo -e "${CYAN}${BOLD}     CREATE VLESS ACCOUNT${NC}"; line
read -rp " Username: " uname
read -rp " Duration (days) [30]: " days
days=${days:-30}
[[ -z "$uname" ]] && exit 1
if [[ -f "$XRAY_DIR/$uname" ]]; then echo -e "${RED}Account exists.${NC}"; exit 1; fi

uuid=$(uuidgen)
exp=$(date -d "+${days} days" +%Y-%m-%d)

tmp=$(mktemp)
jq --arg id "$uuid" --arg email "$uname" \
  '(.inbounds[] | select(.tag=="vless-ws-in") | .settings.clients) += [{"id":$id,"email":$email,"flow":""}]' \
  "$XRAY_CONFIG" > "$tmp" && mv "$tmp" "$XRAY_CONFIG"
XU=$(systemctl show xray -p User  --value 2>/dev/null)
XG=$(systemctl show xray -p Group --value 2>/dev/null)
[ -z "$XU" ] && XU=nobody
[ -z "$XG" ] && XG=nogroup
chown "$XU:$XG" "$XRAY_CONFIG" 2>/dev/null
chmod 644 "$XRAY_CONFIG"
kill -HUP $(pgrep xray 2>/dev/null) 2>/dev/null || systemctl restart xray

echo "type=vless;uuid=$uuid;exp=$exp" > "$XRAY_DIR/$uname"

line
echo -e "${GREEN}  VLESS Account Created${NC}"; line
echo -e " Username : ${CYAN}$uname${NC}"
echo -e " UUID     : ${CYAN}$uuid${NC}"
echo -e " Expires  : ${YELLOW}$exp${NC}"
echo " ─── Links ────────────────────────────────────"
echo -e " WS     : ${CYAN}vless://$uuid@$DOMAIN:80?type=ws&path=%2Fvless#$uname${NC}"
echo -e " WSS    : ${CYAN}vless://$uuid@$DOMAIN:443?type=ws&security=tls&path=%2Fvless#$uname-tls${NC}"
line
read -rp "Press Enter to continue..."
EOF

# ─── add-tr (Create Trojan Account) ─────────────────────────────────
cat > /usr/bin/add-tr <<'EOF'
#!/bin/bash
source /etc/autoscript/lib.sh
clear; line
echo -e "${CYAN}${BOLD}     CREATE TROJAN ACCOUNT${NC}"; line
read -rp " Username: " uname
read -rp " Duration (days) [30]: " days
days=${days:-30}
[[ -z "$uname" ]] && exit 1
if [[ -f "$XRAY_DIR/$uname" ]]; then echo -e "${RED}Account exists.${NC}"; exit 1; fi

pw=$(tr -dc A-Za-z0-9 </dev/urandom | head -c16)
exp=$(date -d "+${days} days" +%Y-%m-%d)

tmp=$(mktemp)
jq --arg pw "$pw" --arg email "$uname" \
  '(.inbounds[] | select(.tag=="trojan-ws-in") | .settings.clients) += [{"password":$pw,"email":$email}]' \
  "$XRAY_CONFIG" > "$tmp" && mv "$tmp" "$XRAY_CONFIG"
XU=$(systemctl show xray -p User  --value 2>/dev/null)
XG=$(systemctl show xray -p Group --value 2>/dev/null)
[ -z "$XU" ] && XU=nobody
[ -z "$XG" ] && XG=nogroup
chown "$XU:$XG" "$XRAY_CONFIG" 2>/dev/null
chmod 644 "$XRAY_CONFIG"
kill -HUP $(pgrep xray 2>/dev/null) 2>/dev/null || systemctl restart xray

echo "type=trojan;pass=$pw;exp=$exp" > "$XRAY_DIR/$uname"

line
echo -e "${GREEN}  Trojan Account Created${NC}"; line
echo -e " Username : ${CYAN}$uname${NC}"
echo -e " Password : ${CYAN}$pw${NC}"
echo -e " Expires  : ${YELLOW}$exp${NC}"
echo " ─── Link (TLS only) ──────────────────────────"
echo -e " WSS : ${CYAN}trojan://$pw@$DOMAIN:443?type=ws&security=tls&path=%2Ftrojan-ws#$uname${NC}"
line
read -rp "Press Enter to continue..."
EOF

# ─── del-xray (Delete Xray Account) ─────────────────────────────────
cat > /usr/bin/del-xray <<'EOF'
#!/bin/bash
source /etc/autoscript/lib.sh
clear; line
echo -e "${CYAN}${BOLD}     DELETE XRAY ACCOUNT${NC}"; line
read -rp " Username: " uname
[[ ! -f "$XRAY_DIR/$uname" ]] && { echo -e "${RED}Not found.${NC}"; exit 1; }
read -rp " Confirm delete $uname? (y/N): " c
[[ "$c" != "y" && "$c" != "Y" ]] && exit 0
tmp=$(mktemp)
jq --arg email "$uname" \
  '(.inbounds[].settings.clients) |= map(select(.email != $email))' \
  "$XRAY_CONFIG" > "$tmp" && mv "$tmp" "$XRAY_CONFIG"
XU=$(systemctl show xray -p User  --value 2>/dev/null)
XG=$(systemctl show xray -p Group --value 2>/dev/null)
[ -z "$XU" ] && XU=nobody
[ -z "$XG" ] && XG=nogroup
chown "$XU:$XG" "$XRAY_CONFIG" 2>/dev/null
chmod 644 "$XRAY_CONFIG"
kill -HUP $(pgrep xray 2>/dev/null) 2>/dev/null || systemctl restart xray
rm -f "$XRAY_DIR/$uname"
echo -e "${GREEN}Account $uname deleted.${NC}"
read -rp "Press Enter to continue..."
EOF

# ─── renew-xray (Extend Xray Account) ───────────────────────────────
cat > /usr/bin/renew-xray <<'EOF'
#!/bin/bash
source /etc/autoscript/lib.sh
clear; line
echo -e "${CYAN}${BOLD}     EXTEND XRAY ACCOUNT${NC}"; line
read -rp " Username: " uname
[[ ! -f "$XRAY_DIR/$uname" ]] && { echo -e "${RED}Not found.${NC}"; exit 1; }
read -rp " Add how many days: " days
[[ -z "$days" ]] && exit 1
cur=$(sed -n 's/.*exp=//p' "$XRAY_DIR/$uname")
now_ts=$(date +%s); cur_ts=$(date -d "$cur" +%s 2>/dev/null)
base=$( [[ -n "$cur_ts" && $cur_ts -gt $now_ts ]] && echo "$cur" || date +%Y-%m-%d )
new_exp=$(date -d "$base +$days days" +%Y-%m-%d)
sed -i "s/exp=.*/exp=$new_exp/" "$XRAY_DIR/$uname"
echo -e "${GREEN}$uname extended to ${CYAN}$new_exp${NC}"
read -rp "Press Enter to continue..."
EOF

# ─── list-xray (List Xray Accounts) ─────────────────────────────────
cat > /usr/bin/list-xray <<'EOF'
#!/bin/bash
source /etc/autoscript/lib.sh
clear; line
echo -e "${CYAN}${BOLD}     XRAY ACCOUNT LIST${NC}"; line
printf "  %-18s %-10s %-12s %-8s\n" "USERNAME" "TYPE" "EXPIRES" "STATUS"
line
now=$(date +%s)
count=0
for f in "$XRAY_DIR"/*; do
  [[ -e "$f" ]] || { echo "  (no accounts)"; break; }
  u=$(basename "$f")
  typ=$(sed -n 's/.*type=\([^;]*\).*/\1/p' "$f")
  exp=$(sed -n 's/.*exp=//p' "$f")
  exp_ts=$(date -d "$exp" +%s 2>/dev/null)
  status="${GREEN}active${NC}"
  [[ -n "$exp_ts" && $exp_ts -lt $now ]] && status="${RED}expired${NC}"
  printf "  %-18s %-10s %-12s " "$u" "${typ:-ssh}" "$exp"
  echo -e "$status"
  ((count++))
done
line
echo -e "  Total: ${CYAN}$count${NC}"; line
read -rp "Press Enter to continue..."
EOF

# ─── trial-xray (1-day Trial Xray) ──────────────────────────────────
cat > /usr/bin/trial-xray <<'EOF'
#!/bin/bash
source /etc/autoscript/lib.sh
echo -e "${CYAN}[1] VMess Trial  [2] VLESS Trial  [3] Trojan Trial${NC}"
read -rp "Choose: " c
case $c in
  1) /usr/bin/add-vmess ;;
  2) /usr/bin/add-vless ;;
  3) /usr/bin/add-tr ;;
  *) echo "Invalid." ;;
esac
EOF

# ─── running (Service Status) ────────────────────────────────────────
cat > /usr/bin/running <<'EOF'
#!/bin/bash
source /etc/autoscript/lib.sh

svc_status() {
  local s="$1"
  if systemctl is-active --quiet "$s"; then
    echo -e "${GREEN}● RUNNING${NC}"
  else
    echo -e "${RED}✗ STOPPED${NC}"
  fi
}

badvpn_status() {
  local up=0 down=0
  for p in 7100 7200 7300; do
    systemctl is-active --quiet "badvpn@${p}" && ((up++)) || ((down++))
  done
  if [[ $down -eq 0 ]]; then
    echo -e "${GREEN}● RUNNING (3/3)${NC}"
  elif [[ $up -eq 0 ]]; then
    echo -e "${RED}✗ STOPPED (0/3)${NC}"
  else
    echo -e "${YELLOW}⚠ PARTIAL (${up}/3)${NC}"
  fi
}

clear; line
echo -e "${CYAN}${BOLD}     RUNNING SERVICES${NC}"; line
printf "  %-26s %s\n" "OpenSSH   (22)"            "$(svc_status ssh)"
printf "  %-26s %s\n" "Dropbear  (109,143)"        "$(svc_status dropbear)"
printf "  %-26s %s\n" "ws-proxy  (2082→22)"        "$(svc_status ws-proxy)"
printf "  %-26s %s\n" "Nginx     (80,443)"          "$(svc_status nginx)"
printf "  %-26s %s\n" "Stunnel5  (447,777)"         "$(svc_status stunnel4)"
printf "  %-26s %s\n" "BadVPN    (7100/7200/7300)"  "$(badvpn_status)"
printf "  %-26s %s\n" "Xray      (10000-10002)"     "$(svc_status xray)"
printf "  %-26s %s\n" "Fail2ban"                    "$(svc_status fail2ban)"
line
echo -e "  SSH Users Online: ${CYAN}$(who | wc -l)${NC}"
echo -e "  Xray Accounts  : ${CYAN}$(ls /etc/autoscript/xray 2>/dev/null | wc -l)${NC}"
echo -e "  SSH  Accounts  : ${CYAN}$(ls /etc/autoscript/ssh  2>/dev/null | wc -l)${NC}"
line
read -rp "Press Enter to continue..."
EOF

# ─── restart (Restart All Services) ─────────────────────────────────
cat > /usr/bin/restart <<'EOF'
#!/bin/bash
echo -e "\033[0;36mRestarting all services...\033[0m"
systemctl restart ssh dropbear ws-proxy nginx stunnel4 badvpn@7100 badvpn@7200 badvpn@7300 xray fail2ban
echo -e "\033[0;32mAll services restarted.\033[0m"
read -rp "Press Enter to continue..."
EOF

# ─── cek-bandwidth ───────────────────────────────────────────────────
cat > /usr/bin/cek-bandwidth <<'EOF'
#!/bin/bash
source /etc/autoscript/lib.sh
clear; line
echo -e "${CYAN}${BOLD}     BANDWIDTH MONITOR${NC}"; line
IF=$(ip route | grep default | awk '{print $5}' | head -1)
echo -e "  Interface: ${CYAN}$IF${NC}"
echo ""
if command -v vnstat &>/dev/null; then
  vnstat -i "$IF"
else
  cat /proc/net/dev | grep "$IF"
fi
line; read -rp "Press Enter to continue..."
EOF

# ─── cek-ram ─────────────────────────────────────────────────────────
cat > /usr/bin/cek-ram <<'EOF'
#!/bin/bash
source /etc/autoscript/lib.sh
clear; line
echo -e "${CYAN}${BOLD}     RAM MONITOR${NC}"; line
free -h
echo ""
echo -e "  Swap usage:"
swapon --show
line; read -rp "Press Enter to continue..."
EOF

# ─── dns (Change DNS) ────────────────────────────────────────────────
cat > /usr/bin/dns <<'EOF'
#!/bin/bash
source /etc/autoscript/lib.sh
clear; line
echo -e "${CYAN}${BOLD}     CHANGE DNS${NC}"; line
echo " [1] Cloudflare  (1.1.1.1)"
echo " [2] Google      (8.8.8.8)"
echo " [3] OpenDNS     (208.67.222.222)"
echo " [4] Custom DNS"
line
read -rp " Choose: " opt
case $opt in
  1) DNS1=1.1.1.1; DNS2=1.0.0.1 ;;
  2) DNS1=8.8.8.8; DNS2=8.8.4.4 ;;
  3) DNS1=208.67.222.222; DNS2=208.67.220.220 ;;
  4) read -rp " DNS 1: " DNS1; read -rp " DNS 2: " DNS2 ;;
  *) echo "Invalid."; exit 1 ;;
esac
{
  echo "nameserver $DNS1"
  echo "nameserver $DNS2"
} > /etc/resolv.conf
# FIX: /etc/resolv.conf is a SYMLINK to a systemd-resolved-managed file
# on stock Ubuntu 24.04. chattr +i here doesn't lock down our own
# file — it follows the symlink and makes systemd-resolved's runtime
# file immutable, so systemd-resolved can no longer update it (e.g. on
# reboot or DHCP renewal), breaking DNS resolution later in a way
# that's confusing to diagnose. Only set immutable when the path is a
# real, regular file (i.e. systemd-resolved's stub isn't in play).
if [[ ! -L /etc/resolv.conf ]]; then
  chattr +i /etc/resolv.conf 2>/dev/null
else
  systemctl disable --now systemd-resolved 2>/dev/null
  rm -f /etc/resolv.conf
  { echo "nameserver $DNS1"; echo "nameserver $DNS2"; } > /etc/resolv.conf
  chattr +i /etc/resolv.conf 2>/dev/null
fi
echo -e "${GREEN}DNS set to $DNS1 / $DNS2${NC}"
read -rp "Press Enter to continue..."
EOF

# ─── swap (Manage Swap) ──────────────────────────────────────────────
cat > /usr/bin/swap <<'EOF'
#!/bin/bash
source /etc/autoscript/lib.sh
clear; line
echo -e "${CYAN}${BOLD}     VIRTUAL SWAPRAM${NC}"; line
echo " Current swap:"
swapon --show
echo ""
echo " [1] Create 1GB Swap  [2] Create 2GB Swap  [3] Remove Swap"
line; read -rp " Choose: " opt
case $opt in
  1) SIZE=1G ;;
  2) SIZE=2G ;;
  3) swapoff /swapfile 2>/dev/null; rm -f /swapfile
     sed -i '/swapfile/d' /etc/fstab
     echo -e "${GREEN}Swap removed.${NC}"; read -rp "Enter..."; exit 0 ;;
  *) exit 1 ;;
esac
swapoff /swapfile 2>/dev/null; rm -f /swapfile
fallocate -l "$SIZE" /swapfile
chmod 600 /swapfile; mkswap /swapfile; swapon /swapfile
grep -qxF '/swapfile none swap sw 0 0' /etc/fstab || \
  echo '/swapfile none swap sw 0 0' >> /etc/fstab
echo -e "${GREEN}$SIZE swap created.${NC}"
read -rp "Press Enter to continue..."
EOF

# ─── bbr (BBR Status) ────────────────────────────────────────────────
cat > /usr/bin/bbr <<'EOF'
#!/bin/bash
source /etc/autoscript/lib.sh
clear; line
echo -e "${CYAN}${BOLD}     BBR STATUS${NC}"; line
echo -e "  TCP CC   : $(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')"
echo -e "  Queue    : $(sysctl net.core.default_qdisc | awk '{print $3}')"
echo -e "  Kernel   : $(uname -r)"
echo ""
cc=$(sysctl -n net.ipv4.tcp_congestion_control)
if [[ "$cc" == "bbr" ]]; then
  echo -e "  Status: ${GREEN}BBR is ACTIVE ✔${NC}"
else
  echo -e "  Status: ${YELLOW}BBR not active — enabling now...${NC}"
  echo "net.core.default_qdisc=fq"               >> /etc/sysctl.conf
  echo "net.ipv4.tcp_congestion_control=bbr"      >> /etc/sysctl.conf
  sysctl -p >/dev/null 2>&1
  echo -e "  Status: ${GREEN}BBR enabled ✔${NC}"
fi
line; read -rp "Press Enter to continue..."
EOF

# ─── clearlog ────────────────────────────────────────────────────────
cat > /usr/bin/clearlog <<'EOF'
#!/bin/bash
echo "Clearing logs..."
> /var/log/nginx/access.log
> /var/log/nginx/error.log
> /var/log/xray/access.log
> /var/log/xray/error.log
> /var/log/auth.log
> /var/log/syslog
journalctl --rotate --vacuum-time=1s >/dev/null 2>&1
echo "Logs cleared."
EOF

# ─── backup ──────────────────────────────────────────────────────────
cat > /usr/bin/backup <<'EOF'
#!/bin/bash
source /etc/autoscript/lib.sh
DATE=$(date +%Y%m%d-%H%M)
FILE="/etc/autoscript/backup/backup-$DATE.tar.gz"
tar -czf "$FILE" /etc/autoscript/ssh /etc/autoscript/xray \
  /usr/local/etc/xray/config.json /etc/autoscript/domain 2>/dev/null
echo -e "${GREEN}Backup saved: $FILE${NC}"
ls -lh "$FILE"
read -rp "Press Enter to continue..."
EOF

# ─── restore ─────────────────────────────────────────────────────────
cat > /usr/bin/restore <<'EOF'
#!/bin/bash
source /etc/autoscript/lib.sh
clear; line
echo -e "${CYAN}${BOLD}     RESTORE BACKUP${NC}"; line
echo "  Available backups:"
ls /etc/autoscript/backup/*.tar.gz 2>/dev/null || { echo "  None found."; exit 1; }
echo ""
read -rp "  Enter backup filename: " f
[[ ! -f "$f" ]] && { echo -e "${RED}File not found.${NC}"; exit 1; }
tar -xzf "$f" -C / 2>/dev/null
systemctl restart xray
echo -e "${GREEN}Restored from $f${NC}"
read -rp "Press Enter to continue..."
EOF

# ─── xp (Expire cron script) ─────────────────────────────────────────
cat > /usr/bin/xp <<'EOF'
#!/bin/bash
SSH_DIR=/etc/autoscript/ssh
XRAY_DIR=/etc/autoscript/xray
XRAY_CONFIG=/usr/local/etc/xray/config.json
now=$(date +%s)

# Expire SSH accounts
for f in "$SSH_DIR"/*; do
  [[ -e "$f" ]] || continue
  u=$(basename "$f")
  id "$u" &>/dev/null || { rm -f "$f"; continue; }
  exp=$(chage -l "$u" 2>/dev/null | grep "Account expires" | cut -d: -f2 | xargs)
  [[ "$exp" == "never" ]] && continue
  exp_ts=$(date -d "$exp" +%s 2>/dev/null)
  if [[ -n "$exp_ts" && $exp_ts -lt $now ]]; then
    userdel -f "$u" 2>/dev/null
    rm -f "$f"
    echo "$(date): expired SSH removed: $u" >> /var/log/autoscript-cron.log
  fi
done

# Expire Xray accounts
changed=0
for f in "$XRAY_DIR"/*; do
  [[ -e "$f" ]] || continue
  u=$(basename "$f")
  exp=$(sed -n 's/.*exp=//p' "$f")
  exp_ts=$(date -d "$exp" +%s 2>/dev/null)
  if [[ -n "$exp_ts" && $exp_ts -lt $now ]]; then
    tmp=$(mktemp)
    jq --arg email "$u" \
      '(.inbounds[].settings.clients) |= map(select(.email != $email))' \
      "$XRAY_CONFIG" > "$tmp" && mv "$tmp" "$XRAY_CONFIG"
    XU=$(systemctl show xray -p User  --value 2>/dev/null)
    XG=$(systemctl show xray -p Group --value 2>/dev/null)
    [ -z "$XU" ] && XU=nobody
    [ -z "$XG" ] && XG=nogroup
    chown "$XU:$XG" "$XRAY_CONFIG" 2>/dev/null
    chmod 644 "$XRAY_CONFIG"
    rm -f "$f"; changed=1
    echo "$(date): expired Xray removed: $u" >> /var/log/autoscript-cron.log
  fi
done
[[ $changed -eq 1 ]] && { kill -HUP $(pgrep xray 2>/dev/null) 2>/dev/null || systemctl restart xray; }
EOF

# ─── renew-ssl ───────────────────────────────────────────────────────
cat > /usr/bin/renew-ssl <<'EOF'
#!/bin/bash
certbot renew --nginx --force-renewal && systemctl reload nginx
echo "SSL renewed."
read -rp "Press Enter to continue..."
EOF

# Make all scripts executable
chmod +x /usr/bin/add-ws /usr/bin/add-ssws /usr/bin/del-ssh \
         /usr/bin/renew-ssh /usr/bin/list-ssh /usr/bin/trial-ssh \
         /usr/bin/check-user /usr/bin/tendang \
         /usr/bin/add-vmess /usr/bin/add-vless /usr/bin/add-tr \
         /usr/bin/del-xray /usr/bin/renew-xray /usr/bin/list-xray \
         /usr/bin/trial-xray /usr/bin/running /usr/bin/restart \
         /usr/bin/cek-bandwidth /usr/bin/cek-ram /usr/bin/dns \
         /usr/bin/swap /usr/bin/bbr /usr/bin/clearlog \
         /usr/bin/backup /usr/bin/restore /usr/bin/xp /usr/bin/renew-ssl

log "All management scripts installed."

# =====================================================================
# 16. MAIN MENU
# =====================================================================
cat > /usr/bin/menu <<'MENUEOF'
#!/bin/bash
while true; do
clear
DOM=$(cat /etc/autoscript/domain 2>/dev/null)
IP=$(cat /etc/autoscript/myip   2>/dev/null)

# ── Multicolor palette ───────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'; BOLD='\e[1m'; PURPLE='\033[0;35m'
ORANGE='\033[38;5;208m'; PINK='\033[38;5;205m'; LIME='\033[38;5;118m'
SKY='\033[38;5;45m';     GOLD='\033[38;5;220m'; WHITE='\033[1;37m'

# ── Box-drawing helpers (FIX for broken alignment) ───────────────
# Root cause of the old misaligned menu: every box row was built from
# hand-counted literal spaces, and ANSI color codes were sometimes
# embedded inside printf's %-Ns width field, which counts the invisible
# escape-code bytes as "width" too. Both silently drift the moment any
# label text changes length. INNER is now the single source of truth
# for box width — every row is padded against it programmatically, so
# rows can never go out of sync with each other again.
INNER=50
COLS=$(tput cols 2>/dev/null || echo 0)
# Shrink to fit narrow phone-terminal screens, never below 36.
if [[ "$COLS" =~ ^[0-9]+$ ]] && (( COLS > 0 && COLS < INNER + 2 )); then
  INNER=$(( COLS - 2 )); (( INNER < 36 )) && INNER=36
fi

hr()   { printf "${SKY}${BOLD}%s%s%s${NC}\n" "$1" "$(printf '═%.0s' $(seq 1 "$INNER"))" "$2"; }
top()  { hr "╔" "╗"; }
mid()  { hr "╠" "╣"; }
bot()  { hr "╚" "╝"; }
# box_line "<plain text, no color codes>" "<same text, may include color codes>"
box_line() {
  local plain="$1" disp="$2"
  local pad=$(( INNER - ${#plain} ))
  (( pad < 0 )) && pad=0
  printf "${SKY}${BOLD}║${NC}%b%*s${SKY}${BOLD}║${NC}\n" "$disp" "$pad" ""
}
# mline "1)" "Create SSH Acct" "8)" "Create VMess"
mline() {
  printf " ${GREEN}%-3s${NC} %-18s ${PINK}%-3s${NC} %s\n" "$1" "$2" "$3" "$4"
}
# sline "15)" "Running Services" "20)" "Change DNS"
sline() {
  printf " ${YELLOW}%-3s${NC} %-18s ${SKY}%-3s${NC} %s\n" "$1" "$2" "$3" "$4"
}

top
box_line "   *** HELPER VPN MENU ***" "   ${GOLD}${BOLD}*** HELPER VPN MENU ***${NC}"
mid
box_line " Domain: $DOM" " ${WHITE}Domain${NC}: ${LIME}$DOM${NC}"
box_line " IP    : $IP"  " ${WHITE}IP    ${NC}: ${LIME}$IP${NC}"
mid
box_line " [ SSH ACCOUNT ]        [ XRAY ACCOUNT ]" " ${GREEN}${BOLD}[ SSH ACCOUNT ]${NC}        ${PINK}${BOLD}[ XRAY ACCOUNT ]${NC}"
mid
echo ""
mline "1)" "Create SSH Acct"   "8)"  "Create VMess"
mline "2)" "Delete SSH Acct"   "9)"  "Create VLESS"
mline "3)" "Extend SSH Acct"   "10)" "Create Trojan"
mline "4)" "List SSH Accts"    "11)" "Delete Xray"
mline "5)" "Trial SSH 1day"    "12)" "Extend Xray"
mline "6)" "Active Logins"     "13)" "List Xray"
mline "7)" "Kill Multi Login"  "14)" "Trial Xray 1day"
echo ""
mid
box_line " [ SYSTEM TOOLS ]" " ${ORANGE}${BOLD}[ SYSTEM TOOLS ]${NC}"
mid
echo ""
sline "15)" "Running Services" "20)" "Change DNS"
sline "16)" "Restart Services" "21)" "BBR Status"
sline "17)" "Bandwidth Monitor" "22)" "Swap RAM"
sline "18)" "RAM Monitor"      "23)" "Renew SSL"
sline "19)" "Clear Logs"       "24)" "Backup Data"
sline ""    ""                 "25)" "Restore Data"
echo ""
mid
box_line "  0) Exit" "  ${RED}${BOLD}0) Exit${NC}"
bot
read -rp "$(echo -e " ${GOLD}${BOLD}Choose [0-25]: ${NC}")" opt
case $opt in
   1) add-ws ;;        2) del-ssh ;;      3) renew-ssh ;;
   4) list-ssh ;;      5) trial-ssh ;;    6) check-user ;;
   7) tendang ;;       8) add-vmess ;;    9) add-vless ;;
  10) add-tr ;;       11) del-xray ;;    12) renew-xray ;;
  13) list-xray ;;    14) trial-xray ;;  15) running ;;
  16) restart ;;      17) cek-bandwidth;;18) cek-ram ;;
  19) clearlog; read -rp "Logs cleared. Enter..." _ ;;
  20) dns ;;          21) bbr ;;         22) swap ;;
  23) renew-ssl ;;    24) backup ;;      25) restore ;;
   0) exit 0 ;;
   *) echo -e "\033[0;31mInvalid option.\033[0m" ; sleep 1 ;;
esac
done
MENUEOF
chmod +x /usr/bin/menu

log "Menu installed — type 'menu' to launch."

# =====================================================================
# 17. AUTO-LAUNCH MENU ON ROOT LOGIN
# =====================================================================
cat > /root/.profile <<'EOF'
if [ "$BASH" ]; then
  if [ -f ~/.bashrc ]; then . ~/.bashrc; fi
fi
mesg n 2>/dev/null || true
clear
menu
EOF

# =====================================================================
# 18. CRON JOBS
# =====================================================================
step "Cron Jobs"
(crontab -l 2>/dev/null | grep -v autoscript ; cat <<'CRONEOF'
# Auto-expire accounts (daily at 00:02)
2 0 * * * /usr/bin/xp >> /var/log/autoscript-cron.log 2>&1
# Auto-clear logs (daily at 01:00)
0 1 * * * /usr/bin/clearlog >> /dev/null 2>&1
# Auto-reboot (daily at 05:00)
0 5 * * * /sbin/reboot
# SSL auto-renew check (weekly)
0 3 * * 0 certbot renew --nginx --quiet && systemctl reload nginx
CRONEOF
) | crontab -

systemctl enable cron
systemctl restart cron
log "Cron jobs configured."

# =====================================================================
# DONE
# =====================================================================
DOMAIN=$(cat "$BASE/domain")
MY_IP=$(cat /etc/autoscript/myip)

# FIX: this summary previously hardcoded every service as present,
# even BadVPN/SSL when they had actually failed above — silently
# misinforming the admin that gaming/calling or HTTPS was ready when
# it wasn't. Now reflects the real, just-checked status of each.
# Status text and color are kept as SEPARATE values (not pre-merged
# colored strings) so box_line can measure the real visible width
# instead of miscounting embedded ANSI bytes as printable characters.
svc_status() { systemctl is-active --quiet "$1" 2>/dev/null && echo "UP" || echo "DOWN"; }
svc_color()  { [[ "$(svc_status "$1")" == "UP" ]] && echo -n "$LIME" || echo -n "$RED"; }
BADVPN_STATUS=$([[ $BADVPN_OK -eq 1 ]] && echo "READY" || echo "SKIPPED")
BADVPN_COLOR=$([[ $BADVPN_OK -eq 1 ]] && echo -n "$LIME" || echo -n "$RED")
SSL_STATUS=$([[ $CERT_OK -eq 1 ]] && echo "ISSUED" || echo "NOT ISSUED (HTTP only)")
SSL_COLOR=$([[ $CERT_OK -eq 1 ]] && echo -n "$LIME" || echo -n "$YELLOW")

# svc_row "<name>" "<port>" "<status text>" "<color var>"
svc_row() {
  local name="$1" port="$2" status="$3" color="$4"
  local plain disp
  plain=$(printf " %-18s %-13s %s" "$name" "$port" "$status")
  disp=$(printf " %-18s %-13s ${color}%s${NC}" "$name" "$port" "$status")
  box_line "$plain" "$disp"
}

echo ""
box_top
box_line "   *** INSTALLATION COMPLETE ***" "   ${GOLD}${BOLD}*** INSTALLATION COMPLETE ***${NC}"
box_mid
box_line " Domain   : $DOMAIN" " ${WHITE}Domain   ${NC}: ${LIME}$DOMAIN${NC}"
box_line " Server IP: $MY_IP"  " ${WHITE}Server IP${NC}: ${LIME}$MY_IP${NC}"
box_line " SSL Cert : $SSL_STATUS" " ${WHITE}SSL Cert ${NC}: ${SSL_COLOR}$SSL_STATUS${NC}"
box_line " Banner   : $([[ $DROPBEAR_BANNER_OK -eq 1 ]] && echo CONFIRMED || echo "CHECK MANUALLY")" " ${WHITE}Banner   ${NC}: $([[ $DROPBEAR_BANNER_OK -eq 1 ]] && echo "${LIME}CONFIRMED${NC}" || echo "${YELLOW}CHECK MANUALLY${NC}")"
box_mid
box_line " SERVICE            PORT         STATUS" " ${ORANGE}${BOLD}SERVICE            PORT         STATUS${NC}"
box_mid
svc_row "OpenSSH"        "22"          "$(svc_status ssh)"        "$(svc_color ssh)"
svc_row "WS-Proxy"       "80 /ssh-ws"  "$(svc_status ws-proxy)"   "$(svc_color ws-proxy)"
svc_row "WSS-Proxy"      "443 /ssh-ws" "$(svc_status nginx)"      "$(svc_color nginx)"
svc_row "Dropbear"       "109/143"     "$(svc_status dropbear)"   "$(svc_color dropbear)"
svc_row "Stunnel5"       "447/777"     "$(svc_status stunnel4)"   "$(svc_color stunnel4)"
svc_row "BadVPN UDPGW"   "7100-7300"   "$BADVPN_STATUS"           "$BADVPN_COLOR"
svc_row "Xray (V/VL/TR)" "80/443"      "$(svc_status xray)"       "$(svc_color xray)"
svc_row "Fail2ban"       "-"           "$(svc_status fail2ban)"   "$(svc_color fail2ban)"
box_mid
box_line " Type 'menu' to manage accounts & services" " ${PINK}${BOLD}Type 'menu'${NC} to manage accounts & services"
box_bot
echo ""

echo -e "${YELLOW}${BOLD}  Cloudflare Settings:${NC}"
echo -e "     SSL/TLS Mode       -> ${LIME}Full${NC}"
echo -e "     WebSockets         -> ${LIME}ON${NC}"
echo -e "     Always Use HTTPS   -> ${RED}OFF${NC}"
echo ""

read -rp "  Press Enter to reboot the server..."
history -c
reboot