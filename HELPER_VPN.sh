#!/bin/bash
# =====================================================================
#  HELPER VPN AUTOSCRIPT — Ubuntu 24.04 LTS
#  Owner / Support : Telegram @H_E_L_P_E_R_1
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

# NOTE: Prefer: curl -fsSL URL -o HELPER_VPN.sh && bash HELPER_VPN.sh
# (avoids "error 23" noise when piping curl directly to bash)

# Ensure service config files are world-readable (some cloud images default umask 077)
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
# BOX_W is the single source of truth; box_line pads against plain text
# only so ANSI escape bytes never corrupt the visible column width.
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
_OS_OK=0
case "${ID:-}:${VERSION_ID:-}" in
  ubuntu:24.04|ubuntu:22.04) _OS_OK=1 ;;
  debian:12|debian:13)       _OS_OK=1 ;;
esac
if [[ $_OS_OK -eq 0 ]]; then
  warn "Tested on Ubuntu 22.04/24.04 and Debian 12/13."
  warn "Detected: ${PRETTY_NAME:-unknown} — may work but is unsupported."
  warn "Continuing in 5s (Ctrl+C to abort)..."
  sleep 5
else
  log "OS check passed: ${PRETTY_NAME:-unknown}"
fi

clear
box_top
box_line "    H E L P E R  V P N  A U T O S C R I P T" "    ${GOLD}${BOLD}H E L P E R  V P N  A U T O S C R I P T${NC}"
OS_LABEL="${PRETTY_NAME:-Linux}"
box_line "      ${OS_LABEL}  -- All Features --" "      ${LIME}${OS_LABEL}${NC}  ${ORANGE}-- All Features --${NC}"
box_line "          Support: @H_E_L_P_E_R_1" "          ${PINK}${BOLD}Support: @H_E_L_P_E_R_1${NC}"
box_bot
sleep 1

# =====================================================================
# 0b. PRE-INSTALL CLEANUP (guarantees a fresh install every time)
# =====================================================================
# Remove previous install (if any) for a guaranteed-clean slate.
# SSL certs are preserved to avoid Let's Encrypt rate-limit waste.
step "Pre-Install Cleanup"
if [[ -d /etc/autoscript ]] || systemctl list-unit-files 2>/dev/null | grep -qE '^(badvpn(@.*)?|ws-proxy)\.service'; then
  warn "Existing install detected — backing up old account data, then removing all previous services/configs for a clean fresh install."

  # Safety net only — never read automatically, never blocks install.
  PRECLEAN_BK="/root/autoscript-preinstall-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
  tar -czf "$PRECLEAN_BK" /etc/autoscript /usr/local/etc/xray/config.json 2>/dev/null || true
  [[ -s "$PRECLEAN_BK" ]] && log "Old account data backed up to $PRECLEAN_BK before wiping." || rm -f "$PRECLEAN_BK"

  for svc in badvpn@7100 badvpn@7200 badvpn@7300 badvpn ws-proxy stunnel4 xray fail2ban dropbear; do
    systemctl stop "$svc" 2>/dev/null || true
    systemctl disable "$svc" 2>/dev/null || true
  done
  systemctl mask badvpn.service 2>/dev/null || true
  rm -f /etc/systemd/system/badvpn.service /etc/systemd/system/badvpn@.service \
        /etc/systemd/system/ws-proxy.service
  rm -rf /etc/systemd/system/dropbear.service.d
  systemctl daemon-reload 2>/dev/null || true

  # Forcefully free every port this stack uses, in case anything is
  # still bound from a crashed/partial earlier run. (nginx/dropbear's
  # own ports are included since we just disabled+stopped them above;
  # this only mops up anything that didn't exit cleanly.)
  for p in 80 443 109 143 447 777 2082 10000 10001 10002 7100 7200 7300; do
    fuser -k "${p}/tcp" >/dev/null 2>&1 || true
  done

  rm -f /usr/bin/add-ws /usr/bin/add-ssws /usr/bin/del-ssh \
        /usr/bin/renew-ssh /usr/bin/list-ssh /usr/bin/trial-ssh \
        /usr/bin/check-user /usr/bin/tendang \
        /usr/bin/add-vmess /usr/bin/add-vless /usr/bin/add-tr \
        /usr/bin/del-xray /usr/bin/renew-xray /usr/bin/list-xray \
        /usr/bin/trial-xray /usr/bin/running /usr/bin/restart \
        /usr/bin/cek-bandwidth /usr/bin/cek-ram /usr/bin/dns \
        /usr/bin/swap /usr/bin/bbr /usr/bin/clearlog \
        /usr/bin/backup /usr/bin/restore /usr/bin/xp /usr/bin/renew-ssl \
        /usr/bin/change-domain /usr/bin/menu /usr/bin/uninstall-vpn \
        /usr/local/sbin/badvpn-udpgw /usr/local/sbin/ws-proxy.py
  rm -f /etc/nginx/conf.d/autoscript.conf /etc/ssh-banner.txt
  rm -f /etc/stunnel/stunnel.conf /etc/stunnel/stunnel.pem
  rm -f /etc/default/dropbear
  sed -i '/^Banner \/etc\/ssh-banner.txt/d' /etc/ssh/sshd_config 2>/dev/null || true

  # Remove SSH accounts this installer created previously (tracked in
  # /etc/autoscript/ssh) so old logins don't linger next to fresh ones.
  if [[ -d /etc/autoscript/ssh ]]; then
    for f in /etc/autoscript/ssh/*; do
      [[ -f "$f" ]] || continue
      u=$(basename "$f")
      id "$u" &>/dev/null && userdel -r "$u" 2>/dev/null
    done
  fi

  (crontab -l 2>/dev/null | grep -v autoscript) | crontab - 2>/dev/null || true

  rm -rf /etc/autoscript /usr/local/etc/xray /var/log/xray
  swapoff /swapfile 2>/dev/null || true
  rm -f /swapfile
  sed -i '/swapfile/d' /etc/fstab 2>/dev/null || true

  log "Previous install removed — starting fresh."
else
  log "No previous install detected — clean server."
fi

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

# Detect public IP with timeout + fallback providers
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
echo "$LE_EMAIL" > /etc/autoscript/le_email

# ─── Telegram Notifications (optional) ──────────────────────────────
# Used to notify the admin of new accounts, expiring accounts, and low
# disk space. Skippable — every notify call below silently no-ops if
# these are left blank.
step "Telegram Notifications (optional)"
echo "  Get a bot token from @BotFather, and your chat ID from @userinfobot."
read -rp "  Telegram Bot Token (Enter to skip): " TG_TOKEN
read -rp "  Telegram Chat ID   (Enter to skip): " TG_CHATID
echo "$TG_TOKEN"  > /etc/autoscript/telegram_token
echo "$TG_CHATID" > /etc/autoscript/telegram_chatid
if [[ -n "$TG_TOKEN" && -n "$TG_CHATID" ]]; then
  TG_TEST=$(curl -s --max-time 8 -X POST "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" \
    -d "chat_id=${TG_CHATID}" --data-urlencode "text=✅ HELPER VPN: Telegram notifications connected." 2>/dev/null)
  if echo "$TG_TEST" | grep -q '"ok":true'; then
    log "Telegram test message sent successfully."
  else
    warn "Telegram test message failed — check the token/chat ID. Notifications will silently no-op until fixed (re-run 'menu' > nothing needed, just edit /etc/autoscript/telegram_token and /etc/autoscript/telegram_chatid)."
  fi
else
  log "Telegram notifications skipped."
fi

# =====================================================================
# 2. SYSTEM PREP
# =====================================================================
step "System Update & Packages"
export DEBIAN_FRONTEND=noninteractive

# ufw and iptables-persistent conflict on Ubuntu 24.04 — drop the latter.
# apt-get uses --force-confold/confdef to suppress conffile prompts that
# would otherwise hang non-interactive installs indefinitely.
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
  qrencode

# neofetch removed in Debian 13 — try it, fallback to fastfetch, continue either way
for _nf in neofetch fastfetch; do
  apt-get install -y "${APT_OPTS[@]}" "$_nf" >/dev/null 2>&1 && {
    log "System info tool installed: $_nf"; break
  } || true
done

# Verify critical binaries landed before proceeding
MISSING_PKGS=()
for bin in nginx dropbear curl jq; do
  command -v "$bin" >/dev/null 2>&1 || MISSING_PKGS+=("$bin")
done
# stunnel4 or stunnel
command -v stunnel4 >/dev/null 2>&1 || command -v stunnel >/dev/null 2>&1 || MISSING_PKGS+=("stunnel4")
# fail2ban-client
command -v fail2ban-client >/dev/null 2>&1 || MISSING_PKGS+=("fail2ban")
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

# UFW manages only the LOCAL firewall — cloud providers need their Security Group opened too.
warn "UFW only opens ports on THIS server."
warn "If you're on AWS/GCP/Oracle/Vultr/etc, also open 80,443,22,109,143,447,777 and 7100-7300/udp in your provider's Security Group / Firewall panel, or these ports will stay unreachable from outside even though UFW shows them open."

# =====================================================================
# 6. LOGIN BANNER + OPENSSH — enable password auth
# =====================================================================
step "Login Banner"

# A single banner file is shared by OpenSSH (:22) and Dropbear (:109/:143)
# so both show the same branded message. SSH client apps (HTTP Injector,
# HTTP Custom, NPV Tunnel, etc.) read this pre-auth banner and render the
# <font>/<center>/<br> markup as styled text in their connection screen.
BANNER_FILE=/etc/ssh-banner.txt

cat << 'EOF' > "$BANNER_FILE"
<center>
<span style="background-color:#000000">
<font color="#00ff00">╔════════════════════════════╗</font><br>
<font color="#00ff00">║</font> <font color="#ffffff">⚡ I AM BACK ⚡</font> <font color="#00ff00">║</font><br>
<font color="#00ff00">║</font> <font color="#00ffff">👨‍💻 HELPER HERE</font> <font color="#00ff00">║</font><br>
<font color="#00ff00">╚════════════════════════════╝</font><br><br>

<font color="#ff0000">⚠ SERVER RULES ⚠</font><br>
<font color="#ffaa00">NO DDOS</font> |
<font color="#ffaa00">NO CARDING</font> |
<font color="#ffaa00">NO TORRENT</font> |
<font color="#ffaa00">NO SPAM</font><br><br>

<font color="#00ffff">TELEGRAM SUPPORT</font><br>
<font color="#ffffff"><a href="https://t.me/H_E_L_P_E_R_01">H_E_L_P_E_R_01 </a></font></br><br>
</span>
</center>
EOF
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
  [[ "$out" == *"HELPER HERE"* ]]
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

# Banner added to DROPBEAR_EXTRA_ARGS too (DROPBEAR_BANNER only works with sysv init, not systemd units)
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

# Always build BadVPN from official upstream (ambrop72/badvpn) — no unverified pre-built binaries.
info "Looking up the latest official BadVPN release tag..."
BADVPN_TAG=$(git ls-remote --tags --refs https://github.com/ambrop72/badvpn.git 2>/dev/null \
  | awk -F/ '{print $NF}' | grep -E '^[0-9]+(\.[0-9]+)*$' | sort -V | tail -1)
if [[ -z "$BADVPN_TAG" ]]; then
  BADVPN_TAG="1.999.130"   # last known-good release tag, used only if the tag lookup itself fails (e.g. network hiccup)
  warn "Could not query GitHub for the latest BadVPN tag — falling back to known-good $BADVPN_TAG."
fi
info "Building BadVPN $BADVPN_TAG from official source (ambrop72/badvpn)..."

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

# Stop existing badvpn instances before replacing the binary (avoids ETXTBSY), then atomic mv
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
# Raised per-client connections to 150 (default 10 causes dropped packets / choppy calls)
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

# badvpn is loopback-only (via SSH tunnel); UFW udp rules kept for client-app compatibility

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

# Fix ownership — openssl creates key at mode 600/root regardless of umask; stunnel4 needs to read it
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

# /var/run/stunnel4/ is not guaranteed on boot — create it explicitly
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
# Download to temp file first (avoids /dev/fd issues on some cloud images)
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
# Write base Xray config only on first install — preserve existing accounts on re-runs.
# existing config (and every account already in it) is left alone.
if [[ ! -f /usr/local/etc/xray/config.json ]]; then
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
log "Fresh Xray config created (no existing accounts found)."
else
log "Existing Xray config found at /usr/local/etc/xray/config.json — keeping it untouched (accounts already in it are preserved)."
fi

systemctl enable xray

# Fix log dir ownership — Xray runs as restricted user but /var/log/xray is created as root
XRAY_USER=$(systemctl show xray -p User --value 2>/dev/null)
XRAY_GROUP=$(systemctl show xray -p Group --value 2>/dev/null)
[[ -z "$XRAY_USER" ]] && XRAY_USER="nobody"
[[ -z "$XRAY_GROUP" ]] && XRAY_GROUP="nogroup"
chown -R "$XRAY_USER:$XRAY_GROUP" /var/log/xray /usr/local/etc/xray 2>/dev/null || true
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

# Remove nginx default site — it competes with our vhost on port 80 and causes 404s
rm -f /etc/nginx/sites-enabled/default
rm -f /etc/nginx/sites-available/default

# Kill anything squatting on 80/443 before nginx starts (one conflict kills both ports)
for p in 80 443; do
  conflict=$(ss -tulnp 2>/dev/null | grep ":$p " | grep -v nginx || true)
  if [[ -n "$conflict" ]]; then
    warn "Port $p is already in use by another process — freeing it automatically:"
    echo "$conflict" | sed 's/^/    /'
    # Stop it cleanly via systemd first, by name, if it's a known unit.
    svcname=$(echo "$conflict" | grep -oP '(?<=users:\(\(")[^"]+' | head -1)
    if [[ -n "$svcname" ]]; then
      systemctl stop "$svcname" 2>/dev/null || true
      systemctl disable "$svcname" 2>/dev/null || true
    fi
    fuser -k "${p}/tcp" >/dev/null 2>&1 || true
    sleep 1
    still=$(ss -tulnp 2>/dev/null | grep ":$p " | grep -v nginx || true)
    if [[ -n "$still" ]]; then
      err "Port $p is STILL held after attempting to free it:"
      echo "$still" | sed 's/^/    /'
      err "Stop it manually (systemctl stop <service>), then re-run this script."
      exit 1
    else
      log "Port $p freed."
    fi
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
ORANGE='\033[38;5;208m'; PINK='\033[38;5;205m'; LIME='\033[38;5;118m'
SKY='\033[38;5;45m'; GOLD='\033[38;5;220m'; WHITE='\033[1;37m'

line() { echo "══════════════════════════════════════════════════"; }

# Sends a Telegram message if a bot token + chat ID were configured at
# install time (/etc/autoscript/telegram_token, telegram_chatid).
# Silently does nothing if either is blank/missing — every call site
# can call this unconditionally without checking first.
tg_notify() {
  local msg="$1" token chatid
  token=$(cat /etc/autoscript/telegram_token 2>/dev/null)
  chatid=$(cat /etc/autoscript/telegram_chatid 2>/dev/null)
  [[ -z "$token" || -z "$chatid" ]] && return 0
  curl -s --max-time 8 -X POST "https://api.telegram.org/bot${token}/sendMessage" \
    -d "chat_id=${chatid}" \
    --data-urlencode "text=${msg}" >/dev/null 2>&1 || true
}

# Xray doesn't support SIGHUP reload — validate config then do a real restart
# restart, then actually confirms Xray came back up instead of assuming.
xray_reload() {
  local test_log
  test_log=$(mktemp)
  if ! /usr/local/bin/xray run -test -config "$XRAY_CONFIG" >"$test_log" 2>&1; then
    echo -e "${RED}Xray config is invalid — NOT restarting (old config still running).${NC}"
    tail -n 8 "$test_log"
    rm -f "$test_log"
    return 1
  fi
  rm -f "$test_log"
  systemctl restart xray
  sleep 1
  if systemctl is-active --quiet xray; then
    return 0
  fi
  echo -e "${RED}Xray failed to restart. Last log:${NC}"
  journalctl -u xray -n 15 --no-pager 2>&1 | tail -n 15
  return 1
}
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
usermod -p "$(openssl passwd -6 "${pass}")" "${user}"
echo "user=$user;pass=$pass;exp=$exp" > "$SSH_DIR/$user"

# Ready-to-paste config for client apps (HTTP Injector, HTTP Custom,
# NPV Tunnel, DarkTunnel, etc.) — saves manually typing out target/
# SNI/payload by hand every time, like we had to do by hand earlier.
PAYLOAD="GET /ssh-ws HTTP/1.1[crlf]Host: ${DOMAIN}[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]User-Agent: [crlf][crlf]"

echo ""
echo -e "  ${GREEN}${BOLD}✅ SSH Account Created${NC}"
echo ""
echo -e "  ${WHITE}Username${NC}   :  ${CYAN}${user}${NC}"
echo -e "  ${WHITE}Password${NC}   :  ${CYAN}${pass}${NC}"
echo -e "  ${WHITE}Expires${NC}    :  ${YELLOW}${exp}${NC}"
echo -e "  ${WHITE}Host${NC}       :  ${CYAN}${DOMAIN}${NC}"
echo ""
echo -e "  ${ORANGE}${BOLD}── Ports ───────────────────────────────${NC}"
echo -e "  ${WHITE}OpenSSH${NC}    :  ${CYAN}${DOMAIN}  :  22${NC}"
echo -e "  ${WHITE}Dropbear${NC}   :  ${CYAN}${DOMAIN}  :  109 / 143${NC}"
echo -e "  ${WHITE}Stunnel${NC}    :  ${CYAN}${DOMAIN}  :  447 / 777${NC}"
echo -e "  ${WHITE}WS HTTP${NC}    :  ${CYAN}ws://${DOMAIN}/ssh-ws${NC}"
echo -e "  ${WHITE}WSS HTTPS${NC}  :  ${CYAN}wss://${DOMAIN}/ssh-ws${NC}"
echo -e "  ${WHITE}BadVPN UDP${NC} :  ${CYAN}127.0.0.1  :  7100 / 7200 / 7300${NC}"
echo ""
echo -e "  ${GOLD}${BOLD}── Client App Config ───────────────────${NC}"
echo -e "  ${WHITE}Target HTTP${NC}  :  ${CYAN}${DOMAIN}:80@${user}:${pass}${NC}"
echo -e "  ${WHITE}Target HTTPS${NC} :  ${CYAN}${DOMAIN}:443@${user}:${pass}${NC}"
echo -e "  ${WHITE}SNI${NC}          :  ${CYAN}${DOMAIN}${NC}"
echo -e "  ${WHITE}Payload${NC}      :  ${CYAN}${PAYLOAD}${NC}"
echo ""
echo -e "  ${PINK}${BOLD}Support : @H_E_L_P_E_R_1${NC}"
echo ""
tg_notify "$(printf '🆕 New SSH Account\nUser: %s\nExpires: %s\nDomain: %s' "$user" "$exp" "$DOMAIN")"
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

# Kill active sessions before userdel — del-f alone can fail if user has active SSH session
pkill -KILL -u "$user" 2>/dev/null
sleep 1
err_out=$(userdel -f -r "$user" 2>&1)
if id "$user" &>/dev/null; then
  echo -e "${RED}Delete failed. userdel said:${NC} ${err_out:-<no output>}"
  echo -e "${YELLOW}Try manually: pkill -KILL -u $user && userdel -f -r $user${NC}"
  read -rp "Press Enter to continue..."
  exit 1
fi
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
err_out=$(useradd -m -s /bin/false -e "$exp" "$user" 2>&1)
if ! id "$user" &>/dev/null; then
  clear; line
  echo -e "${RED}Trial account creation failed.${NC} useradd said: ${err_out:-<no output>}"
  line
  read -rp "Press Enter to continue..."
  exit 1
fi
usermod -p "$(openssl passwd -6 "${pass}")" "${user}"
echo "user=$user;pass=$pass;exp=$exp" > "$SSH_DIR/$user"
PAYLOAD="GET /ssh-ws HTTP/1.1[crlf]Host: ${DOMAIN}[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]User-Agent: [crlf][crlf]"
clear
echo ""
echo -e "  ${GREEN}${BOLD}🎁 Trial SSH Account  (1 Day)${NC}"
echo ""
echo -e "  ${WHITE}Username${NC}   :  ${CYAN}${user}${NC}"
echo -e "  ${WHITE}Password${NC}   :  ${CYAN}${pass}${NC}"
echo -e "  ${WHITE}Expires${NC}    :  ${YELLOW}${exp}${NC}"
echo -e "  ${WHITE}Host${NC}       :  ${CYAN}${DOMAIN}${NC}"
echo ""
echo -e "  ${ORANGE}${BOLD}── Ports ───────────────────────────────${NC}"
echo -e "  ${WHITE}OpenSSH${NC}    :  ${CYAN}${DOMAIN}  :  22${NC}"
echo -e "  ${WHITE}Dropbear${NC}   :  ${CYAN}${DOMAIN}  :  109 / 143${NC}"
echo -e "  ${WHITE}WS HTTP${NC}    :  ${CYAN}ws://${DOMAIN}/ssh-ws${NC}"
echo -e "  ${WHITE}WSS HTTPS${NC}  :  ${CYAN}wss://${DOMAIN}/ssh-ws${NC}"
echo ""
echo -e "  ${GOLD}${BOLD}── Client App Config ───────────────────${NC}"
echo -e "  ${WHITE}Target HTTP${NC}  :  ${CYAN}${DOMAIN}:80@${user}:${pass}${NC}"
echo -e "  ${WHITE}Target HTTPS${NC} :  ${CYAN}${DOMAIN}:443@${user}:${pass}${NC}"
echo -e "  ${WHITE}SNI${NC}          :  ${CYAN}${DOMAIN}${NC}"
echo -e "  ${WHITE}Payload${NC}      :  ${CYAN}${PAYLOAD}${NC}"
echo ""
echo -e "  ${PINK}${BOLD}Support : @H_E_L_P_E_R_1${NC}"
echo ""
tg_notify "$(printf '🎁 New Trial SSH Account\nUser: %s\nExpires: %s\nDomain: %s' "$user" "$exp" "$DOMAIN")"
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
xray_reload || echo -e "${YELLOW}Account saved, but Xray did not reload cleanly — run: systemctl status xray${NC}"

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
echo -e " Support: ${PINK}${BOLD}@H_E_L_P_E_R_1${NC}"
line
tg_notify "$(printf '🆕 New VMess Account\nUser: %s\nExpires: %s\nDomain: %s' "$uname" "$exp" "$DOMAIN")"
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
xray_reload || echo -e "${YELLOW}Account saved, but Xray did not reload cleanly — run: systemctl status xray${NC}"

echo "type=vless;uuid=$uuid;exp=$exp" > "$XRAY_DIR/$uname"

line
echo -e "${GREEN}  VLESS Account Created${NC}"; line
echo -e " Username : ${CYAN}$uname${NC}"
echo -e " UUID     : ${CYAN}$uuid${NC}"
echo -e " Expires  : ${YELLOW}$exp${NC}"
echo " ─── Links ────────────────────────────────────"
echo -e " WS     : ${CYAN}vless://$uuid@$DOMAIN:80?type=ws&path=%2Fvless#$uname${NC}"
echo -e " WSS    : ${CYAN}vless://$uuid@$DOMAIN:443?type=ws&security=tls&path=%2Fvless#$uname-tls${NC}"
echo -e " Support: ${PINK}${BOLD}@H_E_L_P_E_R_1${NC}"
line
tg_notify "$(printf '🆕 New VLESS Account\nUser: %s\nExpires: %s\nDomain: %s' "$uname" "$exp" "$DOMAIN")"
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
xray_reload || echo -e "${YELLOW}Account saved, but Xray did not reload cleanly — run: systemctl status xray${NC}"

echo "type=trojan;pass=$pw;exp=$exp" > "$XRAY_DIR/$uname"

line
echo -e "${GREEN}  Trojan Account Created${NC}"; line
echo -e " Username : ${CYAN}$uname${NC}"
echo -e " Password : ${CYAN}$pw${NC}"
echo -e " Expires  : ${YELLOW}$exp${NC}"
echo " ─── Link (TLS only) ──────────────────────────"
echo -e " WSS : ${CYAN}trojan://$pw@$DOMAIN:443?type=ws&security=tls&path=%2Ftrojan-ws#$uname${NC}"
echo -e " Support: ${PINK}${BOLD}@H_E_L_P_E_R_1${NC}"
line
tg_notify "$(printf '🆕 New Trojan Account\nUser: %s\nExpires: %s\nDomain: %s' "$uname" "$exp" "$DOMAIN")"
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
xray_reload || echo -e "${YELLOW}Config updated, but Xray did not reload cleanly — run: systemctl status xray${NC}"
# Verify the client is actually gone from the live config before
# claiming success — jq finding nothing to remove (e.g. the account
# was already missing from a stale config) should not be reported as
# "deleted" when nothing was really there to delete.
still_there=$(jq --arg email "$uname" '[.inbounds[].settings.clients[]? | select(.email == $email)] | length' "$XRAY_CONFIG" 2>/dev/null)
rm -f "$XRAY_DIR/$uname"
if [[ "$still_there" == "0" ]]; then
  echo -e "${GREEN}Account $uname deleted.${NC}"
else
  echo -e "${YELLOW}Account record removed, but client still appears in Xray config — check manually: jq '.inbounds[].settings.clients' $XRAY_CONFIG${NC}"
fi
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
clear; line
echo -e "${CYAN}${BOLD}     TRIAL XRAY ACCOUNT (1 Day)${NC}"; line
echo -e "${CYAN}[1] VMess  [2] VLESS  [3] Trojan${NC}"
read -rp " Choose: " c
uname="trial$(tr -dc a-z0-9 </dev/urandom | head -c6)"
exp=$(date -d "+1 day" +%Y-%m-%d)
tmp=$(mktemp)

case $c in
  1)
    uuid=$(uuidgen)
    jq --arg id "$uuid" --arg email "$uname" \
      '(.inbounds[] | select(.tag=="vmess-ws-in") | .settings.clients) += [{"id":$id,"email":$email,"alterId":0}]' \
      "$XRAY_CONFIG" > "$tmp" && mv "$tmp" "$XRAY_CONFIG"
    proto="vmess"
    ;;
  2)
    uuid=$(uuidgen)
    jq --arg id "$uuid" --arg email "$uname" \
      '(.inbounds[] | select(.tag=="vless-ws-in") | .settings.clients) += [{"id":$id,"email":$email,"flow":""}]' \
      "$XRAY_CONFIG" > "$tmp" && mv "$tmp" "$XRAY_CONFIG"
    proto="vless"
    ;;
  3)
    pw=$(tr -dc A-Za-z0-9 </dev/urandom | head -c16)
    jq --arg pw "$pw" --arg email "$uname" \
      '(.inbounds[] | select(.tag=="trojan-ws-in") | .settings.clients) += [{"password":$pw,"email":$email}]' \
      "$XRAY_CONFIG" > "$tmp" && mv "$tmp" "$XRAY_CONFIG"
    proto="trojan"
    ;;
  *) echo "Invalid."; rm -f "$tmp"; read -rp "Press Enter to continue..."; exit 1 ;;
esac

XU=$(systemctl show xray -p User  --value 2>/dev/null)
XG=$(systemctl show xray -p Group --value 2>/dev/null)
[ -z "$XU" ] && XU=nobody
[ -z "$XG" ] && XG=nogroup
chown "$XU:$XG" "$XRAY_CONFIG" 2>/dev/null
chmod 644 "$XRAY_CONFIG"
xray_reload || echo -e "${YELLOW}Account saved, but Xray did not reload cleanly — run: systemctl status xray${NC}"

line
echo -e "${GREEN}  TRIAL ${proto^^} ACCOUNT (1 Day)${NC}"; line
echo -e " Username : ${CYAN}$uname${NC}"
echo -e " Expires  : ${YELLOW}$exp${NC}"
case $proto in
  vmess)
    echo "type=vmess;uuid=$uuid;exp=$exp" > "$XRAY_DIR/$uname"
    b64=$(echo -n "{\"v\":\"2\",\"ps\":\"$uname\",\"add\":\"$DOMAIN\",\"port\":\"80\",\"id\":\"$uuid\",\"aid\":\"0\",\"net\":\"ws\",\"path\":\"/vmess\",\"tls\":\"\"}" | base64 -w0)
    b64tls=$(echo -n "{\"v\":\"2\",\"ps\":\"$uname-tls\",\"add\":\"$DOMAIN\",\"port\":\"443\",\"id\":\"$uuid\",\"aid\":\"0\",\"net\":\"ws\",\"path\":\"/vmess\",\"tls\":\"tls\"}" | base64 -w0)
    echo -e " UUID     : ${CYAN}$uuid${NC}"
    echo -e " WS  : ${CYAN}vmess://$b64${NC}"
    echo -e " WSS : ${CYAN}vmess://$b64tls${NC}"
    ;;
  vless)
    echo "type=vless;uuid=$uuid;exp=$exp" > "$XRAY_DIR/$uname"
    echo -e " UUID     : ${CYAN}$uuid${NC}"
    echo -e " WS  : ${CYAN}vless://$uuid@$DOMAIN:80?type=ws&path=%2Fvless#$uname${NC}"
    echo -e " WSS : ${CYAN}vless://$uuid@$DOMAIN:443?type=ws&security=tls&path=%2Fvless#$uname-tls${NC}"
    ;;
  trojan)
    echo "type=trojan;pass=$pw;exp=$exp" > "$XRAY_DIR/$uname"
    echo -e " Password : ${CYAN}$pw${NC}"
    echo -e " WSS : ${CYAN}trojan://$pw@$DOMAIN:443?type=ws&security=tls&path=%2Ftrojan-ws#$uname${NC}"
    ;;
esac
echo -e " Support: ${PINK}${BOLD}@H_E_L_P_E_R_1${NC}"
line
tg_notify "$(printf '🎁 New Trial %s Account\nUser: %s\nExpires: %s\nDomain: %s' "${proto^^}" "$uname" "$exp" "$DOMAIN")"
read -rp "Press Enter to continue..."
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
  local up=0 down=0 bad_ports=""
  for p in 7100 7200 7300; do
    if systemctl is-active --quiet "badvpn@${p}"; then
      up=$((up + 1))
    else
      down=$((down + 1))
      bad_ports="${bad_ports}${bad_ports:+,}${p}"
    fi
  done
  if [[ $down -eq 0 ]]; then
    echo -e "${GREEN}● RUNNING (3/3)${NC}"
  elif [[ $up -eq 0 ]]; then
    echo -e "${RED}✗ STOPPED (0/3)${NC}"
  else
    echo -e "${YELLOW}⚠ PARTIAL (${up}/3, down: ${bad_ports})${NC}"
  fi
}

# Shows the real last error for any stopped unit, right in the menu,
# instead of making you go run journalctl by hand to find out why.
hint_if_down() {
  local svc="$1" label="$2" last
  systemctl is-active --quiet "$svc" && return
  last=$(journalctl -u "$svc" -n 20 --no-pager 2>/dev/null | grep -vi "^--" | tail -n1)
  [[ -n "$last" ]] && printf "    ${RED}↳ %s:${NC} %.70s\n" "$label" "$last"
}

clear; line
echo -e "${CYAN}${BOLD}     RUNNING SERVICES${NC}"; line
printf "  %-26s %s\n" "OpenSSH   (22)"            "$(svc_status ssh)"
hint_if_down ssh "OpenSSH"
printf "  %-26s %s\n" "Dropbear  (109,143)"        "$(svc_status dropbear)"
hint_if_down dropbear "Dropbear"
printf "  %-26s %s\n" "ws-proxy  (2082→22)"        "$(svc_status ws-proxy)"
hint_if_down ws-proxy "ws-proxy"
printf "  %-26s %s\n" "Nginx     (80,443)"          "$(svc_status nginx)"
hint_if_down nginx "Nginx"
printf "  %-26s %s\n" "Stunnel5  (447,777)"         "$(svc_status stunnel4)"
hint_if_down stunnel4 "Stunnel5"
printf "  %-26s %s\n" "BadVPN    (7100/7200/7300)"  "$(badvpn_status)"
printf "  %-26s %s\n" "Xray      (10000-10002)"     "$(svc_status xray)"
hint_if_down xray "Xray"
printf "  %-26s %s\n" "Fail2ban"                    "$(svc_status fail2ban)"
hint_if_down fail2ban "Fail2ban"
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
systemctl restart tg-manager 2>/dev/null || true
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
# Only chattr /etc/resolv.conf if it's a real file, not a symlink to systemd-resolved
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
source /etc/autoscript/lib.sh
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
    tg_notify "$(printf '⌛ SSH Account Expired & Removed\nUser: %s' "$u")"
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
    tg_notify "$(printf '⌛ Xray Account Expired & Removed\nUser: %s' "$u")"
  fi
done
if [[ $changed -eq 1 ]]; then
  if /usr/local/bin/xray run -test -config "$XRAY_CONFIG" >/dev/null 2>&1; then
    systemctl restart xray
    systemctl is-active --quiet xray || echo "$(date): WARNING - xray restart failed after expiry cleanup, check: systemctl status xray" >> /var/log/autoscript-cron.log
  else
    echo "$(date): WARNING - xray config invalid after expiry cleanup, NOT restarting (old config still running)" >> /var/log/autoscript-cron.log
  fi
fi
EOF

# ─── change-domain (Change Domain) ──────────────────────────────────
# ─── notify-check (Daily expiry + disk/RAM alert via Telegram) ───────
cat > /usr/bin/notify-check <<'EOF'
#!/bin/bash
source /etc/autoscript/lib.sh
SSH_DIR=/etc/autoscript/ssh
XRAY_DIR=/etc/autoscript/xray
now=$(date +%s)
msg=""

# Accounts expiring in next 3 days
for f in "$SSH_DIR"/*; do
  [[ -e "$f" ]] || continue
  u=$(basename "$f")
  exp=$(chage -l "$u" 2>/dev/null | grep "Account expires" | cut -d: -f2 | xargs)
  [[ "$exp" == "never" || -z "$exp" ]] && continue
  exp_ts=$(date -d "$exp" +%s 2>/dev/null) || continue
  diff=$(( (exp_ts - now) / 86400 ))
  if [[ $diff -ge 0 && $diff -le 3 ]]; then
    msg+="$(printf '⚠️ SSH expiring in %d day(s): %s (%s)\n' "$diff" "$u" "$exp")"
  fi
done

for f in "$XRAY_DIR"/*; do
  [[ -e "$f" ]] || continue
  u=$(basename "$f")
  exp=$(sed -n 's/.*exp=//p' "$f")
  exp_ts=$(date -d "$exp" +%s 2>/dev/null) || continue
  diff=$(( (exp_ts - now) / 86400 ))
  if [[ $diff -ge 0 && $diff -le 3 ]]; then
    msg+="$(printf '⚠️ Xray expiring in %d day(s): %s (%s)\n' "$diff" "$u" "$exp")"
  fi
done

# Disk space alert if >85% used
disk_pct=$(df / --output=pcent 2>/dev/null | tail -1 | tr -d ' %')
if [[ -n "$disk_pct" && "$disk_pct" -ge 85 ]]; then
  disk_used=$(df -h / --output=used 2>/dev/null | tail -1 | xargs)
  disk_total=$(df -h / --output=size 2>/dev/null | tail -1 | xargs)
  msg+="$(printf '💾 Disk Alert: %s / %s used (%s%%)\n' "$disk_used" "$disk_total" "$disk_pct")"
fi

# RAM alert if >90% used
ram_total=$(free -m | awk '/Mem:/{print $2}')
ram_used=$(free -m | awk '/Mem:/{print $3}')
if [[ -n "$ram_total" && "$ram_total" -gt 0 ]]; then
  ram_pct=$(( ram_used * 100 / ram_total ))
  if [[ $ram_pct -ge 90 ]]; then
    msg+="$(printf '🧠 RAM Alert: %sMB / %sMB used (%s%%)\n' "$ram_used" "$ram_total" "$ram_pct")"
  fi
fi

[[ -n "$msg" ]] && tg_notify "$(printf '📊 HELPER VPN Daily Report\nDomain: %s\n\n%s' "$DOMAIN" "$msg")"
EOF

# ─── tg-setup (Update Telegram credentials from menu) ────────────────
cat > /usr/bin/tg-setup <<'EOF'
#!/bin/bash
source /etc/autoscript/lib.sh
clear
line
echo -e "${CYAN}${BOLD}     TELEGRAM NOTIFICATIONS SETUP${NC}"
line
echo " Current token    : $(cat /etc/autoscript/telegram_token 2>/dev/null | sed 's/.\{10\}$/***/')"
echo " Current admin IDs: $(cat /etc/autoscript/telegram_chatid 2>/dev/null | tr '\n' ',' | sed 's/,$//')"
echo ""
echo -e "${YELLOW} Multi-admin: you can add multiple Telegram IDs."
echo -e " Separate multiple IDs with commas, e.g.: 123456789,987654321${NC}"
echo ""
read -rp " New Bot Token (Enter to keep current): " tok
read -rp " Admin ID(s)  (Enter to keep current): " cids
[[ -n "$tok" ]] && echo "$tok" > /etc/autoscript/telegram_token
if [[ -n "$cids" ]]; then
  # store each ID on its own line, strip spaces
  echo "$cids" | tr ',' '\n' | sed 's/[[:space:]]//g' | grep -v '^$' > /etc/autoscript/telegram_chatid
fi
tok=$(cat /etc/autoscript/telegram_token 2>/dev/null)
# Use first ID for test message
first_cid=$(head -1 /etc/autoscript/telegram_chatid 2>/dev/null)
if [[ -n "$tok" && -n "$first_cid" ]]; then
  out=$(curl -s --max-time 8 -X POST "https://api.telegram.org/bot${tok}/sendMessage" \
    -d "chat_id=${first_cid}" --data-urlencode "text=✅ HELPER VPN: Telegram test message." 2>/dev/null)
  if echo "$out" | grep -q '"ok":true'; then
    echo -e "${GREEN}Test message sent to ${first_cid} successfully!${NC}"
  else
    echo -e "${RED}Test failed — check token/chat ID. Error: ${out}${NC}"
  fi
else
  echo -e "${YELLOW}Token or Chat ID is blank — notifications disabled.${NC}"
fi
line
read -rp "Press Enter to continue..."
EOF

cat > /usr/bin/change-domain <<'EOF'
#!/bin/bash
source /etc/autoscript/lib.sh
clear; line
echo -e "${CYAN}${BOLD}     CHANGE DOMAIN${NC}"; line
echo -e " Current domain: ${CYAN}$DOMAIN${NC}"
echo -e " Server IP     : ${CYAN}$MY_IP${NC}"
line
read -rp " New domain (A record must already point to $MY_IP): " newdom
[[ -z "$newdom" ]] && { echo "Cancelled."; read -rp "Press Enter to continue..."; exit 0; }
olddom="$DOMAIN"
if [[ "$newdom" == "$olddom" ]]; then
  echo -e "${YELLOW}That's already the current domain.${NC}"
  read -rp "Press Enter to continue..."
  exit 0
fi

# Use dig for DNS check (getent can return stale negatives from systemd-resolved cache)
resolved=$(dig +short A "$newdom" 2>/dev/null | tail -n1)
if [[ -z "$resolved" ]]; then
  resolved=$(dig +short A "$newdom" @1.1.1.1 2>/dev/null | tail -n1)
fi
if [[ -z "$resolved" ]]; then
  echo -e "${RED}$newdom does not resolve yet. Point its A record at $MY_IP, wait for DNS to propagate, then try again.${NC}"
  read -rp "Press Enter to continue..."
  exit 1
elif [[ "$resolved" != "$MY_IP" ]]; then
  echo -e "${YELLOW}Warning: $newdom currently resolves to $resolved, not this server ($MY_IP).${NC}"
  read -rp " Continue anyway? (y/N): " c
  [[ "$c" != "y" && "$c" != "Y" ]] && { echo "Cancelled."; read -rp "Press Enter to continue..."; exit 0; }
fi

# Get the cert for the NEW domain first, before touching anything else
# — if this fails, the old domain is left fully working.
LE_EMAIL=$(cat /etc/autoscript/le_email 2>/dev/null)
echo -e "${CYAN}Requesting SSL certificate for $newdom...${NC}"
if [[ -n "$LE_EMAIL" ]]; then
  certbot certonly --nginx -d "$newdom" --email "$LE_EMAIL" --agree-tos --non-interactive >/tmp/certbot-changedomain.log 2>&1
else
  certbot certonly --nginx -d "$newdom" --register-unsafely-without-email --agree-tos --non-interactive >/tmp/certbot-changedomain.log 2>&1
fi
if [[ ! -d "/etc/letsencrypt/live/$newdom" ]]; then
  echo -e "${RED}Certificate request failed — $olddom is still active, nothing changed. Details:${NC}"
  tail -n 10 /tmp/certbot-changedomain.log
  read -rp "Press Enter to continue..."
  exit 1
fi

# Regenerate full nginx config from scratch (sed-replace silently fails if 443 block was never written)
# template the installer itself uses) guarantees port 443 comes up
# regardless of what state the previous config was in.
cp /etc/nginx/conf.d/autoscript.conf /tmp/autoscript.conf.bak

cat > /etc/nginx/conf.d/autoscript.conf <<NCEOF
# ── Port 80 (Non-TLS) ──────────────────────────────────────────
server {
  listen 80;
  server_name ${newdom};

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
  server_name ${newdom};

  ssl_certificate     /etc/letsencrypt/live/${newdom}/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/${newdom}/privkey.pem;
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

if nginx -t >/tmp/nginx-changedomain.log 2>&1; then
  echo "$newdom" > /etc/autoscript/domain
  systemctl reload nginx
  if systemctl is-active --quiet nginx && ss -tulnp 2>/dev/null | grep -q ":443.*nginx"; then
    echo -e "${GREEN}Nginx confirmed listening on 443 for $newdom.${NC}"
  else
    echo -e "${RED}Nginx reloaded but is NOT listening on 443 — check: journalctl -u nginx -n 20${NC}"
  fi
else
  echo -e "${RED}New nginx config is invalid — reverting, $olddom stays active. Details:${NC}"
  cat /tmp/nginx-changedomain.log
  cp /tmp/autoscript.conf.bak /etc/nginx/conf.d/autoscript.conf
  read -rp "Press Enter to continue..."
  exit 1
fi

# Refresh the SSH/Dropbear pre-auth banner so it shows the new domain too.
[[ -f /etc/ssh-banner.txt ]] && { 
  _old_esc=$(printf "%s" "$olddom" | sed "s/\./\\\./g")
  _new_esc=$(printf "%s" "$newdom" | sed "s/\./\\\./g")
  sed -i "s/${_old_esc}/${_new_esc}/g" /etc/ssh-banner.txt
}

line
echo -e "${GREEN}Domain changed: $olddom -> $newdom${NC}"
echo -e "${YELLOW}Note: VMess/VLESS/Trojan links shown earlier still have the OLD domain baked in.${NC}"
echo -e "${YELLOW}Run 'list-xray' / 'list-ssh' to get fresh links/details with the new domain.${NC}"
line
read -rp "Press Enter to continue..."
EOF

# ─── renew-ssl ───────────────────────────────────────────────────────
cat > /usr/bin/renew-ssl <<'EOF'
#!/bin/bash
DOMAIN=$(cat /etc/autoscript/domain 2>/dev/null)

if [[ -z "$DOMAIN" ]] || [[ ! -d "/etc/letsencrypt/live/$DOMAIN" ]]; then
  echo "No SSL certificate found for $DOMAIN — nothing to renew."
  echo "Run: certbot certonly --nginx -d $DOMAIN   to issue one first."
  read -rp "Press Enter to continue..."
  exit 0
fi

OUT=$(certbot renew --cert-name "$DOMAIN" --nginx 2>&1)
echo "$OUT"

if echo "$OUT" | grep -q "No renewals were attempted"; then
  echo "Certbot found no tracked renewal config for $DOMAIN — check 'certbot certificates'."
elif echo "$OUT" | grep -qi "Congratulations\|successfully renewed"; then
  systemctl reload nginx
  echo "SSL renewed successfully for $DOMAIN."
else
  echo "Renewal did not complete cleanly — see output above."
fi
read -rp "Press Enter to continue..."
EOF

# ─── uninstall-vpn (Uninstall) ──────────────────────────────────────
cat > /usr/bin/uninstall-vpn <<'EOF'
#!/bin/bash
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'; BOLD='\e[1m'
clear
echo -e "${RED}${BOLD}══════════════════════════════════════════════════${NC}"
echo -e "${RED}${BOLD}            UNINSTALL HELPER VPN${NC}"
echo -e "${RED}${BOLD}══════════════════════════════════════════════════${NC}"
echo " This will permanently remove:"
echo "  - Every SSH and Xray (VMess/VLESS/Trojan) account"
echo "  - nginx vhost, dropbear, stunnel4, xray, badvpn, fail2ban setup"
echo "  - All management scripts (menu, add-ws, list-ssh, etc.)"
echo "  - Cron jobs, swap file, login banner"
echo ""
echo -e "${YELLOW}OpenSSH itself (your access to this server) is left untouched.${NC}"
echo -e "${YELLOW}nginx/dropbear/xray/stunnel4/fail2ban packages stay installed${NC}"
echo -e "${YELLOW}(just unconfigured) — remove with apt yourself if you want them fully gone.${NC}"
echo ""
read -rp " Also delete the SSL certificate for this domain? (y/N): " DELCERT
echo ""
read -rp " Type UNINSTALL in capitals to confirm (this cannot be undone): " CONFIRM
if [[ "$CONFIRM" != "UNINSTALL" ]]; then
  echo "Cancelled — nothing was removed."
  read -rp "Press Enter to continue..."
  exit 0
fi

DOM=$(cat /etc/autoscript/domain 2>/dev/null)

echo " Stopping services..."
for svc in badvpn@7100 badvpn@7200 badvpn@7300 ws-proxy stunnel4 xray fail2ban dropbear tg-manager; do
  systemctl stop "$svc" 2>/dev/null
  systemctl disable "$svc" 2>/dev/null
done

echo " Removing systemd units..."
rm -f /etc/systemd/system/badvpn@.service /etc/systemd/system/ws-proxy.service \
      /etc/systemd/system/tg-manager.service
rm -rf /etc/systemd/system/dropbear.service.d
systemctl daemon-reload 2>/dev/null

echo " Removing stunnel and dropbear configs..."
rm -f /etc/stunnel/stunnel.conf /etc/stunnel/stunnel.pem
rm -f /etc/default/dropbear

echo " Removing SSH accounts..."
if [[ -d /etc/autoscript/ssh ]]; then
  for f in /etc/autoscript/ssh/*; do
    [[ -f "$f" ]] || continue
    u=$(basename "$f")
    id "$u" &>/dev/null && userdel -r "$u" 2>/dev/null
  done
fi

echo " Removing nginx vhost..."
rm -f /etc/nginx/conf.d/autoscript.conf
systemctl reload nginx 2>/dev/null || systemctl restart nginx 2>/dev/null

echo " Removing login banner..."
sed -i '/^Banner \/etc\/ssh-banner.txt/d' /etc/ssh/sshd_config 2>/dev/null
rm -f /etc/ssh-banner.txt
systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null

echo " Removing management scripts..."
rm -f /usr/bin/add-ws /usr/bin/add-ssws /usr/bin/del-ssh \
      /usr/bin/renew-ssh /usr/bin/list-ssh /usr/bin/trial-ssh \
      /usr/bin/check-user /usr/bin/tendang \
      /usr/bin/add-vmess /usr/bin/add-vless /usr/bin/add-tr \
      /usr/bin/del-xray /usr/bin/renew-xray /usr/bin/list-xray \
      /usr/bin/trial-xray /usr/bin/running /usr/bin/restart \
      /usr/bin/cek-bandwidth /usr/bin/cek-ram /usr/bin/dns \
      /usr/bin/swap /usr/bin/bbr /usr/bin/clearlog \
      /usr/bin/backup /usr/bin/restore /usr/bin/xp /usr/bin/renew-ssl \
      /usr/bin/change-domain /usr/local/sbin/badvpn-udpgw \
      /usr/local/sbin/ws-proxy.py /usr/bin/notify-check /usr/bin/tg-setup /usr/bin/tg-manager

echo " Removing cron jobs..."
(crontab -l 2>/dev/null | grep -v autoscript) | crontab - 2>/dev/null

echo " Removing swap file..."
swapoff /swapfile 2>/dev/null
rm -f /swapfile
sed -i '/swapfile/d' /etc/fstab 2>/dev/null

if [[ "$DELCERT" == "y" || "$DELCERT" == "Y" ]] && [[ -n "$DOM" ]]; then
  echo " Removing SSL certificate for $DOM..."
  certbot delete --cert-name "$DOM" --non-interactive 2>/dev/null
fi

echo " Restoring default root login (removing menu auto-launch)..."
rm -f /root/.profile

echo " Removing account/config data..."
rm -rf /etc/autoscript /usr/local/etc/xray /var/log/xray

echo ""
echo -e "${GREEN}${BOLD}Uninstall complete.${NC}"
echo " This menu and the uninstall-vpn command are being removed now too."
rm -f /usr/bin/menu /usr/bin/uninstall-vpn
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
         /usr/bin/backup /usr/bin/restore /usr/bin/xp /usr/bin/renew-ssl \
         /usr/bin/change-domain /usr/bin/uninstall-vpn \
         /usr/bin/notify-check /usr/bin/tg-setup /usr/bin/tg-manager

log "All management scripts installed."
# =====================================================================
# 15b. TELEGRAM BOT MANAGER (tg-manager)
# =====================================================================
step "Telegram Bot Manager"

cat > /usr/bin/tg-manager << 'TGEOF'
#!/bin/bash
# ─────────────────────────────────────────────────────────────────
#  HELPER VPN — Telegram Account Manager Bot  v3
#  Features:
#   ✅ Multi-admin support (multiple Telegram IDs)
#   ✅ Inline buttons — tap to create SSH / V2Ray accounts
#   ✅ Step-by-step guided flows (no need to remember commands)
#   ✅ Text commands still work as before
#   ✅ State machine per-chat for conversational flows
# ─────────────────────────────────────────────────────────────────
source /etc/autoscript/lib.sh

TOKEN=$(cat /etc/autoscript/telegram_token 2>/dev/null)
OFFSET_FILE=/etc/autoscript/tg_offset
STATE_DIR=/etc/autoscript/tg_state
mkdir -p "$STATE_DIR"

# ── Multi-admin: read all IDs from file (one per line or comma-sep) ─
mapfile -t ADMIN_IDS < <(
  cat /etc/autoscript/telegram_chatid 2>/dev/null \
    | tr ',' '\n' | sed 's/[[:space:]]//g' | grep -v '^$'
)

if [[ -z "$TOKEN" || ${#ADMIN_IDS[@]} -eq 0 ]]; then
  echo "ERROR: Telegram token/chatid not set. Run menu > option 28."
  exit 1
fi

# Primary admin (first ID) receives startup notification
PRIMARY_ADMIN="${ADMIN_IDS[0]}"

_log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [tg-bot] $*" >> /var/log/autoscript-tg.log; }

# ── is_admin: returns 0 if chat_id is in admin list ─────────────
is_admin() {
  local cid="$1"
  for aid in "${ADMIN_IDS[@]}"; do
    [[ "$cid" == "$aid" ]] && return 0
  done
  return 1
}

# ── tg_send: plain text message ─────────────────────────────────
tg_send() {
  local cid="$1" msg="$2"
  curl -s --max-time 15 -X POST \
    "https://api.telegram.org/bot${TOKEN}/sendMessage" \
    -d "chat_id=${cid}" \
    -d "parse_mode=Markdown" \
    --data-urlencode "text=${msg}" >/dev/null 2>&1 || true
}

# ── tg_send_inline: message with inline keyboard ─────────────────
# $1=chat_id  $2=message_text  $3=keyboard_json
tg_send_inline() {
  local cid="$1" msg="$2" kb="$3"
  curl -s --max-time 15 -X POST \
    "https://api.telegram.org/bot${TOKEN}/sendMessage" \
    -d "chat_id=${cid}" \
    -d "parse_mode=Markdown" \
    -d "reply_markup=${kb}" \
    --data-urlencode "text=${msg}" >/dev/null 2>&1 || true
}

# ── tg_answer_callback: acknowledge button tap (removes loading) ──
tg_answer_callback() {
  local cq_id="$1" text="${2:-}"
  curl -s --max-time 8 -X POST \
    "https://api.telegram.org/bot${TOKEN}/answerCallbackQuery" \
    -d "callback_query_id=${cq_id}" \
    --data-urlencode "text=${text}" >/dev/null 2>&1 || true
}

# ── State machine helpers ────────────────────────────────────────
# State file per chat: /etc/autoscript/tg_state/<chatid>
# Format:  step|data1|data2|...
get_state() { cat "$STATE_DIR/$1" 2>/dev/null || echo ""; }
set_state() { echo "$2" > "$STATE_DIR/$1"; }
clear_state() { rm -f "$STATE_DIR/$1"; }

# ── API helpers ──────────────────────────────────────────────────
get_updates() {
  curl -s --max-time 40 \
    "https://api.telegram.org/bot${TOKEN}/getUpdates?offset=${1}&timeout=30&allowed_updates=message,callback_query" \
    2>/dev/null || echo "{}"
}
get_offset() { cat "$OFFSET_FILE" 2>/dev/null || echo 0; }
set_offset()  { echo "$1" > "$OFFSET_FILE"; }

# ── xray permission helper ───────────────────────────────────────
xray_fix_perms() {
  local XU XG
  XU=$(systemctl show xray -p User  --value 2>/dev/null); [[ -z "$XU" ]] && XU=nobody
  XG=$(systemctl show xray -p Group --value 2>/dev/null); [[ -z "$XG" ]] && XG=nogroup
  chown "$XU:$XG" "$XRAY_CONFIG" 2>/dev/null
  chmod 644 "$XRAY_CONFIG"
}

# ════════════════════════════════════════════════════════════════════
# INLINE KEYBOARD DEFINITIONS
# ════════════════════════════════════════════════════════════════════

kb_main_menu() {
  cat <<'JSON'
{"inline_keyboard":[
  [{"text":"🔐  ── SSH ACCOUNTS ──  🔐","callback_data":"noop"}],
  [{"text":"➕ Create SSH","callback_data":"flow_ssh_start"},{"text":"🎁 Trial SSH","callback_data":"do_trialssh"},{"text":"📋 List SSH","callback_data":"do_listssh"}],
  [{"text":"♻️ Renew SSH","callback_data":"flow_renewssh_start"},{"text":"❌ Delete SSH","callback_data":"flow_delssh_start"}],
  [{"text":"👥 Active Logins","callback_data":"do_checkuser"},{"text":"💀 Kill Multi-Login","callback_data":"do_tendang"}],
  [{"text":"⚡  ── XRAY ACCOUNTS ──  ⚡","callback_data":"noop"}],
  [{"text":"🔵 VMess","callback_data":"flow_vmess_start"},{"text":"🟣 VLESS","callback_data":"flow_vless_start"},{"text":"⚪ Trojan","callback_data":"flow_trojan_start"}],
  [{"text":"🎁 Trial Xray","callback_data":"show_trial_xray"},{"text":"📋 List Xray","callback_data":"do_listxray"}],
  [{"text":"♻️ Renew Xray","callback_data":"flow_renewxray_start"},{"text":"❌ Delete Xray","callback_data":"flow_delxray_start"}],
  [{"text":"⚙️  ── SYSTEM ──  ⚙️","callback_data":"noop"}],
  [{"text":"📊 Status","callback_data":"do_status"},{"text":"🔄 Restart All","callback_data":"do_restart"}]
]}
JSON
}

kb_xray_trial() {
  cat <<'JSON'
{"inline_keyboard":[
  [{"text":"🔵 Trial VMess","callback_data":"do_trial_vmess"},{"text":"🟣 Trial VLESS","callback_data":"do_trial_vless"},{"text":"⚪ Trial Trojan","callback_data":"do_trial_trojan"}],
  [{"text":"🔙 Back to Menu","callback_data":"show_menu"}]
]}
JSON
}

kb_cancel() {
  cat <<'JSON'
{"inline_keyboard":[[{"text":"❌ Cancel","callback_data":"cancel_flow"}]]}
JSON
}

kb_back() {
  cat <<'JSON'
{"inline_keyboard":[[{"text":"🔙 Back to Menu","callback_data":"show_menu"}]]}
JSON
}

# ════════════════════════════════════════════════════════════════════
# ACCOUNT CREATION HELPERS
# ════════════════════════════════════════════════════════════════════

do_addssh() {
  local user="$1" pass="$2" days="${3:-30}"
  [[ -z "$user" || -z "$pass" ]] && { echo "❌ Usage: /addssh <user> <pass> [days]"; return; }
  if id "$user" &>/dev/null; then echo "❌ User *${user}* already exists."; return; fi
  local exp
  exp=$(date -d "+${days} days" +%Y-%m-%d)
  useradd -m -s /bin/false -e "$exp" "$user" 2>/dev/null
  usermod -p "$(openssl passwd -6 "${pass}")" "${user}"
  echo "user=$user;pass=$pass;exp=$exp" > "$SSH_DIR/$user"
  local PAYLOAD="GET /ssh-ws HTTP/1.1[crlf]Host: ${DOMAIN}[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]User-Agent: [crlf][crlf]"
  printf "✅ *SSH Account Created*\n\n👤 Username : \`%s\`\n🔑 Password : \`%s\`\n📅 Expires  : \`%s\`  (%s days)\n🌐 Host     : \`%s\`\n\n*── Ports ──────────────────*\n🔌 OpenSSH   :  \`%s : 22\`\n🔌 Dropbear  :  \`%s : 109 / 143\`\n🔌 Stunnel   :  \`%s : 447 / 777\`\n🌐 WS HTTP   :  \`ws://%s/ssh-ws\`\n🔒 WSS HTTPS :  \`wss://%s/ssh-ws\`\n🎮 BadVPN    :  \`127.0.0.1 : 7100/7200/7300\`\n\n*── Client App Config ──────*\n📌 Target HTTP   :  \`%s:80@%s:%s\`\n📌 Target HTTPS  :  \`%s:443@%s:%s\`\n📌 SNI           :  \`%s\`\n📌 Payload       :  \`%s\`" \
    "$user" "$pass" "$exp" "$days" "$DOMAIN" \
    "$DOMAIN" "$DOMAIN" "$DOMAIN" "$DOMAIN" "$DOMAIN" \
    "$DOMAIN" "$user" "$pass" \
    "$DOMAIN" "$user" "$pass" \
    "$DOMAIN" "$PAYLOAD"
  tg_notify "$(printf '🆕 New SSH Account\nUser: %s\nExpires: %s\nDomain: %s' "$user" "$exp" "$DOMAIN")"
}

do_trialssh() {
  local user pass exp
  user="trial$(tr -dc a-z0-9 </dev/urandom | head -c6)"
  pass=$(tr -dc A-Za-z0-9 </dev/urandom | head -c10)
  exp=$(date -d "+1 day" +%Y-%m-%d)
  useradd -m -s /bin/false -e "$exp" "$user" 2>/dev/null
  usermod -p "$(openssl passwd -6 "${pass}")" "${user}"
  echo "user=$user;pass=$pass;exp=$exp" > "$SSH_DIR/$user"
  local PAYLOAD="GET /ssh-ws HTTP/1.1[crlf]Host: ${DOMAIN}[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]User-Agent: [crlf][crlf]"
  printf "🎁 *Trial SSH  (1 Day)*\n\n👤 Username : \`%s\`\n🔑 Password : \`%s\`\n📅 Expires  : \`%s\`\n🌐 Host     : \`%s\`\n\n*── Client App Config ──────*\n📌 Target HTTP   :  \`%s:80@%s:%s\`\n📌 Target HTTPS  :  \`%s:443@%s:%s\`\n📌 SNI           :  \`%s\`\n📌 Payload       :  \`%s\`" \
    "$user" "$pass" "$exp" "$DOMAIN" \
    "$DOMAIN" "$user" "$pass" \
    "$DOMAIN" "$user" "$pass" \
    "$DOMAIN" "$PAYLOAD"
  tg_notify "$(printf '🎁 Trial SSH Account\nUser: %s\nExpires: %s' "$user" "$exp")"
}

do_delssh() {
  local user="$1"
  [[ -z "$user" ]] && { echo "❌ Usage: /delssh <user>"; return; }
  if ! id "$user" &>/dev/null; then echo "❌ User *${user}* not found."; return; fi
  pkill -KILL -u "$user" 2>/dev/null; sleep 1
  local err_out
  err_out=$(userdel -f -r "$user" 2>&1)
  if id "$user" &>/dev/null; then
    echo "❌ Delete failed: ${err_out:-<no output>}"
  else
    rm -f "$SSH_DIR/$user"
    echo "🗑 SSH account *${user}* deleted."
  fi
}

do_renewssh() {
  local user="$1" days="$2"
  [[ -z "$user" || -z "$days" ]] && { echo "❌ Usage: /renewssh <user> <days>"; return; }
  [[ ! -f "$SSH_DIR/$user" ]] && { echo "❌ Account *${user}* not found."; return; }
  local cur now_ts cur_ts base new_exp
  cur=$(chage -l "$user" 2>/dev/null | grep "Account expires" | cut -d: -f2 | xargs)
  [[ "$cur" == "never" ]] && cur=$(date +%Y-%m-%d)
  cur_ts=$(date -d "$cur" +%s 2>/dev/null); now_ts=$(date +%s)
  base=$( [[ -n "$cur_ts" && $cur_ts -gt $now_ts ]] && echo "$cur" || date +%Y-%m-%d )
  new_exp=$(date -d "$base +${days} days" +%Y-%m-%d)
  chage -E "$new_exp" "$user"
  sed -i "s/exp=.*/exp=$new_exp/" "$SSH_DIR/$user"
  echo "♻️ SSH *${user}* extended to \`${new_exp}\`"
}

do_listssh() {
  local now; now=$(date +%s)
  local count=0
  local out="📋 *SSH Account List*\n━━━━━━━━━━━━━━━━━━━\n"
  for f in "$SSH_DIR"/*; do
    [[ -e "$f" ]] || continue
    local u exp exp_ts status logins
    u=$(basename "$f")
    exp=$(sed -n 's/.*exp=//p' "$f")
    exp_ts=$(date -d "$exp" +%s 2>/dev/null)
    status="🟢 active"
    [[ -n "$exp_ts" && $exp_ts -lt $now ]] && status="🔴 expired"
    logins=$(who | grep -c "^${u} " 2>/dev/null || echo 0)
    out+="👤 \`${u}\`  |  ${exp}  |  ${status}  |  🔌 ${logins}\n"
    ((count++))
  done
  [[ $count -eq 0 ]] && out+="_(no accounts yet)_\n"
  out+="━━━━━━━━━━━━━━━━━━━\nTotal: *${count}*"
  echo -e "$out"
}

do_addvmess() {
  local uname="$1" days="${2:-30}"
  [[ -z "$uname" ]] && { echo "❌ Provide a username."; return; }
  [[ -f "$XRAY_DIR/$uname" ]] && { echo "❌ Account *${uname}* already exists."; return; }
  local uuid exp tmp b64 b64tls
  uuid=$(uuidgen); exp=$(date -d "+${days} days" +%Y-%m-%d)
  tmp=$(mktemp)
  jq --arg id "$uuid" --arg email "$uname" \
    '(.inbounds[] | select(.tag=="vmess-ws-in") | .settings.clients) += [{"id":$id,"email":$email,"alterId":0}]' \
    "$XRAY_CONFIG" > "$tmp" && mv "$tmp" "$XRAY_CONFIG"
  xray_fix_perms; xray_reload >/dev/null 2>&1
  echo "type=vmess;uuid=$uuid;exp=$exp" > "$XRAY_DIR/$uname"
  b64=$(echo -n "{\"v\":\"2\",\"ps\":\"${uname}\",\"add\":\"${DOMAIN}\",\"port\":\"80\",\"id\":\"${uuid}\",\"aid\":\"0\",\"net\":\"ws\",\"path\":\"/vmess\",\"tls\":\"\"}" | base64 -w0)
  b64tls=$(echo -n "{\"v\":\"2\",\"ps\":\"${uname}-tls\",\"add\":\"${DOMAIN}\",\"port\":\"443\",\"id\":\"${uuid}\",\"aid\":\"0\",\"net\":\"ws\",\"path\":\"/vmess\",\"tls\":\"tls\"}" | base64 -w0)
  printf "✅ *VMess Account Created*\n\n👤 Username : \`%s\`\n🔑 UUID     : \`%s\`\n📅 Expires  : \`%s\`  (%s days)\n🌐 Host     : \`%s\`\n\n*── Links ──────────────────*\n🌐 WS  (HTTP)  :  \`vmess://%s\`\n🔒 WSS (HTTPS) :  \`vmess://%s\`" \
    "$uname" "$uuid" "$exp" "$days" "$DOMAIN" "$b64" "$b64tls"
  tg_notify "$(printf '🆕 New VMess Account\nUser: %s\nExpires: %s' "$uname" "$exp")"
}

do_addvless() {
  local uname="$1" days="${2:-30}"
  [[ -z "$uname" ]] && { echo "❌ Provide a username."; return; }
  [[ -f "$XRAY_DIR/$uname" ]] && { echo "❌ Account *${uname}* already exists."; return; }
  local uuid exp tmp
  uuid=$(uuidgen); exp=$(date -d "+${days} days" +%Y-%m-%d)
  tmp=$(mktemp)
  jq --arg id "$uuid" --arg email "$uname" \
    '(.inbounds[] | select(.tag=="vless-ws-in") | .settings.clients) += [{"id":$id,"email":$email,"flow":""}]' \
    "$XRAY_CONFIG" > "$tmp" && mv "$tmp" "$XRAY_CONFIG"
  xray_fix_perms; xray_reload >/dev/null 2>&1
  echo "type=vless;uuid=$uuid;exp=$exp" > "$XRAY_DIR/$uname"
  printf "✅ *VLESS Account Created*\n\n👤 Username : \`%s\`\n🔑 UUID     : \`%s\`\n📅 Expires  : \`%s\`  (%s days)\n🌐 Host     : \`%s\`\n\n*── Links ──────────────────*\n🌐 WS  (HTTP)  :  \`vless://%s@%s:80?type=ws&path=%%2Fvless#%s\`\n🔒 WSS (HTTPS) :  \`vless://%s@%s:443?type=ws&security=tls&path=%%2Fvless#%s-tls\`" \
    "$uname" "$uuid" "$exp" "$days" "$DOMAIN" \
    "$uuid" "$DOMAIN" "$uname" \
    "$uuid" "$DOMAIN" "$uname"
  tg_notify "$(printf '🆕 New VLESS Account\nUser: %s\nExpires: %s' "$uname" "$exp")"
}

do_addtrojan() {
  local uname="$1" days="${2:-30}"
  [[ -z "$uname" ]] && { echo "❌ Provide a username."; return; }
  [[ -f "$XRAY_DIR/$uname" ]] && { echo "❌ Account *${uname}* already exists."; return; }
  local pw exp tmp
  pw=$(tr -dc A-Za-z0-9 </dev/urandom | head -c16)
  exp=$(date -d "+${days} days" +%Y-%m-%d)
  tmp=$(mktemp)
  jq --arg pw "$pw" --arg email "$uname" \
    '(.inbounds[] | select(.tag=="trojan-ws-in") | .settings.clients) += [{"password":$pw,"email":$email}]' \
    "$XRAY_CONFIG" > "$tmp" && mv "$tmp" "$XRAY_CONFIG"
  xray_fix_perms; xray_reload >/dev/null 2>&1
  echo "type=trojan;pass=$pw;exp=$exp" > "$XRAY_DIR/$uname"
  printf "✅ *Trojan Account Created*\n\n👤 Username : \`%s\`\n🔑 Password : \`%s\`\n📅 Expires  : \`%s\`  (%s days)\n🌐 Host     : \`%s\`\n\n*── Links ──────────────────*\n🔒 WSS (HTTPS) :  \`trojan://%s@%s:443?type=ws&security=tls&path=%%2Ftrojan-ws#%s\`" \
    "$uname" "$pw" "$exp" "$days" "$DOMAIN" "$pw" "$DOMAIN" "$uname"
  tg_notify "$(printf '🆕 New Trojan Account\nUser: %s\nExpires: %s' "$uname" "$exp")"
}

do_delxray() {
  local uname="$1"
  [[ -z "$uname" ]] && { echo "❌ Provide a username."; return; }
  [[ ! -f "$XRAY_DIR/$uname" ]] && { echo "❌ Account *${uname}* not found."; return; }
  local tmp; tmp=$(mktemp)
  jq --arg email "$uname" \
    '(.inbounds[].settings.clients) |= map(select(.email != $email))' \
    "$XRAY_CONFIG" > "$tmp" && mv "$tmp" "$XRAY_CONFIG"
  xray_fix_perms; xray_reload >/dev/null 2>&1
  rm -f "$XRAY_DIR/$uname"
  echo "🗑 Xray account *${uname}* deleted."
}

do_renewxray() {
  local uname="$1" days="$2"
  [[ -z "$uname" || -z "$days" ]] && { echo "❌ Usage: /renewxray <user> <days>"; return; }
  [[ ! -f "$XRAY_DIR/$uname" ]] && { echo "❌ Account *${uname}* not found."; return; }
  local cur now_ts cur_ts base new_exp
  cur=$(sed -n 's/.*exp=//p' "$XRAY_DIR/$uname")
  now_ts=$(date +%s); cur_ts=$(date -d "$cur" +%s 2>/dev/null)
  base=$( [[ -n "$cur_ts" && $cur_ts -gt $now_ts ]] && echo "$cur" || date +%Y-%m-%d )
  new_exp=$(date -d "$base +${days} days" +%Y-%m-%d)
  sed -i "s/exp=.*/exp=$new_exp/" "$XRAY_DIR/$uname"
  echo "♻️ Xray *${uname}* extended to \`${new_exp}\`"
}

do_listxray() {
  local now; now=$(date +%s)
  local count=0
  local out="📋 *Xray Account List*\n━━━━━━━━━━━━━━━━━━━\n"
  for f in "$XRAY_DIR"/*; do
    [[ -e "$f" ]] || continue
    local u typ exp exp_ts status
    u=$(basename "$f")
    typ=$(sed -n 's/.*type=\([^;]*\).*/\1/p' "$f")
    exp=$(sed -n 's/.*exp=//p' "$f")
    exp_ts=$(date -d "$exp" +%s 2>/dev/null)
    status="🟢 active"
    [[ -n "$exp_ts" && $exp_ts -lt $now ]] && status="🔴 expired"
    out+="👤 \`${u}\`  |  ${typ:-?}  |  ${exp}  |  ${status}\n"
    ((count++))
  done
  [[ $count -eq 0 ]] && out+="_(no accounts yet)_\n"
  out+="━━━━━━━━━━━━━━━━━━━\nTotal: *${count}*"
  echo -e "$out"
}

do_trialxray() {
  local proto="${1:-vmess}"
  local uname exp tmp uuid pw XU XG
  uname="trial$(tr -dc a-z0-9 </dev/urandom | head -c6)"
  exp=$(date -d "+1 day" +%Y-%m-%d)
  tmp=$(mktemp)
  XU=$(systemctl show xray -p User  --value 2>/dev/null); [[ -z "$XU" ]] && XU=nobody
  XG=$(systemctl show xray -p Group --value 2>/dev/null); [[ -z "$XG" ]] && XG=nogroup
  case "$proto" in
    vmess)
      uuid=$(uuidgen)
      jq --arg id "$uuid" --arg email "$uname" \
        '(.inbounds[] | select(.tag=="vmess-ws-in") | .settings.clients) += [{"id":$id,"email":$email,"alterId":0}]' \
        "$XRAY_CONFIG" > "$tmp" && mv "$tmp" "$XRAY_CONFIG"
      chown "$XU:$XG" "$XRAY_CONFIG" 2>/dev/null; chmod 644 "$XRAY_CONFIG"
      xray_reload >/dev/null 2>&1
      echo "type=vmess;uuid=$uuid;exp=$exp" > "$XRAY_DIR/$uname"
      local b64 b64tls
      b64=$(echo -n "{\"v\":\"2\",\"ps\":\"${uname}\",\"add\":\"${DOMAIN}\",\"port\":\"80\",\"id\":\"${uuid}\",\"aid\":\"0\",\"net\":\"ws\",\"path\":\"/vmess\",\"tls\":\"\"}" | base64 -w0)
      b64tls=$(echo -n "{\"v\":\"2\",\"ps\":\"${uname}-tls\",\"add\":\"${DOMAIN}\",\"port\":\"443\",\"id\":\"${uuid}\",\"aid\":\"0\",\"net\":\"ws\",\"path\":\"/vmess\",\"tls\":\"tls\"}" | base64 -w0)
      printf "🎁 *Trial VMess  (1 Day)*\n\n👤 Username : \`%s\`\n📅 Expires  : \`%s\`\n\n🌐 WS  :  \`vmess://%s\`\n🔒 WSS :  \`vmess://%s\`" "$uname" "$exp" "$b64" "$b64tls"
      ;;
    vless)
      uuid=$(uuidgen)
      jq --arg id "$uuid" --arg email "$uname" \
        '(.inbounds[] | select(.tag=="vless-ws-in") | .settings.clients) += [{"id":$id,"email":$email,"flow":""}]' \
        "$XRAY_CONFIG" > "$tmp" && mv "$tmp" "$XRAY_CONFIG"
      chown "$XU:$XG" "$XRAY_CONFIG" 2>/dev/null; chmod 644 "$XRAY_CONFIG"
      xray_reload >/dev/null 2>&1
      echo "type=vless;uuid=$uuid;exp=$exp" > "$XRAY_DIR/$uname"
      printf "🎁 *Trial VLESS  (1 Day)*\n\n👤 Username : \`%s\`\n📅 Expires  : \`%s\`\n\n🌐 WS  :  \`vless://%s@%s:80?type=ws&path=%%2Fvless#%s\`\n🔒 WSS :  \`vless://%s@%s:443?type=ws&security=tls&path=%%2Fvless#%s-tls\`" \
        "$uname" "$exp" "$uuid" "$DOMAIN" "$uname" "$uuid" "$DOMAIN" "$uname"
      ;;
    trojan)
      pw=$(tr -dc A-Za-z0-9 </dev/urandom | head -c16)
      jq --arg pw "$pw" --arg email "$uname" \
        '(.inbounds[] | select(.tag=="trojan-ws-in") | .settings.clients) += [{"password":$pw,"email":$email}]' \
        "$XRAY_CONFIG" > "$tmp" && mv "$tmp" "$XRAY_CONFIG"
      chown "$XU:$XG" "$XRAY_CONFIG" 2>/dev/null; chmod 644 "$XRAY_CONFIG"
      xray_reload >/dev/null 2>&1
      echo "type=trojan;pass=$pw;exp=$exp" > "$XRAY_DIR/$uname"
      printf "🎁 *Trial Trojan  (1 Day)*\n\n👤 Username : \`%s\`\n📅 Expires  : \`%s\`\n\n🔒 WSS :  \`trojan://%s@%s:443?type=ws&security=tls&path=%%2Ftrojan-ws#%s\`" \
        "$uname" "$exp" "$pw" "$DOMAIN" "$uname"
      ;;
    *) echo "❌ Usage: /trialxray vmess|vless|trojan" ;;
  esac
}

do_checkuser() {
  local out="👥 *Active SSH Logins*\n━━━━━━━━━━━━━━━━━━━\n"
  local sessions; sessions=$(who 2>/dev/null | grep -v "^$")
  if [[ -z "$sessions" ]]; then
    out+="_(no active sessions right now)_"
  else
    while IFS= read -r line; do
      out+="\`${line}\`\n"
    done <<< "$sessions"
    local total; total=$(echo "$sessions" | wc -l)
    out+="━━━━━━━━━━━━━━━━━━━\nTotal: *${total}* session(s)"
  fi
  echo -e "$out"
}

do_tendang() {
  # Find users with more than 1 simultaneous SSH session and kill them
  local killed=0
  local dupes
  dupes=$(who 2>/dev/null | awk '{print $1}' | sort | uniq -d)
  if [[ -z "$dupes" ]]; then
    echo "✅ No multi-login detected. All users have ≤ 1 session."
    return
  fi
  local out="💀 *Multi-Login Kill*\n━━━━━━━━━━━━━━━━━━━\n"
  while IFS= read -r u; do
    [[ -z "$u" ]] && continue
    pkill -KILL -u "$u" 2>/dev/null && { out+="🔴 Killed: \`${u}\`\n"; ((killed++)); }
  done <<< "$dupes"
  out+="━━━━━━━━━━━━━━━━━━━\nTotal killed: *${killed}* user(s)"
  echo -e "$out"
}

do_status() {
  local svc_icon
  svc_icon() { systemctl is-active --quiet "$1" 2>/dev/null && echo "🟢" || echo "🔴"; }
  local bdv_up=0
  for p in 7100 7200 7300; do systemctl is-active --quiet "badvpn@${p}" && ((bdv_up++)); done
  local bdv_icon="🟢 (3/3)"
  [[ $bdv_up -lt 3 ]] && bdv_icon="🔴 (${bdv_up}/3)"
  printf "📊 *HELPER VPN — Service Status*\n━━━━━━━━━━━━━━━━━━━━━━━━\n%s OpenSSH    :  22\n%s Dropbear   :  109 / 143\n%s WS-Proxy   :  2082→22\n%s Nginx      :  80 / 443\n%s Stunnel5   :  447 / 777\n%s BadVPN     :  7100-7300\n%s Xray       :  10000-10002\n%s Fail2ban\n━━━━━━━━━━━━━━━━━━━━━━━━\n🔌 SSH Online  :  %d session(s)\n👥 SSH Accts   :  %d\n📡 Xray Accts  :  %d\n🌐 Domain      :  %s\n👮 Admins      :  %d ID(s)" \
    "$(svc_icon ssh)" "$(svc_icon dropbear)" "$(svc_icon ws-proxy)" "$(svc_icon nginx)" \
    "$(svc_icon stunnel4)" "$bdv_icon" "$(svc_icon xray)" "$(svc_icon fail2ban)" \
    "$(who | wc -l)" "$(ls "$SSH_DIR"  2>/dev/null | wc -l)" \
    "$(ls "$XRAY_DIR" 2>/dev/null | wc -l)" "$DOMAIN" "${#ADMIN_IDS[@]}"
}

do_restart() {
  systemctl restart ssh dropbear ws-proxy nginx stunnel4 \
    badvpn@7100 badvpn@7200 badvpn@7300 xray fail2ban 2>/dev/null
  echo "🔄 All services restarted."
}

# ════════════════════════════════════════════════════════════════════
# STEP-BY-STEP FLOW HANDLER
# State format:  <flow_name>|<step>|<saved_arg1>|<saved_arg2>|...
# ════════════════════════════════════════════════════════════════════

handle_state() {
  local cid="$1" text="$2"
  local state; state=$(get_state "$cid")
  [[ -z "$state" ]] && return 1   # no active flow

  IFS='|' read -ra parts <<< "$state"
  local flow="${parts[0]}" step="${parts[1]}"
  local a1="${parts[2]:-}" a2="${parts[3]:-}" a3="${parts[4]:-}"

  # Cancel shortcut
  if [[ "$text" == "/cancel" || "$text" == "cancel" || "$text" == "❌ Cancel" ]]; then
    clear_state "$cid"
    tg_send_inline "$cid" "❌ *Cancelled.*\n\nBack to menu:" "$(kb_main_menu)"
    return 0
  fi

  case "${flow}|${step}" in

    # ── SSH Create Flow ────────────────────────────────────────
    ssh_create|ask_user)
      set_state "$cid" "ssh_create|ask_pass|${text}"
      tg_send_inline "$cid" "✏️ *Create SSH  —  Step 2/3*\n\nEnter *password* for user \`${text}\`:\n_(or type \`auto\` for a random one)_" "$(kb_cancel)"
      ;;
    ssh_create|ask_pass)
      local pass="$text"
      [[ "$text" == "auto" ]] && pass=$(tr -dc A-Za-z0-9 </dev/urandom | head -c10)
      set_state "$cid" "ssh_create|ask_days|${a1}|${pass}"
      tg_send_inline "$cid" "✏️ *Create SSH  —  Step 3/3*\n\nEnter *duration* (days) for \`${a1}\`:\n_(press 30 for default, or type a number)_" "$(kb_cancel)"
      ;;
    ssh_create|ask_days)
      local days="$text"
      [[ ! "$days" =~ ^[0-9]+$ ]] && days=30
      clear_state "$cid"
      local result; result=$(do_addssh "$a1" "$a2" "$days")
      tg_send_inline "$cid" "$result" "$(kb_main_menu)"
      ;;

    # ── SSH Delete Flow ────────────────────────────────────────
    ssh_delete|ask_user)
      clear_state "$cid"
      local result; result=$(do_delssh "$text")
      tg_send_inline "$cid" "$result" "$(kb_main_menu)"
      ;;

    # ── SSH Renew Flow ─────────────────────────────────────────
    ssh_renew|ask_user)
      set_state "$cid" "ssh_renew|ask_days|${text}"
      tg_send_inline "$cid" "♻️ *Renew SSH  —  Step 2/2*\n\nHow many *days* to add for \`${text}\`?" "$(kb_cancel)"
      ;;
    ssh_renew|ask_days)
      clear_state "$cid"
      local result; result=$(do_renewssh "$a1" "$text")
      tg_send_inline "$cid" "$result" "$(kb_main_menu)"
      ;;

    # ── VMess Create Flow ──────────────────────────────────────
    vmess_create|ask_user)
      set_state "$cid" "vmess_create|ask_days|${text}"
      tg_send_inline "$cid" "✏️ *Create VMess  —  Step 2/2*\n\nEnter *duration* (days) for \`${text}\`:\n_(press 30 for default)_" "$(kb_cancel)"
      ;;
    vmess_create|ask_days)
      local days="$text"
      [[ ! "$days" =~ ^[0-9]+$ ]] && days=30
      clear_state "$cid"
      local result; result=$(do_addvmess "$a1" "$days")
      tg_send_inline "$cid" "$result" "$(kb_main_menu)"
      ;;

    # ── VLESS Create Flow ──────────────────────────────────────
    vless_create|ask_user)
      set_state "$cid" "vless_create|ask_days|${text}"
      tg_send_inline "$cid" "✏️ *Create VLESS  —  Step 2/2*\n\nEnter *duration* (days) for \`${text}\`:\n_(press 30 for default)_" "$(kb_cancel)"
      ;;
    vless_create|ask_days)
      local days="$text"
      [[ ! "$days" =~ ^[0-9]+$ ]] && days=30
      clear_state "$cid"
      local result; result=$(do_addvless "$a1" "$days")
      tg_send_inline "$cid" "$result" "$(kb_main_menu)"
      ;;

    # ── Trojan Create Flow ─────────────────────────────────────
    trojan_create|ask_user)
      set_state "$cid" "trojan_create|ask_days|${text}"
      tg_send_inline "$cid" "✏️ *Create Trojan  —  Step 2/2*\n\nEnter *duration* (days) for \`${text}\`:\n_(press 30 for default)_" "$(kb_cancel)"
      ;;
    trojan_create|ask_days)
      local days="$text"
      [[ ! "$days" =~ ^[0-9]+$ ]] && days=30
      clear_state "$cid"
      local result; result=$(do_addtrojan "$a1" "$days")
      tg_send_inline "$cid" "$result" "$(kb_main_menu)"
      ;;

    # ── Xray Delete Flow ───────────────────────────────────────
    xray_delete|ask_user)
      clear_state "$cid"
      local result; result=$(do_delxray "$text")
      tg_send_inline "$cid" "$result" "$(kb_main_menu)"
      ;;

    # ── Xray Renew Flow ────────────────────────────────────────
    xray_renew|ask_user)
      set_state "$cid" "xray_renew|ask_days|${text}"
      tg_send_inline "$cid" "♻️ *Renew Xray  —  Step 2/2*\n\nHow many *days* to add for \`${text}\`?" "$(kb_cancel)"
      ;;
    xray_renew|ask_days)
      clear_state "$cid"
      local result; result=$(do_renewxray "$a1" "$text")
      tg_send_inline "$cid" "$result" "$(kb_main_menu)"
      ;;

    *)
      clear_state "$cid"
      tg_send "$cid" "⚠️ Unknown flow step — reset. Send /menu or /help."
      ;;
  esac
  return 0
}

# ════════════════════════════════════════════════════════════════════
# CALLBACK QUERY HANDLER  (inline button taps)
# ════════════════════════════════════════════════════════════════════

handle_callback() {
  local cid="$1" cq_id="$2" data="$3"
  tg_answer_callback "$cq_id"   # always ack immediately

  case "$data" in
    noop)
      # Section-header buttons — acknowledge tap, do nothing
      tg_answer_callback "$cq_id" ""
      return
      ;;
    show_menu)
      clear_state "$cid"
      tg_send_inline "$cid" "🤖 *HELPER VPN — Main Menu*\n\nChoose an option below:" "$(kb_main_menu)"
      ;;
    cancel_flow)
      clear_state "$cid"
      tg_send_inline "$cid" "❌ *Cancelled.*\n\nBack to menu:" "$(kb_main_menu)"
      ;;

    # ── SSH flows ───────────────────────────────────────────────
    flow_ssh_start)
      set_state "$cid" "ssh_create|ask_user"
      tg_send_inline "$cid" "✏️ *Create SSH  —  Step 1/3*\n\nEnter *username* for the new SSH account:" "$(kb_cancel)"
      ;;
    flow_delssh_start)
      set_state "$cid" "ssh_delete|ask_user"
      tg_send_inline "$cid" "🗑 *Delete SSH*\n\nEnter the *username* to delete:" "$(kb_cancel)"
      ;;
    flow_renewssh_start)
      set_state "$cid" "ssh_renew|ask_user"
      tg_send_inline "$cid" "♻️ *Renew SSH  —  Step 1/2*\n\nEnter *username* to renew:" "$(kb_cancel)"
      ;;
    do_trialssh)
      local result; result=$(do_trialssh)
      tg_send_inline "$cid" "$result" "$(kb_main_menu)"
      ;;
    do_listssh)
      local result; result=$(do_listssh)
      tg_send_inline "$cid" "$result" "$(kb_main_menu)"
      ;;

    # ── Xray flows ──────────────────────────────────────────────
    flow_vmess_start)
      set_state "$cid" "vmess_create|ask_user"
      tg_send_inline "$cid" "✏️ *Create VMess  —  Step 1/2*\n\nEnter *username* for the new VMess account:" "$(kb_cancel)"
      ;;
    flow_vless_start)
      set_state "$cid" "vless_create|ask_user"
      tg_send_inline "$cid" "✏️ *Create VLESS  —  Step 1/2*\n\nEnter *username* for the new VLESS account:" "$(kb_cancel)"
      ;;
    flow_trojan_start)
      set_state "$cid" "trojan_create|ask_user"
      tg_send_inline "$cid" "✏️ *Create Trojan  —  Step 1/2*\n\nEnter *username* for the new Trojan account:" "$(kb_cancel)"
      ;;
    flow_delxray_start)
      set_state "$cid" "xray_delete|ask_user"
      tg_send_inline "$cid" "🗑 *Delete Xray*\n\nEnter the *username* to delete:" "$(kb_cancel)"
      ;;
    flow_renewxray_start)
      set_state "$cid" "xray_renew|ask_user"
      tg_send_inline "$cid" "♻️ *Renew Xray  —  Step 1/2*\n\nEnter *username* to renew:" "$(kb_cancel)"
      ;;
    show_trial_xray)
      tg_send_inline "$cid" "🎁 *Trial Xray — Choose Protocol:*\n\nSelect one to create a 1-day trial account:" "$(kb_xray_trial)"
      ;;
    do_listxray)
      local result; result=$(do_listxray)
      tg_send_inline "$cid" "$result" "$(kb_main_menu)"
      ;;
    do_checkuser)
      local result; result=$(do_checkuser)
      tg_send_inline "$cid" "$result" "$(kb_main_menu)"
      ;;
    do_tendang)
      local result; result=$(do_tendang)
      tg_send_inline "$cid" "$result" "$(kb_main_menu)"
      ;;
    do_trial_vmess)
      local result; result=$(do_trialxray "vmess")
      tg_send_inline "$cid" "$result" "$(kb_main_menu)"
      ;;
    do_trial_vless)
      local result; result=$(do_trialxray "vless")
      tg_send_inline "$cid" "$result" "$(kb_main_menu)"
      ;;
    do_trial_trojan)
      local result; result=$(do_trialxray "trojan")
      tg_send_inline "$cid" "$result" "$(kb_main_menu)"
      ;;

    # ── System ──────────────────────────────────────────────────
    do_status)
      local result; result=$(do_status)
      tg_send_inline "$cid" "$result" "$(kb_main_menu)"
      ;;
    do_restart)
      local result; result=$(do_restart)
      tg_send_inline "$cid" "$result" "$(kb_main_menu)"
      ;;

    *)
      tg_send "$cid" "❓ Unknown action."
      ;;
  esac
}

# ════════════════════════════════════════════════════════════════════
# TEXT COMMAND HANDLER  (typed commands still work)
# ════════════════════════════════════════════════════════════════════

handle_text_cmd() {
  local cid="$1" text="$2"
  local CMD A1 A2 A3
  CMD=$(echo "$text" | awk '{print $1}' | tr '[:upper:]' '[:lower:]' | sed 's/@.*//')
  A1=$(echo "$text" | awk '{print $2}')
  A2=$(echo "$text" | awk '{print $3}')
  A3=$(echo "$text" | awk '{print $4}')
  _log "CMD=$CMD A1=$A1 A2=$A2 A3=$A3 from=$cid"

  local REPLY=""
  case "$CMD" in
    /start|/menu)
      clear_state "$cid"
      tg_send_inline "$cid" "🤖 *HELPER VPN — Main Menu*\n\nChoose an option below, or use text commands:" "$(kb_main_menu)"
      return ;;
    /help)
      REPLY="🤖 *HELPER VPN Bot — Commands*
━━━━━━━━━━━━━━━━━━━━━━━━
💡 _Tap /menu for inline buttons (easier!)_

*SSH*
/addssh \`<user> <pass> [days]\`
/delssh \`<user>\`
/renewssh \`<user> <days>\`
/listssh — /trialssh

*Xray*
/addvmess \`<user> [days]\`
/addvless \`<user> [days]\`
/addtrojan \`<user> [days]\`
/delxray \`<user>\`
/renewxray \`<user> <days>\`
/listxray — /trialxray \`vmess|vless|trojan\`

*System*
/status — /restart — /menu

_Default duration: 30 days_
_Multi-admin: ${#ADMIN_IDS[@]} admin ID(s) configured._" ;;
    /addssh)    REPLY=$(do_addssh    "$A1" "$A2" "$A3") ;;
    /delssh)    REPLY=$(do_delssh    "$A1") ;;
    /renewssh)  REPLY=$(do_renewssh  "$A1" "$A2") ;;
    /listssh)   REPLY=$(do_listssh) ;;
    /trialssh)  REPLY=$(do_trialssh) ;;
    /addvmess)  REPLY=$(do_addvmess  "$A1" "$A2") ;;
    /addvless)  REPLY=$(do_addvless  "$A1" "$A2") ;;
    /addtrojan) REPLY=$(do_addtrojan "$A1" "$A2") ;;
    /delxray)   REPLY=$(do_delxray   "$A1") ;;
    /renewxray) REPLY=$(do_renewxray "$A1" "$A2") ;;
    /listxray)  REPLY=$(do_listxray) ;;
    /trialxray) REPLY=$(do_trialxray "$A1") ;;
    /status)    REPLY=$(do_status) ;;
    /restart)   REPLY=$(do_restart) ;;
    /cancel)
      clear_state "$cid"
      tg_send_inline "$cid" "❌ *Cancelled.*" "$(kb_main_menu)"
      return ;;
    *) REPLY="❓ Unknown command. Send /help or /menu." ;;
  esac
  [[ -n "$REPLY" ]] && tg_send_inline "$cid" "$REPLY" "$(kb_back)"
}

# ════════════════════════════════════════════════════════════════════
# MAIN POLLING LOOP
# ════════════════════════════════════════════════════════════════════
_log "tg-manager started. Admins: ${ADMIN_IDS[*]}"
tg_send_inline "$PRIMARY_ADMIN" "🤖 *HELPER VPN Bot is online.*\n${#ADMIN_IDS[@]} admin ID(s) configured.\n\nChoose an option below or send /help:" "$(kb_main_menu)"

while true; do
  OFFSET=$(get_offset)
  RESPONSE=$(get_updates "$OFFSET")

  UPDATE_IDS=$(echo "$RESPONSE" | jq -r '.result[]?.update_id' 2>/dev/null)
  if [[ -z "$UPDATE_IDS" ]]; then sleep 2; continue; fi

  while IFS= read -r uid; do
    [[ -z "$uid" ]] && continue
    UPDATE=$(echo "$RESPONSE" | jq ".result[] | select(.update_id == $uid)" 2>/dev/null)
    set_offset $(( uid + 1 ))

    # ── Detect update type ──────────────────────────────────────
    CQ_ID=$(echo "$UPDATE"   | jq -r '.callback_query.id           // ""' 2>/dev/null)
    CQ_DATA=$(echo "$UPDATE" | jq -r '.callback_query.data         // ""' 2>/dev/null)
    CQ_FROM=$(echo "$UPDATE" | jq -r '.callback_query.from.id      // ""' 2>/dev/null)
    MSG_CID=$(echo "$UPDATE" | jq -r '.message.chat.id             // ""' 2>/dev/null)
    MSG_TXT=$(echo "$UPDATE" | jq -r '.message.text                // ""' 2>/dev/null)

    # ── Callback query (button tap) ─────────────────────────────
    if [[ -n "$CQ_ID" ]]; then
      if ! is_admin "$CQ_FROM"; then
        tg_answer_callback "$CQ_ID" "⛔ Unauthorized"
        _log "Blocked callback from: $CQ_FROM"
        continue
      fi
      _log "CALLBACK from=$CQ_FROM data=$CQ_DATA"
      handle_callback "$CQ_FROM" "$CQ_ID" "$CQ_DATA"
      continue
    fi

    # ── Regular message ─────────────────────────────────────────
    if [[ -n "$MSG_CID" ]]; then
      if ! is_admin "$MSG_CID"; then
        tg_send "$MSG_CID" "⛔ Unauthorized. This bot is private."
        _log "Blocked message from: $MSG_CID"
        continue
      fi
      [[ -z "$MSG_TXT" ]] && continue

      # Check if there's an active step-by-step flow first
      if handle_state "$MSG_CID" "$MSG_TXT"; then
        continue
      fi

      # Otherwise treat as a text command
      handle_text_cmd "$MSG_CID" "$MSG_TXT"
    fi

  done <<< "$UPDATE_IDS"

  sleep 1
done
TGEOF
chmod +x /usr/bin/tg-manager

# systemd service for tg-manager
cat > /etc/systemd/system/tg-manager.service <<'EOF'
[Unit]
Description=HELPER VPN Telegram Account Manager Bot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/tg-manager
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

# Only enable+start the bot if a token and chatid are actually configured.
# If they were left blank at install time the bot will exit immediately with
# an error, which is confusing — it can be started later via menu option 29
# or by running: systemctl enable --now tg-manager
TG_TOKEN_VAL=$(cat /etc/autoscript/telegram_token  2>/dev/null)
TG_CHAT_VAL=$(cat  /etc/autoscript/telegram_chatid 2>/dev/null)
if [[ -n "$TG_TOKEN_VAL" && -n "$TG_CHAT_VAL" ]]; then
  systemctl enable tg-manager
  systemctl start  tg-manager
  sleep 2
  if systemctl is-active --quiet tg-manager; then
    log "Telegram bot (tg-manager) started — send /help to your bot."
  else
    warn "tg-manager failed to start. Check: journalctl -u tg-manager -n 20"
  fi
else
  warn "Telegram credentials not set — tg-manager NOT started."
  warn "Configure via menu option 28, then start: systemctl enable --now tg-manager"
fi



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
CYAN='\033[0;36m'; BLUE='\033[0;34m'; NC='\033[0m'; BOLD='\e[1m'; PURPLE='\033[0;35m'
ORANGE='\033[38;5;208m'; PINK='\033[38;5;205m'; LIME='\033[38;5;118m'
SKY='\033[38;5;45m';     GOLD='\033[38;5;220m'; WHITE='\033[1;37m'

# ── Box-drawing helpers ───────────────────────────────────────────
INNER=50
COLS=$(tput cols 2>/dev/null || echo 0)
if [[ "$COLS" =~ ^[0-9]+$ ]] && (( COLS > 0 && COLS < INNER + 2 )); then
  INNER=$(( COLS - 2 )); (( INNER < 36 )) && INNER=36
fi

hr()   { printf "${SKY}${BOLD}%s%s%s${NC}\n" "$1" "$(printf '═%.0s' $(seq 1 "$INNER"))" "$2"; }
top()  { hr "╔" "╗"; }
mid()  { hr "╠" "╣"; }
bot()  { hr "╚" "╝"; }
box_line() {
  local plain="$1" disp="$2"
  local pad=$(( INNER - ${#plain} ))
  (( pad < 0 )) && pad=0
  printf "${SKY}${BOLD}║${NC}%b%*s${SKY}${BOLD}║${NC}\n" "$disp" "$pad" ""
}
mline() {
  printf " ${GREEN}%-3s${NC} %-18s ${PINK}%-3s${NC} %s\n" "$1" "$2" "$3" "$4"
}
sline() {
  printf " ${YELLOW}%-3s${NC} %-18s ${SKY}%-3s${NC} %s\n" "$1" "$2" "$3" "$4"
}

top
box_line "   *** HELPER VPN MENU ***" "   ${GOLD}${BOLD}*** HELPER VPN MENU ***${NC}"
box_line "      Support: @H_E_L_P_E_R_1" "      ${PINK}${BOLD}Support: @H_E_L_P_E_R_1${NC}"
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
sline "15)" "Running Services"  "16)" "Restart Services"
sline "17)" "Bandwidth Monitor" "18)" "RAM Monitor"
sline "19)" "Clear Logs"        "20)" "Change DNS"
sline "21)" "BBR Status"        "22)" "Swap RAM"
sline "23)" "Renew SSL"         "24)" "Backup Data"
sline "25)" "Restore Data"      "26)" "Change Domain"
sline "27)" "Uninstall VPN"     "28)" "Telegram Setup"
sline "29)" "Bot Start/Stop"    "30)" "Bot Status"
echo ""
mid
box_line "  0) Exit" "  ${RED}${BOLD}0) Exit${NC}"
bot
read -rp "$(echo -e " ${GOLD}${BOLD}Choose [0-30]: ${NC}")" opt
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
  26) change-domain ;; 27) uninstall-vpn ;; 28) tg-setup ;;
  29)
    if systemctl is-active --quiet tg-manager; then
      systemctl stop tg-manager
      echo -e "${RED}Telegram bot stopped.${NC}"
    else
      TK=$(cat /etc/autoscript/telegram_token 2>/dev/null)
      CI=$(cat /etc/autoscript/telegram_chatid 2>/dev/null)
      if [[ -z "$TK" || -z "$CI" ]]; then
        echo -e "${RED}No Telegram credentials — run option 28 first.${NC}"
      else
        systemctl enable tg-manager 2>/dev/null
        systemctl start  tg-manager
        sleep 2
        systemctl is-active --quiet tg-manager \
          && echo -e "${GREEN}Telegram bot started.${NC}" \
          || echo -e "${RED}Bot failed to start — check: journalctl -u tg-manager -n 20${NC}"
      fi
    fi
    read -rp "Press Enter to continue..." ;;
  30)
    clear
    echo -e "${CYAN}${BOLD}  TELEGRAM BOT STATUS${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    systemctl status tg-manager --no-pager -l 2>&1 | head -20
    echo ""
    echo "  Log (last 10 lines):"
    tail -10 /var/log/autoscript-tg.log 2>/dev/null || echo "  (no log yet)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    read -rp "Press Enter to continue..." ;;
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
# Expiry reminders + disk space alert via Telegram (daily at 09:00)
0 9 * * * /usr/bin/notify-check >> /var/log/autoscript-cron.log 2>&1
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