#!/usr/bin/env bash
# Install AutoHeal on Ubuntu 22.04 / 24.04 as systemd services.
#
#   sudo ./deploy/install_ubuntu.sh                 # platform only (point it at your Kafka)
#   sudo ./deploy/install_ubuntu.sh --with-kafka    # also install a single-node Kafka (KRaft)
#   sudo ./deploy/install_ubuntu.sh --with-kafka --with-simulator   # full lab on one box
set -euo pipefail

WITH_KAFKA=0
WITH_SIM=0
KAFKA_VERSION="3.8.1"
SCALA_VERSION="2.13"
for arg in "$@"; do
  case "$arg" in
    --with-kafka) WITH_KAFKA=1 ;;
    --with-simulator) WITH_SIM=1 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "run as root (sudo)" >&2; exit 1; }
. /etc/os-release
[[ "${ID}" == "ubuntu" ]] || echo "warning: tested on Ubuntu, found ${ID} ${VERSION_ID}" >&2

SRC="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX=/opt/autoheal
ETC=/etc/autoheal
DATA=/var/lib/autoheal

echo "==> system packages"
apt-get update -y
apt-get install -y python3 python3-venv python3-dev build-essential libxml2-dev libxslt1-dev \
  libffi-dev libssl-dev curl ca-certificates
if [[ $WITH_KAFKA -eq 1 ]]; then
  apt-get install -y openjdk-21-jre-headless || apt-get install -y openjdk-17-jre-headless
fi

echo "==> user and directories"
id autoheal >/dev/null 2>&1 || useradd --system --home "$PREFIX" --shell /usr/sbin/nologin autoheal
mkdir -p "$PREFIX" "$ETC" "$DATA"
cp -r "$SRC/autoheal" "$SRC/simulator" "$SRC/pyproject.toml" "$SRC/README.md" "$PREFIX/"

echo "==> python environment"
python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install --upgrade pip
"$PREFIX/venv/bin/pip" install "$PREFIX"

echo "==> configuration (existing files in $ETC are kept)"
for f in settings.yaml topology.yaml rca_rules.yaml playbooks.yaml; do
  [[ -f "$ETC/$f" ]] || cp "$SRC/config/$f" "$ETC/$f"
done
mkdir -p "$ETC/vendors"
cp -n "$SRC"/config/vendors/*.yaml "$ETC/vendors/" || true
# settings.yaml paths are relative to the parent of its directory; pin them to /etc/autoheal.
sed -i \
  -e "s#topology: config/topology.yaml#topology: $ETC/topology.yaml#" \
  -e "s#rules: config/rca_rules.yaml#rules: $ETC/rca_rules.yaml#" \
  -e "s#playbooks: config/playbooks.yaml#playbooks: $ETC/playbooks.yaml#" \
  -e "s#vendors_dir: config/vendors#vendors_dir: $ETC/vendors#" \
  -e "s#db_path: data/autoheal.db#db_path: $DATA/autoheal.db#" \
  "$ETC/settings.yaml"
if [[ ! -f "$ETC/autoheal.env" ]]; then
  cat > "$ETC/autoheal.env" <<EOF
# Environment for all AutoHeal services
KAFKA_BOOTSTRAP=localhost:9092
AUTOHEAL_BUS=kafka
AUTOHEAL_MODE=auto
SIM_HOST=127.0.0.1
# NETCONF_USER=...
# NETCONF_PASSWORD=...
# AUTOHEAL_WEBHOOK=https://hooks.slack.com/services/...
EOF
  chmod 640 "$ETC/autoheal.env"
fi
chown -R autoheal:autoheal "$DATA" "$ETC"

if [[ $WITH_KAFKA -eq 1 ]]; then
  echo "==> kafka ${KAFKA_VERSION} (KRaft single node)"
  id kafka >/dev/null 2>&1 || useradd --system --home /opt/kafka --shell /usr/sbin/nologin kafka
  if [[ ! -d /opt/kafka ]]; then
    curl -fsSL "https://archive.apache.org/dist/kafka/${KAFKA_VERSION}/kafka_${SCALA_VERSION}-${KAFKA_VERSION}.tgz" \
      | tar -xz -C /opt
    mv "/opt/kafka_${SCALA_VERSION}-${KAFKA_VERSION}" /opt/kafka
  fi
  mkdir -p /var/lib/kafka
  sed -i "s#^log.dirs=.*#log.dirs=/var/lib/kafka#" /opt/kafka/config/kraft/server.properties
  chown -R kafka:kafka /opt/kafka /var/lib/kafka
  if [[ ! -f /var/lib/kafka/meta.properties ]]; then
    CLUSTER_ID="$(sudo -u kafka /opt/kafka/bin/kafka-storage.sh random-uuid)"
    sudo -u kafka /opt/kafka/bin/kafka-storage.sh format -t "$CLUSTER_ID" -c /opt/kafka/config/kraft/server.properties
  fi
  cat > /etc/systemd/system/kafka.service <<'EOF'
[Unit]
Description=Apache Kafka (KRaft)
After=network-online.target

[Service]
User=kafka
Environment=KAFKA_HEAP_OPTS=-Xms512m -Xmx1g
ExecStart=/opt/kafka/bin/kafka-server-start.sh /opt/kafka/config/kraft/server.properties
Restart=always

[Install]
WantedBy=multi-user.target
EOF
fi

echo "==> systemd units"
cp "$SRC"/deploy/systemd/autoheal-*.service "$SRC"/deploy/systemd/autoheal.target /etc/systemd/system/
systemctl daemon-reload
[[ $WITH_KAFKA -eq 1 ]] && systemctl enable --now kafka.service
[[ $WITH_SIM -eq 1 ]] && systemctl enable --now autoheal-simulator.service
systemctl enable --now autoheal.target

echo
echo "AutoHeal installed."
echo "  config:     $ETC (edit topology.yaml, playbooks.yaml, autoheal.env)"
echo "  validate:   sudo -u autoheal AUTOHEAL_CONFIG=$ETC/settings.yaml $PREFIX/venv/bin/autoheal check"
echo "  status:     systemctl status 'autoheal-*'"
echo "  logs:       journalctl -u 'autoheal-*' -f"
echo "  dashboard:  http://$(hostname -I | awk '{print $1}'):8080"
