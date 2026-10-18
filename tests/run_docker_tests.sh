#!/bin/bash
# =============================================================================
# run_docker_tests.sh - Uji ZySentinel via Docker (Debian & AlmaLinux)
# =============================================================================
# Skrip ini membangun image Docker minimal, menjalankan plugin installer,
# dan mengeksekusi suite unit test lengkap untuk ZySentinel.
#
# Penggunaan: bash run_docker_tests.sh [debian|almalinux|all]
# =============================================================================

set -euo pipefail

TARGET="${1:-all}"
SENTINEL_ZIP="/www/backup/sentinel.zip"
TEST_SCRIPT="/tmp/docker_sentinel_test/test_docker_full.py"
RESULTS_DIR="/tmp/docker_sentinel_test/results"
mkdir -p "$RESULTS_DIR"

# Warna terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

# Verifikasi prasyarat
if [ ! -f "$SENTINEL_ZIP" ]; then
    error "sentinel.zip tidak ditemukan di $SENTINEL_ZIP"
    exit 1
fi

if [ ! -f "$TEST_SCRIPT" ]; then
    error "Script test tidak ditemukan: $TEST_SCRIPT"
    exit 1
fi

echo ""
echo "========================================================================"
echo " ZYSENTINEL DOCKER TEST RUNNER"
echo " Target: $TARGET"
echo " sentinel.zip: $SENTINEL_ZIP ($(du -sh $SENTINEL_ZIP | cut -f1))"
echo " SHA-256: $(sha256sum $SENTINEL_ZIP | cut -c1-16)..."
echo "========================================================================"

# =============================================================================
# Fungsi: Jalankan test pada container tertentu
# =============================================================================
run_test_on_container() {
    local distro="$1"
    local image="$2"
    local pkg_cmd="$3"
    local log_file="$RESULTS_DIR/${distro}_test.log"

    info "Membangun container $distro ($image)..."

    # Buat Dockerfile inline
    local dockerfile="/tmp/docker_sentinel_test/Dockerfile.${distro}.run"
    if [ "$distro" = "debian" ]; then
        cat > "$dockerfile" << 'DOCKEREOF'
FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Jakarta
RUN apt-get update -qq && apt-get install -y -qq \
    gcc libc6-dev libsqlite3-dev sqlite3 \
    ipset iptables iproute2 \
    python3 nodejs \
    curl wget unzip procps sudo file \
    ca-certificates coreutils bash \
    2>/dev/null && rm -rf /var/lib/apt/lists/*
RUN ln -sf /usr/bin/python3 /usr/bin/python 2>/dev/null || true
RUN printf '#!/bin/sh\necho "ClamAV 1.0.0"\nexit 0\n' > /usr/local/bin/clamscan && chmod 755 /usr/local/bin/clamscan
DOCKEREOF
    else
        cat > "$dockerfile" << 'DOCKEREOF'
FROM almalinux:9-minimal
RUN microdnf install -y \
    gcc glibc-devel sqlite sqlite-devel \
    iptables ipset iproute \
    python3 nodejs \
    wget unzip procps-ng sudo file \
    ca-certificates bash findutils \
    && microdnf clean all
RUN ln -sf /usr/bin/python3 /usr/bin/python 2>/dev/null || true
RUN printf '#!/bin/sh\necho "ClamAV 1.0.0"\nexit 0\n' > /usr/local/bin/clamscan && chmod 755 /usr/local/bin/clamscan
DOCKEREOF
    fi

    local image_name="zy-test-${distro}:latest"

    # Build image
    if ! docker build -f "$dockerfile" -t "$image_name" /tmp/docker_sentinel_test/ --quiet >/dev/null 2>&1; then
        warn "Build quiet gagal, mencoba ulang dengan output penuh..."
        docker build -f "$dockerfile" -t "$image_name" /tmp/docker_sentinel_test/
    fi
    ok "Image $image_name berhasil dibangun."

    # Setup structure dalam container dan jalankan test
    info "Menjalankan test suite pada $distro..."
    local geo_mount=""
    if [ -f "/www/server/panel/data/firewall/GeoLite2-Country.json" ]; then
        geo_mount="-v /www/server/panel/data/firewall/GeoLite2-Country.json:/www/server/panel/data/firewall/GeoLite2-Country.json:ro"
    fi

    docker run --rm --privileged \
        -v "$SENTINEL_ZIP:/tmp/sentinel.zip:ro" \
        -v "$TEST_SCRIPT:/tmp/test_docker_full.py:ro" \
        $geo_mount \
        "$image_name" \
        /bin/bash -c '
set -e

# ---------------------------------------------------------------
# 1. Siapkan struktur direktori aaPanel
# ---------------------------------------------------------------
mkdir -p /www/server/panel/class \
         /www/server/panel/plugin/sentinel \
         /www/wwwroot \
         /www/wwwlogs

useradd -r -u 1002 -m -s /bin/bash www 2>/dev/null || true

# ---------------------------------------------------------------
# 2. Extract dan install plugin via install.sh pasang
# ---------------------------------------------------------------
unzip -o -q /tmp/sentinel.zip -d /tmp/sentinel_extract/
cp -a /tmp/sentinel_extract/sentinel/. /www/server/panel/plugin/sentinel/

cd /www/server/panel/plugin/sentinel
bash install.sh pasang

# Siapkan dummy log untuk vhost test
mkdir -p /www/wwwlogs
echo "127.0.0.1 - - [test] \"GET / HTTP/1.1\" 200 100" > /www/wwwlogs/test.local.log

echo ""
echo "=== Installation Summary ==="
echo "guardd: $(ls -lh /www/server/sentinel/bin/guardd 2>/dev/null || echo MISSING)"
echo "guardctl: $(ls -lh /www/server/sentinel/bin/guardctl 2>/dev/null || echo MISSING)"
echo "sentinel_main.py: $(ls -lh /www/server/panel/plugin/sentinel/sentinel_main.py 2>/dev/null || echo MISSING)"
echo "============================="

# ---------------------------------------------------------------
# 3. Jalankan test suite
# ---------------------------------------------------------------
export SENTINEL_PLUGIN_DIR="/www/server/panel/plugin/sentinel"
export SENTINEL_DIR="/www/server/sentinel"

echo ""
python3 /tmp/test_docker_full.py
exit $?
        ' 2>&1 | tee "$log_file"

    local exit_code=${PIPESTATUS[0]}

    echo ""
    if [ $exit_code -eq 0 ]; then
        ok "=== $distro: SEMUA TEST LOLOS (PASSED) ==="
    else
        error "=== $distro: ADA TEST YANG GAGAL (FAILED) ==="
    fi
    echo ""

    return $exit_code
}

# =============================================================================
# Jalankan test berdasarkan target
# =============================================================================
DEBIAN_RESULT=0
ALMA_RESULT=0

if [ "$TARGET" = "all" ] || [ "$TARGET" = "debian" ]; then
    info "=== Menjalankan Test Suite: Debian 12 Bookworm ==="
    run_test_on_container "debian" "debian:bookworm-slim" "apt-get" || DEBIAN_RESULT=$?
fi

if [ "$TARGET" = "all" ] || [ "$TARGET" = "almalinux" ]; then
    info "=== Menjalankan Test Suite: AlmaLinux 9 ==="
    run_test_on_container "almalinux" "almalinux:9-minimal" "microdnf" || ALMA_RESULT=$?
fi

# =============================================================================
# Ringkasan Akhir
# =============================================================================
echo ""
echo "========================================================================"
echo " DOCKER TEST RUNNER - RINGKASAN AKHIR"
echo "========================================================================"
[ "$TARGET" = "all" ] || [ "$TARGET" = "debian" ] && {
    [ $DEBIAN_RESULT -eq 0 ] \
        && echo -e "${GREEN} Debian 12:   PASSED${NC}" \
        || echo -e "${RED} Debian 12:   FAILED (exit code $DEBIAN_RESULT)${NC}"
}
[ "$TARGET" = "all" ] || [ "$TARGET" = "almalinux" ] && {
    [ $ALMA_RESULT -eq 0 ] \
        && echo -e "${GREEN} AlmaLinux 9: PASSED${NC}" \
        || echo -e "${RED} AlmaLinux 9: FAILED (exit code $ALMA_RESULT)${NC}"
}
echo "========================================================================"

[ $DEBIAN_RESULT -eq 0 ] && [ $ALMA_RESULT -eq 0 ] && exit 0 || exit 1
