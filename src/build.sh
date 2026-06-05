#!/bin/bash
set -e

cd "$(dirname "$0")"

build_server() {
    local target="$1"
    if [ -z "$target" ]; then
        echo "Usage: build.sh [server|magisk|all]"
        exit 1
    fi
    shift

    case "$target" in
        server)
            build_server_all
            ;;
        magisk)
            build_magisk "$@"
            ;;
        all)
            build_server_all
            build_magisk "$@"
            ;;
        *)
            echo "Unknown target: $target"
            echo "Usage: build.sh [server|magisk|all]"
            exit 1
            ;;
    esac
}

build_server_all() {
    echo "=== Building FusionTunX server ==="

    echo "[1/4] Building frontend..."
    cd dash
    if [ ! -d node_modules ]; then
        npm install
    fi
    npm run build
    cd ..

    echo "[1.5/4] Tidying Go modules..."
    go mod tidy

    echo "[2/4] Generating Swagger docs..."
    export PATH=$HOME/go/bin:$PATH
    if command -v swag >/dev/null 2>&1; then
        swag init -g cmd/server/main.go -o docs
    else
        echo "  ! swag not found in PATH; skipping swagger generation"
    fi

    echo "[3/4] Preparing static files..."
    rm -rf internal/ui/dist
    cp -r dash/dist internal/ui/dist
    chmod -R 755 internal/ui/dist

    echo "[4/4] Building Go binaries (Multi-Arch)..."

    platforms=(
        "linux/amd64"
        "linux/arm64"
        "linux/386"
        "linux/arm"
        "linux/mips"
        "linux/mipsle"
        "linux/mips64"
        "linux/mips64le"
        "linux/riscv64"
        "linux/ppc64"
        "linux/ppc64le"
        "linux/s390x"
        "android/arm64"
    )

    mkdir -p bin

    for platform in "${platforms[@]}"; do
        platform_split=(${platform//\// })
        GOOS=${platform_split[0]}
        GOARCH=${platform_split[1]}
        output_name="bin/fusiontunx-$GOOS-$GOARCH"

        if [ "$GOARCH" == "arm" ]; then
            for v in 5 6 7; do
                echo " -> Building for $GOOS/$GOARCH (ARMv${v})..."
                env GIN_MODE=release CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH GOARM=$v \
                    go build -ldflags="-s -w" -o "${output_name}v${v}" ./cmd/server
            done
        else
            echo " -> Building for $GOOS/$GOARCH..."
            EXTRA_ENV=""
            if [ "$GOARCH" = "mips" ] || [ "$GOARCH" = "mipsle" ]; then
                EXTRA_ENV="GOMIPS=softfloat"
            fi
            env GIN_MODE=release CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH $EXTRA_ENV \
                go build -ldflags="-s -w" -o "$output_name" ./cmd/server
        fi
    done

    echo "Server build complete!"
}

build_magisk() {
    local arch="arm64"
    local mihomo_version="v1.19.18"
    local skip_dashboard=0
    local skip_mihomo=0
    local skip_geoip=0
    local refresh=0

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --arch=*)        arch="${1#*=}" ;;
            --mihomo=*)      mihomo_version="${1#*=}" ;;
            --no-dashboard)  skip_dashboard=1 ;;
            --no-mihomo)     skip_mihomo=1 ;;
            --no-geoip)      skip_geoip=1 ;;
            --refresh)       refresh=1 ;;
            *) echo "Unknown flag: $1"; echo "Usage: $0 magisk [--arch=arm64|amd64] [--mihomo=vX.Y.Z] [--no-dashboard] [--no-mihomo] [--no-geoip] [--refresh]"; exit 1 ;;
        esac
        shift
    done

    case "$arch" in
        arm64) mihomo_arch="arm64-v8"; goarch="arm64" ;;
        amd64|x86_64) mihomo_arch="amd64"; goarch="amd64" ;;
        armv7|arm) mihomo_arch="armv7"; goarch="arm" ;;
        386) mihomo_arch="386"; goarch="386" ;;
        *) echo "Unsupported --arch: $arch (use arm64|amd64|armv7|386)"; exit 1 ;;
    esac

    echo "=== Building FusionTunX magisk module (arch=$arch) ==="

    local stage="bin/magisk-stage"
    local out="bin/fusiontunx-magisk.zip"
    rm -f "$out"
    mkdir -p "$stage"

    # skeleton + config files are always re-copied (cheap, ensures freshness)
    rm -rf "$stage/META-INF" "$stage/module.prop" "$stage/customize.sh" \
           "$stage/service.sh" "$stage/app.yaml" \
           "$stage/configs" "$stage/proxy_providers" "$stage/rule_providers"
    local skeleton_files=(META-INF module.prop customize.sh service.sh app.yaml)
    for f in "${skeleton_files[@]}"; do
        cp -R "../files/magisk/$f" "$stage/"
    done
    [ -d ../files/configs ]         && cp -R ../files/configs         "$stage/configs"
    [ -d ../files/proxy_providers ] && cp -R ../files/proxy_providers "$stage/proxy_providers"
    [ -d ../files/rule_providers ]  && cp -R ../files/rule_providers  "$stage/rule_providers"

    # downloads are persistent in $stage (kept across runs; use --refresh to re-fetch)
    if [ "$skip_dashboard" -eq 0 ]; then
        echo "[2/7] Zashboard dashboard..."
        local zash_url="https://github.com/Zephyruso/zashboard/releases/latest/download/dist.zip"
        local zash_asset="dist.zip"
        local zash_sha=""
        if [ "$refresh" -eq 1 ] || [ ! -s "$stage/dashboard.zip" ]; then
            zash_sha=$(github_asset_sha256 Zephyruso/zashboard latest "$zash_asset" || true)
        fi
        fetch_if_missing "$stage/dashboard.zip" "$zash_url" "$refresh" "$zash_sha" || exit 1
    fi

    if [ "$skip_mihomo" -eq 0 ]; then
        echo "[3/7] mihomo $mihomo_version (android-$mihomo_arch)..."
        mkdir -p "$stage/core"
        local mih_asset="mihomo-android-${mihomo_arch}-${mihomo_version}.gz"
        local mih_url="https://github.com/MetaCubeX/mihomo/releases/download/${mihomo_version}/${mih_asset}"
        local mih_sha=""
        if [ "$refresh" -eq 1 ] || [ ! -s "$stage/core/mihomo.gz" ]; then
            mih_sha=$(github_asset_sha256 MetaCubeX/mihomo "tags/${mihomo_version}" "$mih_asset" || true)
        fi
        fetch_if_missing "$stage/core/mihomo.gz" "$mih_url" "$refresh" "$mih_sha" || exit 1
    fi

    if [ "$skip_geoip" -eq 0 ]; then
        echo "[4/7] GeoIP/GeoSite assets..."
        mkdir -p "$stage/geoip"
        fetch_geoip "$stage/geoip" "$refresh"
    fi

    echo "[5/7] Tidying Go modules..."
    go mod tidy

    echo "[6/7] Building magisk daemon (android/$goarch)..."
    mkdir -p "$stage/system/bin"
    env CGO_ENABLED=0 GOOS=android GOARCH=$goarch \
        go build -ldflags="-s -w" -o "$stage/system/bin/fusiontunx" ./cmd/server
    chmod 0755 "$stage/system/bin/fusiontunx"
    echo "  -> $stage/system/bin/fusiontunx (android/$goarch)"

    echo "[7/7] Assembling module zip..."
    if command -v zip >/dev/null 2>&1; then
        (cd "$stage" && zip -qr "../../$out" .)
        echo "  -> $out"
    else
        echo "  ! zip not found; skipping zip packaging. Stage is at $stage/"
    fi

    echo "Magisk build complete!"
}

# ----------------------------------------------------------------------
# Download helpers
# ----------------------------------------------------------------------

have_curl() { command -v curl >/dev/null 2>&1; }
have_wget() { command -v wget >/dev/null 2>&1; }

http_get() {
    local url="$1"; local out="$2"
    if have_curl; then
        curl -fsSL --retry 2 --connect-timeout 15 -o "$out" "$url"
    elif have_wget; then
        wget -q --tries=2 --timeout=30 -O "$out" "$url"
    else
        echo "  ! neither curl nor wget found" >&2
        return 1
    fi
}

file_size() {
    stat -f%z "$1" 2>/dev/null || stat -c%s "$1" 2>/dev/null
}

# sha256_file <path> - print lowercase hex sha256 (macOS/Linux)
sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        echo "  ! neither sha256sum nor shasum found" >&2
        return 1
    fi
}

# github_asset_sha256 <owner/repo> <latest|tag/vX.Y.Z> <asset_name>
# returns "sha256:<hex>" or empty on failure (no error printed, just empty)
github_asset_sha256() {
    local repo="$1" ref="$2" asset="$3"
    local api="https://api.github.com/repos/${repo}/releases/${ref}"
    local body
    body=$(http_get_to_stdout "$api" 2>/dev/null) || return 1
    # Use python3 for reliable JSON parsing (available on macOS & most Linux)
    if command -v python3 >/dev/null 2>&1; then
        printf '%s' "$body" | python3 -c "
import json, sys
d = json.load(sys.stdin)
for a in d.get('assets', []):
    if a.get('name') == sys.argv[1]:
        print(a.get('digest', ''))
        break
" "$asset"
    else
        # Fallback: grep the asset name line and read the next 'digest' line
        printf '%s' "$body" | awk -v want="$asset" '
            $0 ~ "\"name\": \"" want "\"" {found=1; next}
            found && /"digest":/ {
                gsub(/[, "]/, "", $0); print "sha256:" $2; exit
            }
        '
    fi
}

http_get_to_stdout() {
    if have_curl; then
        curl -fsSL --retry 2 --connect-timeout 15 "$1"
    elif have_wget; then
        wget -q --tries=2 --timeout=30 -O - "$1"
    else
        return 1
    fi
}

# fetch_if_missing <out_path> <url> <refresh:0|1> [<expected_sha256>]
# - skips download if out_path exists and refresh=0
# - verifies SHA256 if <expected_sha256> is non-empty (e.g. "sha256:abc..." or "abc...")
fetch_if_missing() {
    local out="$1" url="$2" refresh="$3" expected="$4"
    mkdir -p "$(dirname "$out")"
    if [ "$refresh" -eq 0 ] && [ -s "$out" ]; then
        local size; size=$(file_size "$out")
        echo "  -> using existing ($size bytes)  $out"
        return 0
    fi
    echo "  -> $url"
    if ! http_get "$url" "$out"; then
        echo "  ! download failed" >&2
        rm -f "$out"; return 1
    fi
    local size; size=$(file_size "$out")
    echo "  -> $size bytes  $out"
    if [ -n "$expected" ]; then
        local actual; actual=$(sha256_file "$out" 2>/dev/null) || return 1
        # strip optional "sha256:" prefix from expected
        local want="${expected#sha256:}"
        if [ "$actual" != "$want" ]; then
            echo "  ! SHA256 mismatch" >&2
            echo "    expected: $want" >&2
            echo "    actual:   $actual" >&2
            rm -f "$out"
            return 1
        fi
        echo "  -> SHA256 OK  ($want)"
    fi
}

fetch_geoip() {
    local out="$1" refresh="$2"
    local base="https://github.com/rtaserver/meta-rules-dat/releases"
    local f
    for f in country.mmdb geoip.dat geosite.dat; do
        fetch_if_missing "$out/$f" "$base/latest/download/$f" "$refresh" "" || true
    done
    fetch_if_missing "$out/geoip.metadb" "$base/download/latest/geoip.metadb" "$refresh" "" || true
}

target="${1:-all}"
if [ $# -gt 0 ]; then
    build_server "$@"
else
    build_server "all"
fi
