ui_print "Installing fusiontunx..."

case "${ARCH}" in
    arm64) ;;
    arm)   ui_print "  ! 32-bit arm is not currently supported"; abort ;;
    x86_64) ui_print "  ! x86_64 is not currently supported"; abort ;;
    *)     ui_print "  ! unsupported architecture: ${ARCH}"; abort ;;
esac

DATA_DIR="/data/adb/fusiontunx"
RUN_DIR="${DATA_DIR}/run"
CORE_DIR="${DATA_DIR}/core"
CONFIGS_DIR="${DATA_DIR}/configs"
DASHBOARD_DIR="${DATA_DIR}/ui/zashboard"

ui_print "  - creating data directories"
mkdir -p "${RUN_DIR}"
mkdir -p "${CORE_DIR}"
mkdir -p "${CONFIGS_DIR}"
mkdir -p "${DATA_DIR}/proxy_providers"
mkdir -p "${DATA_DIR}/rule_providers"

ui_print "  - installing daemon binary"
chmod 0755 "${MODPATH}/system/bin/fusiontunx"
set_perm "${MODPATH}/system/bin/fusiontunx" 0 0 0755

if [ -f "${MODPATH}/core/mihomo.gz" ] ; then
    ui_print "  - extracting mihomo core"
    gunzip -f "${MODPATH}/core/mihomo.gz"
    mv "${MODPATH}/core/mihomo" "${CORE_DIR}/mihomo"
    rmdir "${MODPATH}/core" 2>/dev/null
    chmod 0755 "${CORE_DIR}/mihomo"
    set_perm "${CORE_DIR}/mihomo" 0 0 0755
    if command -v setcap >/dev/null 2>&1 ; then
        setcap 'cap_net_admin,cap_net_raw+ep' "${CORE_DIR}/mihomo" || \
            ui_print "  ! setcap failed; mihomo may not be able to set up TUN"
    fi
fi

if [ -d "${MODPATH}/configs" ] ; then
    ui_print "  - installing mihomo config"
    cp -R "${MODPATH}/configs/." "${CONFIGS_DIR}/"
    rm -rf "${MODPATH}/configs"
fi

if [ -d "${MODPATH}/proxy_providers" ] ; then
    cp -R "${MODPATH}/proxy_providers/." "${DATA_DIR}/proxy_providers/"
    rm -rf "${MODPATH}/proxy_providers"
fi

if [ -d "${MODPATH}/rule_providers" ] ; then
    cp -R "${MODPATH}/rule_providers/." "${DATA_DIR}/rule_providers/"
    rm -rf "${MODPATH}/rule_providers"
fi

if [ -f "${MODPATH}/dashboard.zip" ] ; then
    ui_print "  - extracting dashboard"
    rm -rf "${DASHBOARD_DIR}"
    mkdir -p "${DASHBOARD_DIR}"
    unzip -q -o "${MODPATH}/dashboard.zip" -d "${DASHBOARD_DIR}"
    if [ -d "${DASHBOARD_DIR}/dist" ] ; then
        mv "${DASHBOARD_DIR}/dist/"* "${DASHBOARD_DIR}/" 2>/dev/null
        rmdir "${DASHBOARD_DIR}/dist" 2>/dev/null
    fi
    rm -f "${MODPATH}/dashboard.zip"
fi

if [ -d "${MODPATH}/geoip" ] ; then
    ui_print "  - installing GeoIP/GeoSite assets"
    for f in country.mmdb geoip.dat geosite.dat geoip.metadb ; do
        if [ -f "${MODPATH}/geoip/${f}" ] ; then
            mv "${MODPATH}/geoip/${f}" "${DATA_DIR}/${f}"
        fi
    done
    rmdir "${MODPATH}/geoip" 2>/dev/null
fi

if [ -f "${MODPATH}/app.yaml" ] && [ ! -f "${DATA_DIR}/app.yaml" ] ; then
    mv "${MODPATH}/app.yaml" "${DATA_DIR}/app.yaml"
else
    rm -f "${MODPATH}/app.yaml"
fi

if [ ! -f "${DATA_DIR}/packages.list" ] ; then
    touch "${DATA_DIR}/packages.list"
fi

set_perm_recursive "${MODPATH}" 0 0 0755 0644
set_perm "${MODPATH}/system/bin/fusiontunx" 0 0 0755
set_perm_recursive "${DATA_DIR}" 0 3005 0755 0644
set_perm "${DATA_DIR}/core/mihomo" 0 3005 0755
set_perm "${DATA_DIR}/app.yaml" 0 3005 0644
set_perm "${DATA_DIR}/packages.list" 0 3005 0644

ui_print "  - fusiontunx installed"
ui_print "  - dashboard:  http://127.0.0.1:9090"
ui_print "  - config:     ${CONFIGS_DIR}/config.yaml"
