#!/system/bin/sh
# Magisk service.sh - started on boot (late_start service mode)

# Detect MODPATH if not set (Magisk should set it, but just in case)
if [ -z "${MODPATH}" ] ; then
    MODPATH="$(readlink -f "$0")"
    MODPATH="$(dirname "${MODPATH}")"
fi

DATA_DIR="/data/adb/fusiontunx"
RUN_DIR="${DATA_DIR}/run"
DAEMON="${MODPATH}/system/bin/fusiontunx"
PID_FILE="${RUN_DIR}/fusiontunx.pid"

mkdir -p "${RUN_DIR}"

if [ ! -x "${DAEMON}" ] ; then
    echo "fusiontunx: daemon binary not found or not executable: ${DAEMON}" > "${RUN_DIR}/service.log"
    exit 1
fi

# Kill old instance if running
if [ -f "${PID_FILE}" ] ; then
    OLDPID="$(cat "${PID_FILE}")"
    if [ -n "${OLDPID}" ] && kill -0 "${OLDPID}" 2>/dev/null ; then
        kill "${OLDPID}" 2>/dev/null
        sleep 1
    fi
    rm -f "${PID_FILE}"
fi

nohup "${DAEMON}" --config "${DATA_DIR}/app.yaml" >"${RUN_DIR}/daemon.log" 2>&1 &
echo $! > "${PID_FILE}"
