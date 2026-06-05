#!/system/bin/sh

WAIT_BOOT_SECS=10

if [ -z "${MODPATH}" ] ; then
    MODPATH="$(readlink -f "$0")"
    MODPATH="$(dirname "${MODPATH}")"
fi

export PATH="/system/bin:/system/xbin:/vendor/bin:${PATH}"

DATA_DIR="/data/adb/fusiontunx"
RUN_DIR="${DATA_DIR}/run"
DAEMON="${MODPATH}/system/bin/fusiontunx"
PID_FILE="${RUN_DIR}/fusiontunx.pid"

mkdir -p "${RUN_DIR}"

if [ ! -x "${DAEMON}" ] ; then
    echo "fusiontunx: daemon binary not found" > "${RUN_DIR}/service.log"
    exit 1
fi

if [ -f "${PID_FILE}" ] ; then
    OLDPID="$(cat "${PID_FILE}")"
    if [ -n "${OLDPID}" ] && kill -0 "${OLDPID}" 2>/dev/null ; then
        kill "${OLDPID}" 2>/dev/null
        sleep 1
        kill -0 "${OLDPID}" 2>/dev/null && kill -9 "${OLDPID}" 2>/dev/null
    fi
    rm -f "${PID_FILE}"
fi

(
    sleep "${WAIT_BOOT_SECS}"
    nohup "${DAEMON}" --config "${DATA_DIR}/app.yaml" >>"${RUN_DIR}/daemon.log" 2>&1 &
    echo $! > "${PID_FILE}"
) &
