#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${BPFRX_CLUSTER_ENV:-${PROJECT_ROOT}/test/incus/loss-userspace-cluster.env}"
BRANCH="$(git -C "${PROJECT_ROOT}" rev-parse --abbrev-ref HEAD)"
WITH_PERF=0

while [[ $# -gt 0 ]]; do
	case "$1" in
	--perf) WITH_PERF=1 ;;
	--env) ENV_FILE="$2"; shift ;;
	*)
		echo "unknown arg: $1" >&2
		exit 2
		;;
	esac
	shift
done

cd "${PROJECT_ROOT}"

git push origin "${BRANCH}"
BPFRX_CLUSTER_ENV="${ENV_FILE}" ./test/incus/cluster-setup.sh deploy all

if [[ ${WITH_PERF} -eq 1 ]]; then
	./scripts/userspace-ha-validation.sh --env "${ENV_FILE}" --perf
else
	./scripts/userspace-ha-validation.sh --env "${ENV_FILE}"
fi
