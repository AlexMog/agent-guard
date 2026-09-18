#!/usr/bin/env bash
# Keep the payload pinned to a reviewed runtime revision. Update this SHA when
# publishing runtime changes; the bootstrap itself is served from main.
# Wrap execution in a function so a truncated download cannot run half a script.
set -euo pipefail

main() {
    local source_commit=d21b14efb716c17425425412e76dfe4d6e249dee
    local target_uid='' observe=0 check=0 current_uid systemd_version temp_dir source_dir
    local -a installer_args elevate=()

    die() { printf 'Agent Guard: %s\n' "$*" >&2; exit 1; }
    while (( $# )); do
        case "$1" in
            --uid)
                (( $# >= 2 )) || die '--uid requires a numeric user ID.'
                target_uid=$2; shift 2 ;;
            --observe) observe=1; shift ;;
            --check) check=1; shift ;;
            --help|-h)
                cat <<'HELP'
Usage: install.sh [--uid UID] [--observe] [--check]

Install Agent Guard and enable resource limits for new workloads.
Existing installations are updated without changing configuration or state.

  --uid UID   Track this non-root user (default: the invoking user).
  --observe   Fresh installation without CPU limits or termination.
  --check     Check prerequisites and source archive structure only.
              Does not run privileged kernel tests or install anything.
  --help      Show this help.

Requires Linux, systemd 255+, Python 3.12+, cgroups v2, curl, and sudo
(unless already root). The kernel must support the process connector.
HELP
                return 0 ;;
            *) die "Unknown option: $1 (use --help)." ;;
        esac
    done

    [[ $(uname -s) == Linux ]] || die 'Linux is required; macOS and Windows are not supported.'
    for command in curl systemctl mktemp; do
        command -v "$command" >/dev/null || die "Missing dependency: $command. Install it with your package manager."
    done
    [[ -x /usr/bin/python3 ]] || die 'Python 3.12+ is required at /usr/bin/python3.'
    /usr/bin/python3 -I -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' \
        || die 'Python 3.12 or newer is required.'
    systemd_version=$(systemctl --version)
    systemd_version=${systemd_version#systemd }
    systemd_version=${systemd_version%% *}
    systemd_version=${systemd_version%%$'\n'*}
    [[ $systemd_version =~ ^[0-9]+$ ]] && (( systemd_version >= 255 )) \
        || die 'systemd 255 or newer is required.'
    [[ -d /run/systemd/system ]] || die 'systemd must be running as the system service manager.'
    [[ -f /sys/fs/cgroup/cgroup.controllers ]] || die 'A cgroups v2 hierarchy is required.'
    for controller in cpuset cpu memory pids; do
        [[ " $(</sys/fs/cgroup/cgroup.controllers) " == *" $controller "* ]] \
            || die "Required cgroup controller is unavailable: $controller."
    done
    current_uid=$(id -u)
    if [[ -z $target_uid ]]; then
        if [[ $current_uid == 0 ]]; then
            target_uid=${SUDO_UID:-}
        else
            target_uid=$current_uid
        fi
    fi
    [[ $target_uid =~ ^[1-9][0-9]*$ ]] \
        || die 'Specify a non-root user with --uid UID, or run from the target user terminal.'
    /usr/bin/python3 -I -c 'import pwd, sys; pwd.getpwuid(int(sys.argv[1]))' "$target_uid" \
        || die "No local account exists for UID $target_uid."
    installer_args=(--uid "$target_uid")
    if [[ -e /etc/agent-guard.json || -L /etc/agent-guard.json ]]; then
        (( observe == 0 )) || die '--observe is for fresh installations; existing configuration is preserved on update.'
        installer_args+=(--update)
        printf 'Updating Agent Guard; preserving configuration and state.\n'
    elif (( observe == 0 )); then
        installer_args+=(--enforce-new)
    fi
    if [[ $current_uid != 0 ]] && (( check == 0 )); then
        command -v sudo >/dev/null || die 'sudo is required; alternatively, run as root with --uid UID.'
        elevate=(sudo --)
    fi

    umask 077
    temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/agent-guard.XXXXXXXX")
    # Keep the path alive if Bash unwinds main before executing the EXIT trap.
    declare -g agent_guard_temp_dir="$temp_dir"
    cleanup() { rm -rf -- "$agent_guard_temp_dir"; }
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    printf 'Downloading Agent Guard revision %s...\n' "$source_commit"
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --tlsv1.2 --connect-timeout 15 --max-time 120 --retry 2 --max-filesize 16777216 \
        --output "$temp_dir/source.tar.gz" \
        "https://codeload.github.com/AlexMog/agent-guard/tar.gz/$source_commit"
    source_dir=$(/usr/bin/python3 -I - "$temp_dir/source.tar.gz" "$temp_dir" <<'PY'
import sys
import tarfile
from pathlib import Path, PurePosixPath

archive, destination = sys.argv[1:]
with tarfile.open(archive, 'r:gz') as source:
    members = source.getmembers()
    roots, names = set(), set()
    if not members or len(members) > 10000 or sum(m.size for m in members) > 64 * 1024**2:
        raise SystemExit('Archive is empty or exceeds the installation size limit.')
    for member in members:
        path = PurePosixPath(member.name)
        if (path.is_absolute() or '..' in path.parts or not path.parts
                or not (member.isfile() or member.isdir()) or path in names):
            raise SystemExit('Unsafe or duplicate archive member rejected.')
        roots.add(path.parts[0])
        names.add(path)
    if len(roots) != 1:
        raise SystemExit('Expected one source directory in the archive.')
    source.extractall(destination, members=members, filter='data')
root = Path(destination) / roots.pop()
for required in ('install.py', 'agent_guard/__init__.py', 'packaging/agent-guard.service', 'tests/test_events.py'):
    if not (root / required).is_file():
        raise SystemExit(f'Incomplete download: missing {required}.')
print(root)
PY
    )
    if (( check )); then
        printf 'Prerequisites and source archive checked. Nothing installed.\n'
    else
        printf 'Installing for UID %s. Administrator authentication may be requested.\n' "$target_uid"
        # Downloads stay private, but the installed CLI must be user-accessible.
        (umask 022; "${elevate[@]}" /usr/bin/python3 "$source_dir/install.py" "${installer_args[@]}")
        printf 'Agent Guard is ready. Run: agent-guard status\n'
    fi
    # Clean up before local variables leave scope; EXIT also handles failures.
    cleanup
    trap - EXIT INT TERM
}

main "$@"
