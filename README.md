# Agent Guard

An independent Linux service that limits local workloads launched by Codex and Claude. No wrappers or instructions for agents are required. Uses the Python 3.12 standard library, systemd 255, cgroups v2, and the process connector.

## Quick install

Run this from the account whose agents you want to limit. No Git clone is needed:

```bash
curl -fsSL https://raw.githubusercontent.com/AlexMog/agent-guard/main/install.sh | bash
```

The script checks prerequisites, downloads a pinned runtime revision over HTTPS, validates and extracts the archive in a temporary directory, and invokes the installer with `sudo` when needed. New installations enable the default **15 GiB memory budget and 50% CPU cap**. Running the command again updates an existing installation while preserving its configuration and state. Temporary downloads are removed on success or failure.

Requirements: Linux running systemd 255+, `/usr/bin/python3` 3.12+, cgroups v2 with `cpuset`, `cpu`, `memory`, and `pids`, and `curl`. Administrator access is required to install. The installer tests kernel process-connector support before changing the system. Missing dependencies are reported; the script does not change package manager configuration.

To start in observation mode, without applying limits:

```bash
curl -fsSL https://raw.githubusercontent.com/AlexMog/agent-guard/main/install.sh | bash -s -- --observe
```

To check prerequisites and the download without installing or requesting administrator access:

```bash
curl -fsSL https://raw.githubusercontent.com/AlexMog/agent-guard/main/install.sh | bash -s -- --check
```

`--check` does not run privileged kernel tests. `--observe` applies only to fresh installations. Use `--uid UID` to select another local, non-root account; when running directly as root without `SUDO_UID`, this option is required. After installation, run `agent-guard status`.

## Policy

- Recognizes installed agent executables, verifies ancestry through `/proc`, reads `fork/exec/exit` events in a dedicated thread with a bounded buffer, and performs a full reconciliation every 30 seconds.
- Process identity combines the PID and start time, with saved state tied to the kernel boot. Names such as `node` or `MainThread` never prove origin.
- One group per workload. Workloads share a **15 GiB PSS memory budget**. The **50% CPU cap** applies to the common parent group of tracked agents, helpers, and workloads: their children inherit it at fork, before classification. A CPU time quota is combined with a `cpuset` restricted to half the logical processors (8 out of 16), preventing simultaneous use of every processor. The processor count is rounded down, with a minimum of one; fractions below one processor are still enforced through the CPU time quota.
- Recognized agent processes, MCP/stdio/code-mode components, and plugin runtimes are protected from memory-triggered termination and excluded from the workload memory budget. They share the CPU cap. Unknown helpers may require extending `is_helper`; check the process inventory after adding a new tool.
- The text of a shell `-c` command does not prove that it is a helper: a preamble mentioning a plugin must not exempt tests from the quota. Actual helpers are recognized when they execute. An update recovers earlier exclusions of this kind only when ancestry to the live agent can be verified; recovered workloads remain protected from memory-triggered termination.
- **All workloads present when enforcement is enabled are protected from automatic memory-triggered termination.** This protection survives service restarts and extends to their descendants. The CPU cap also applies to these workloads.
- **60 seconds of observation at service startup**, followed by three consecutive complete measurements above the memory budget. This is not a separate 60-second wait for each new workload.
- Terminates the newest eligible workload with at least 64 MiB PSS. Only one termination at a time, with at least 10 seconds between decisions. Sends TERM, then KILL after three seconds if needed.
- Before each signal, briefly freezes the group, revalidates its members and executables, and binds process identity to a pidfd. An agent, helper, or unknown member causes the action to be canceled. The audit log is written and synchronized before signaling. No `pkill`, no signaling by name or unverified PID, and no recursive `cgroup.kill`.
- Ambiguous or interrupted migrations quarantine the group; migration markers are persisted before any migration write. Incomplete measurements or lost events suspend new memory decisions.

The memory budget is a **monitoring threshold**, not a strict global `MemoryMax`: the latter would let the kernel choose a victim. Brief overruns are possible. If only protected workloads exceed the threshold, the service reports it without killing anything. PSS measurements include pages allocated before a process moves into a cgroup; swap is reported separately and is not capped in this version. CPU limits are enforced by the kernel: [`cpu.max` and `cpuset` documentation](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html).

## Existing orphan processes

A known process retains its attribution after its parent disappears. A child in an already registered, root-owned workload group can recover its membership. An unknown orphan in a control group remains protected because it might belong to an MCP component.

Older processes whose origin is only suggested by a `/tmp/claude-UID/...` file are **reported candidates**, never automatic termination targets. An agent exiting is not enough evidence that a development server should be stopped. Actual zombies (state Z) have already terminated and are not targeted.

## Verification and installation

```bash
git clone https://github.com/AlexMog/agent-guard.git
cd agent-guard
python3 -m unittest discover -s tests -v
python3 -m agent_guard audit --uid "$(id -u)" --orphans
```

Isolated kernel integration test, operating only on the test's own child processes:

```bash
systemd-run --user --unit=agent-guard-integration-test.service --collect \
  -p Delegate=yes -p RuntimeMaxSec=30 --wait --pipe \
  /usr/bin/python3 "$PWD/tests/integration_cgroups.py" --run
```

Additional test of the shared CPU cap in a temporary root service: inheritance in `control`, a shared quota with `work`, an attempt to widen CPU affinity, and restoration of CPU access:

```bash
sudo systemd-run --unit=agent-guard-cpu-test.service --collect --wait --pipe \
  -p Delegate=yes -p RuntimeMaxSec=30 \
  /usr/bin/python3 "$PWD/tests/integration_cpu_boundary.py" --run
```

Install and enable enforcement for new workloads. Privileged event tests and an initial observation run automatically precede activation:

```bash
sudo /usr/bin/python3 ./install.py --uid "$(id -u)" --enforce-new
```

Omit `--enforce-new` to install in observation mode only: no process migration, CPU limits, or signals. The installer refuses to overwrite an existing installation. Authentication can also be provided through `pkexec`.

## Usage

```bash
agent-guard status
agent-guard explain 12345
agent-guard audit --uid "$(id -u)" --orphans
journalctl -u agent-guard.service
sudo systemctl stop agent-guard.service
```

`status` reports the mode, event stream health, groups, baseline protections, quarantines, and report age. `explain` retrieves termination reasons and the affected process identities from the rotating logs. A Unix signal cannot automatically carry this explanation to the agent's standard output; the explanation remains available without modifying the agent.

Root-owned configuration: `/etc/agent-guard.json`. After editing, run `sudo systemctl restart agent-guard.service`. `mode: "observe"` disables interventions. To enable enforcement after observation, set `mode: "enforce"`; workloads already running at that point become protected. A normal supervisor shutdown removes CPU restrictions, thaws groups, and leaves workloads running. `DelegateSubgroup=supervisor` and `KillMode=process` allow restarts without stopping adopted processes.

State and logs are stored in `/var/lib/agent-guard/`, in root-owned files that agents cannot modify, without raw command arguments or environment variables. Logs rotate across three files of approximately 2 MiB each; state retains at most 256 completed workloads in addition to live workloads.

## Updating and disabling

To disable the service persistently, run `sudo systemctl disable --now agent-guard.service`. Files can remain in place to preserve diagnostics. Do not delete populated cgroups or erase state: it contains protections for existing workloads. To update, stop the service, replace only the root-owned code files and service unit, run `systemctl daemon-reload`, and restart. Preserve the configuration file and state.

The installer also provides `sudo python3 install.py --update`, which reruns event tests, stops the supervisor, replaces the code and unit, and restarts without erasing configuration or state.

Moving a process into a system cgroup can change the session association used by Polkit: `pkexec` launched from a tracked agent may no longer find its graphical authentication agent. Authentication remains available from an untracked user terminal. For an administrative command initiated by an agent, this pattern has been verified:

```bash
systemd-run --user --unit=agent-guard-admin-restart --collect --wait --pipe \
  /usr/bin/pkexec --disable-internal-agent /usr/bin/systemctl restart agent-guard.service
```

This command still requires normal administrator authentication.

## Known limitations

- Initial detection of a new agent happens after it starts. Once the agent is attached, all its descendants immediately inherit the CPU cap, even before being classified as workloads. Events do not provide a mechanism to block execution before it begins; no transparent execution queue is provided.
- The daemon cannot reliably attribute a process retroactively if it predates tracking and all its ancestors have disappeared.
- Docker, remote execution, and commands delegated to an external service are not automatically covered.
- Agents with root privileges cannot be constrained by this service. The recognizer supports Claude installed under `~/.local/share/claude/versions/` and Codex installed through npm under NVM, for accounts under `/home/`. Other locations require adapting `is_agent` in `agent_guard/model.py`.
- Linux process migration still uses a numeric PID. Checks before and after migration, together with a transactional log, quarantine ambiguous results; signals exclusively use pidfds to avoid targeting a reused PID.
- This service does not automatically clean up old servers. Ambiguous cases remain visible and protected.
