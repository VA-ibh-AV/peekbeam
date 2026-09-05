//! FR1.2: resolve a `--container <ID>` argument to a cgroup id, via the host
//! process the container runtime reports plus that process's own
//! `/proc/<pid>/cgroup` entry (rather than guessing the runtime's cgroup path
//! convention directly, which readme.md §7 flags as fragile across
//! Docker/containerd and cgroupfs/systemd drivers).
//!
//! Requires the unified cgroup v2 hierarchy: `bpf_get_current_cgroup_id()` on
//! the eBPF side only reflects the v2 hierarchy.

use std::{fs, os::unix::fs::MetadataExt, path::Path, process::Command};

use anyhow::{Context, anyhow};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";

pub struct ContainerTarget {
    pub cgroup_id: u64,
    pub full_id: String,
}

pub fn resolve(id_or_name: &str) -> anyhow::Result<ContainerTarget> {
    if !Path::new(CGROUP_ROOT).join("cgroup.controllers").exists() {
        return Err(anyhow!(
            "--container needs the unified cgroup v2 hierarchy (no cgroup.controllers \
             under {CGROUP_ROOT}); cgroup v1 hosts aren't supported yet"
        ));
    }

    let output = Command::new("docker")
        .args(["inspect", "--format", "{{.State.Pid}}|{{.Id}}", id_or_name])
        .output()
        .context("running `docker inspect` (is Docker installed and on PATH?)")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "no such container: `{id_or_name}` (docker inspect: {})",
            stderr.trim()
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let (pid_str, full_id) = stdout
        .trim()
        .split_once('|')
        .ok_or_else(|| anyhow!("unexpected `docker inspect` output: {stdout:?}"))?;
    let pid: u32 = pid_str
        .parse()
        .with_context(|| format!("parsing container PID from docker inspect: {pid_str:?}"))?;
    if pid == 0 {
        return Err(anyhow!(
            "container `{id_or_name}` is not running (docker reports PID 0)"
        ));
    }

    let cgroup_path = resolve_cgroup_path(pid)?;
    let full_path = format!("{CGROUP_ROOT}{cgroup_path}");
    let metadata =
        fs::metadata(&full_path).with_context(|| format!("statting cgroup path {full_path}"))?;

    Ok(ContainerTarget {
        cgroup_id: metadata.ino(),
        full_id: full_id.trim().to_string(),
    })
}

/// Reads `/proc/<pid>/cgroup` and returns the unified (v2) cgroup path, e.g.
/// `/system.slice/docker-<id>.scope`. This covers every process in the
/// container (init, workers, ...), unlike resolving a single PID.
fn resolve_cgroup_path(pid: u32) -> anyhow::Result<String> {
    let contents = fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .with_context(|| format!("reading /proc/{pid}/cgroup"))?;

    // cgroup v2 hosts have a single "0::<path>" line; cgroup v1 hosts instead
    // have multiple "<hierarchy-id>:<controllers>:<path>" lines.
    contents
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map(str::to_string)
        .ok_or_else(|| {
            anyhow!(
                "no unified (cgroup v2) entry in /proc/{pid}/cgroup; this container \
                 may be running under cgroup v1, which isn't supported yet"
            )
        })
}
