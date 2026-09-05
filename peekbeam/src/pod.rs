//! FR1.3 + FR9.1: resolve `--pod <name> -n <namespace>` to a container, via
//! `kubectl` for the node/containerID and then either `container::resolve`
//! (Docker) or `crictl` (containerd), reusing the same cgroup-path logic
//! either way.
//!
//! **Not implemented, and untested against a real cluster** (no Kubernetes
//! cluster was reachable while building this): FR9.2/9.3's automatic
//! `kubectl exec` into a DaemonSet pod on the target's node. That depends on
//! a DaemonSet image/manifest (Usage Mode 3, readme.md §3.1) that doesn't
//! exist yet — orchestrating into a target we can't verify exists would be
//! pure guesswork. When the pod isn't on this node, this prints the right
//! manual command instead (Usage Mode 1 or 2).

use std::process::Command;

use anyhow::{Context, anyhow};

use crate::container::{self, ContainerTarget};

pub fn resolve(pod: &str, namespace: &str) -> anyhow::Result<ContainerTarget> {
    let output = Command::new("kubectl")
        .args([
            "get",
            "pod",
            pod,
            "-n",
            namespace,
            "-o",
            "jsonpath={.spec.nodeName}|{.status.containerStatuses[0].containerID}",
        ])
        .output()
        .context("running `kubectl get pod` (is kubectl installed and configured?)")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "no such pod: `{pod}` in namespace `{namespace}` (kubectl: {})",
            stderr.trim()
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let (node_name, container_ref) = stdout
        .trim()
        .split_once('|')
        .ok_or_else(|| anyhow!("unexpected `kubectl get pod` output: {stdout:?}"))?;

    if container_ref.is_empty() {
        return Err(anyhow!(
            "pod `{pod}` has no running container yet (check `kubectl get pod {pod} -n {namespace}`)"
        ));
    }

    check_same_node(node_name)?;

    let (runtime, id) = container_ref
        .split_once("://")
        .ok_or_else(|| anyhow!("unrecognized containerID format from kubectl: {container_ref:?}"))?;

    match runtime {
        "docker" => container::resolve(id),
        "containerd" => resolve_containerd(id),
        other => Err(anyhow!(
            "unsupported container runtime `{other}` reported by kubectl (only docker and containerd are supported)"
        )),
    }
}

/// FR9.1: peekbeam only ever sees its own node's kernel (readme.md §3.1) — a
/// pod scheduled elsewhere would silently trace nothing without this check.
fn check_same_node(node_name: &str) -> anyhow::Result<()> {
    let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
    let hostname = hostname.trim();

    if hostname.eq_ignore_ascii_case(node_name) {
        return Ok(());
    }

    Err(anyhow!(
        "this pod is scheduled on node `{node_name}`, but peekbeam is running on `{hostname}`.\n\
         peekbeam only sees its own node's kernel (readme.md §3.1) — it can't reach across nodes.\n\
         Run it on that node instead:\n\
         \x20 kubectl debug node/{node_name} -it --image=<peekbeam-image> -- peekbeam --container <id>\n\
         (Usage Mode 2 — needs a peekbeam container image, not built yet), or SSH directly to \
         `{node_name}` (Usage Mode 1)."
    ))
}

/// `crictl inspect --output go-template` mirrors `docker inspect --format`,
/// so we can reuse `container::from_pid` once we have the PID.
fn resolve_containerd(id: &str) -> anyhow::Result<ContainerTarget> {
    let output = Command::new("crictl")
        .args(["inspect", "--output", "go-template", "--template", "{{.info.pid}}", id])
        .output()
        .context("running `crictl inspect` (is crictl installed and configured?)")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("no such containerd container: `{id}` (crictl: {})", stderr.trim()));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let pid: u32 = stdout
        .trim()
        .parse()
        .with_context(|| format!("parsing container PID from crictl inspect: {stdout:?}"))?;

    container::from_pid(pid, id.to_string())
}
