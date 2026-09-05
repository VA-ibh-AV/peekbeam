//! Syscall number -> name -> plain-language category + one-line annotation.
//!
//! Backs FR6.5 (grouped categories) and FR6.6 (one-line annotations): the default
//! view should be readable without already knowing the syscall table cold.

pub struct SyscallInfo {
    pub name: &'static str,
    pub category: &'static str,
    pub annotation: &'static str,
}

pub fn lookup(nr: u64) -> SyscallInfo {
    let name = syscalls::Sysno::new(nr as usize)
        .map(|sysno| sysno.name())
        .unwrap_or("unknown");
    let (category, annotation) = classify(name);
    SyscallInfo {
        name,
        category,
        annotation,
    }
}

fn classify(name: &str) -> (&'static str, &'static str) {
    match name {
        "read" | "pread64" | "readv" | "preadv" | "preadv2" => {
            ("File I/O", "reading from a file descriptor")
        }
        "write" | "pwrite64" | "writev" | "pwritev" | "pwritev2" => {
            ("File I/O", "writing to a file descriptor")
        }
        "openat" | "openat2" | "open" | "creat" => ("File I/O", "opening a file"),
        "close" | "close_range" => ("File I/O", "closing a file descriptor"),
        "fstat" | "newfstatat" | "statx" | "stat" | "lstat" => {
            ("File I/O", "checking file metadata")
        }
        "lseek" => ("File I/O", "moving the read/write position in a file"),
        "getdents64" => ("File I/O", "reading directory entries"),
        "ioctl" => ("File I/O", "device-specific control operation"),
        "fsync" | "fdatasync" => ("File I/O", "flushing file data to disk"),

        "socket" => ("Networking", "creating a network socket"),
        "connect" => ("Networking", "connecting to a remote address"),
        "accept" | "accept4" => ("Networking", "accepting an incoming connection"),
        "sendto" | "sendmsg" | "sendmmsg" => ("Networking", "sending data on a socket"),
        "recvfrom" | "recvmsg" | "recvmmsg" => ("Networking", "receiving data on a socket"),
        "bind" => ("Networking", "binding a socket to an address"),
        "listen" => ("Networking", "listening for incoming connections"),
        "epoll_wait" | "epoll_pwait" | "epoll_pwait2" | "epoll_ctl" | "epoll_create1" => {
            ("Networking", "waiting on / managing I/O readiness (often sockets)")
        }
        "poll" | "ppoll" | "select" | "pselect6" => {
            ("Networking", "waiting on multiple file descriptors for I/O readiness")
        }
        "getsockopt" | "setsockopt" => ("Networking", "reading/setting socket options"),
        "shutdown" => ("Networking", "shutting down part of a socket connection"),

        "clone" | "clone3" | "fork" | "vfork" => {
            ("Process/Thread", "creating a new process/thread")
        }
        "execve" | "execveat" => {
            ("Process/Thread", "replacing the process image (running a new program)")
        }
        "exit" | "exit_group" => ("Process/Thread", "terminating the process/thread"),
        "wait4" | "waitid" => ("Process/Thread", "waiting for a child process to change state"),
        "sched_yield" => ("Process/Thread", "yielding the CPU to another thread"),
        "sched_getaffinity" | "sched_setaffinity" => {
            ("Process/Thread", "reading/setting which CPUs this thread may run on")
        }
        "gettid" | "getpid" | "getppid" => ("Process/Thread", "reading a process/thread ID"),
        "set_tid_address" | "set_robust_list" | "prctl" => {
            ("Process/Thread", "thread/process bookkeeping for the kernel")
        }

        "mmap" => ("Memory", "mapping memory (file-backed or anonymous)"),
        "munmap" => ("Memory", "unmapping memory"),
        "mprotect" => ("Memory", "changing memory protection flags"),
        "brk" => ("Memory", "adjusting the heap break"),
        "madvise" => ("Memory", "giving the kernel a memory usage hint"),
        "mremap" => ("Memory", "resizing/moving an existing memory mapping"),

        "futex" => ("Synchronization", "waiting on or waking a lock"),
        "rt_sigaction" | "rt_sigprocmask" | "rt_sigreturn" | "rt_sigsuspend" | "tgkill" => {
            ("Synchronization", "signal handling setup or delivery")
        }

        _ => ("Other", "uncommon syscall, no plain-language annotation yet"),
    }
}
