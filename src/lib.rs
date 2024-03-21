use nix::libc::{self, siginfo_t, user_regs_struct};
use nix::sys::ptrace::Options;
use nix::sys::ptrace::{Request, RequestType};
use nix::sys::signal::Signal;
use nix::unistd::{fork, ForkResult, Pid};
use nix::Error;
use nix::Result;

use std::convert::Infallible;
use std::ffi::{c_long, c_void};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Condvar, Mutex};

type AddressType = usize;
type Data = usize;
type ChildCB = dyn FnOnce() -> Infallible + Send + 'static;

struct PtraceRequest {
    ty: Request,
    pid: Pid,
    addr: AddressType,
    data: Data,
}

impl PtraceRequest {
    #[inline]
    unsafe fn other(self) -> c_long {
        let ret = libc::ptrace(
            self.ty as RequestType,
            libc::pid_t::from(self.pid),
            self.addr,
            self.data,
        );

        if ret == -1 {
            -(Error::last() as c_long)
        } else {
            ret
        }
    }

    #[inline]
    unsafe fn peek(self) -> c_long {
        Error::clear();
        let ret = libc::ptrace(
            self.ty as RequestType,
            libc::pid_t::from(self.pid),
            self.addr,
            self.data,
        );

        if ret == -1 {
            let errno = Error::last();

            if errno == Error::UnknownErrno {
                ret
            } else {
                -(errno as c_long)
            }
        } else {
            ret
        }
    }

    fn execute(self) -> c_long {
        match self.ty {
            Request::PTRACE_PEEKDATA | Request::PTRACE_PEEKUSER | Request::PTRACE_SETSIGINFO => {
                unsafe { self.peek() }
            },
            _ => unsafe { self.other() },
        }
    }
}

enum RemoteRequest {
    Fork(Box<ChildCB>),
    Ptrace(PtraceRequest),
}

pub struct Tracer {
    reqs: Sender<RemoteRequest>,
    result: Arc<(Mutex<c_long>, Condvar)>,
}

impl Tracer {
    pub fn spawn() -> Self {
        let (reqs_sendr, reqs_recv) = mpsc::channel::<RemoteRequest>();
        let ress = Arc::new((Mutex::new(c_long::MIN), Condvar::new()));

        let cress = Arc::clone(&ress);
        std::thread::spawn(move || {
            for req in reqs_recv {
                let result = match req {
                    RemoteRequest::Fork(callback) => match unsafe { fork() } {
                        Err(err) => err as c_long,
                        Ok(res) => match res {
                            ForkResult::Child => {
                                callback();
                                unreachable!();
                            }
                            ForkResult::Parent { child } => child.as_raw() as c_long,
                        },
                    },
                    RemoteRequest::Ptrace(req) => req.execute(),
                };

                let (lock, cvar) = &*cress;
                *lock.lock().unwrap() = result;
                cvar.notify_all();
            }
        });

        Self {
            reqs: reqs_sendr,
            result: ress,
        }
    }

    fn send(&self, req: PtraceRequest) -> Result<c_long> {
        let (lock, cvar) = &*self.result;
        let mut lock = lock.lock().unwrap();

        self.reqs.send(RemoteRequest::Ptrace(req)).unwrap();

        while *lock == c_long::MIN {
            lock = cvar.wait(lock).unwrap();
        }

        let result = *lock;
        *lock = c_long::MIN;

        if result < 0 {
            Err(Error::from_raw(-result as i32))
        } else {
            Ok(result)
        }
    }

    pub fn fork(&self, child: Box<ChildCB>) -> Result<Pid> {
        let (lock, cvar) = &*self.result;
        let mut lock = lock.lock().unwrap();

        self.reqs.send(RemoteRequest::Fork(child)).unwrap();

        while *lock == c_long::MIN {
            lock = cvar.wait(lock).unwrap();
        }

        let result = *lock;
        *lock = c_long::MIN;

        if result < 0 {
            Err(Error::from_raw(-result as i32))
        } else {
            Ok(Pid::from_raw(result as i32))
        }
    }

    /// Restart the stopped tracee process, as with `ptrace(PTRACE_CONT, ...)`
    ///
    /// Continues the execution of the process with PID `pid`, optionally
    /// delivering a signal specified by `sig`.
    pub fn cont<T: Into<Option<Signal>>>(&self, pid: Pid, sig: T) -> Result<()> {
        let data = match sig.into() {
            Some(s) => s as i32 as usize,
            None => 0,
        };

        self.send(PtraceRequest {
            ty: Request::PTRACE_CONT,
            pid,
            addr: 0,
            data,
        })
        .map(drop)
    }

    /// Continue execution until the next syscall, as with `ptrace(PTRACE_SYSCALL, ...)`
    ///
    /// Arranges for the tracee to be stopped at the next entry to or exit from a system call,
    /// optionally delivering a signal specified by `sig`.
    pub fn syscall<T: Into<Option<Signal>>>(&self, pid: Pid, sig: T) -> Result<()> {
        let data = match sig.into() {
            Some(s) => s as i32 as usize,
            None => 0,
        };

        self.send(PtraceRequest {
            ty: Request::PTRACE_SYSCALL,
            pid,
            addr: 0,
            data,
        })
        .map(drop)
    }

    /// Sets the process as traceable, as with `ptrace(PTRACE_TRACEME, ...)`
    ///
    /// Indicates that this process is to be traced by its parent.
    /// This is the only ptrace request to be issued by the tracee.
    pub fn traceme(&self) -> Result<()> {
        self.send(PtraceRequest {
            ty: Request::PTRACE_TRACEME,
            pid: Pid::from_raw(0),
            addr: 0,
            data: 0,
        })
        .map(drop)
    }

    /// Reads a word from a processes memory at the given address, as with
    /// ptrace(PTRACE_PEEKDATA, ...)
    pub fn read(&self, pid: Pid, addr: AddressType) -> Result<c_long> {
        self.send(PtraceRequest {
            ty: Request::PTRACE_PEEKDATA,
            pid,
            addr,
            data: 0,
        })
    }

    /// Writes a word into the processes memory at the given address, as with
    /// ptrace(PTRACE_POKEDATA, ...)
    ///
    /// # Safety
    ///
    /// The `data` argument is passed directly to `ptrace(2)`.  Read that man page
    /// for guidance.
    pub unsafe fn write(&self, pid: Pid, addr: AddressType, data: *mut c_void) -> Result<()> {
        self.send(PtraceRequest {
            ty: Request::PTRACE_POKEDATA,
            pid,
            addr,
            data: data as usize,
        })
        .map(drop)
    }

    /// Reads a word from a user area at `offset`, as with ptrace(PTRACE_PEEKUSER, ...).
    /// The user struct definition can be found in `/usr/include/sys/user.h`.
    pub fn read_user(&self, pid: Pid, offset: AddressType) -> Result<c_long> {
        self.send(PtraceRequest {
            ty: Request::PTRACE_PEEKUSER,
            pid,
            addr: offset,
            data: 0,
        })
    }

    /// Writes a word to a user area at `offset`, as with ptrace(PTRACE_POKEUSER, ...).
    /// The user struct definition can be found in `/usr/include/sys/user.h`.
    ///
    /// # Safety
    ///
    /// The `data` argument is passed directly to `ptrace(2)`.  Read that man page
    /// for guidance.
    pub unsafe fn write_user(
        &self,
        pid: Pid,
        offset: AddressType,
        data: *mut c_void,
    ) -> Result<()> {
        self.send(PtraceRequest {
            ty: Request::PTRACE_POKEUSER,
            pid,
            addr: offset,
            data: data as usize,
        })
        .map(drop)
    }

    /// Get user registers, as with `ptrace(PTRACE_GETREGS, ...)`
    #[cfg(all(
        target_os = "linux",
        any(
            all(target_arch = "x86_64", any(target_env = "gnu", target_env = "musl")),
            all(target_arch = "x86", target_env = "gnu")
        )
    ))]
    pub fn getregs(&self, pid: Pid) -> Result<user_regs_struct> {
        self.ptrace_get_data::<user_regs_struct>(Request::PTRACE_GETREGS, pid)
    }

    /// Set user registers, as with `ptrace(PTRACE_SETREGS, ...)`
    #[cfg(all(
        target_os = "linux",
        any(
            all(target_arch = "x86_64", any(target_env = "gnu", target_env = "musl")),
            all(target_arch = "x86", target_env = "gnu")
        )
    ))]
    pub fn setregs(&self, pid: Pid, regs: user_regs_struct) -> Result<()> {
        self.send(PtraceRequest {
            ty: Request::PTRACE_SETREGS,
            pid,
            addr: 0,
            data: &regs as *const _ as usize,
        })
        .map(drop)
    }

    /// Function for ptrace requests that return values from the data field.
    /// Some ptrace get requests populate structs or larger elements than `c_long`
    /// and therefore use the data field to return values. This function handles these
    /// requests.
    fn ptrace_get_data<T>(&self, request: Request, pid: Pid) -> Result<T> {
        let mut data = std::mem::MaybeUninit::<T>::uninit();
        self.send(PtraceRequest {
            ty: request,
            pid,
            addr: 0,
            data: data.as_mut_ptr() as usize,
        })?;
        Ok(unsafe { data.assume_init() })
    }

    /// Set options, as with `ptrace(PTRACE_SETOPTIONS, ...)`.
    pub fn setoptions(&self, pid: Pid, options: Options) -> Result<()> {
        self.send(PtraceRequest {
            ty: Request::PTRACE_SETOPTIONS,
            pid,
            addr: 0,
            data: options.bits() as usize,
        })
        .map(drop)
    }

    /// Gets a ptrace event as described by `ptrace(PTRACE_GETEVENTMSG, ...)`
    pub fn getevent(&self, pid: Pid) -> Result<c_long> {
        self.ptrace_get_data::<c_long>(Request::PTRACE_GETEVENTMSG, pid)
    }

    /// Get siginfo as with `ptrace(PTRACE_GETSIGINFO, ...)`
    pub fn getsiginfo(&self, pid: Pid) -> Result<siginfo_t> {
        self.ptrace_get_data::<siginfo_t>(Request::PTRACE_GETSIGINFO, pid)
    }

    /// Set siginfo as with `ptrace(PTRACE_SETSIGINFO, ...)`
    pub fn setsiginfo(&self, pid: Pid, sig: &siginfo_t) -> Result<()> {
        self.send(PtraceRequest {
            ty: Request::PTRACE_SETSIGINFO,
            pid,
            addr: 0,
            data: sig as *const siginfo_t as usize,
        })
        .map(drop)
    }

    /// Continue execution until the next syscall, as with `ptrace(PTRACE_SYSEMU, ...)`
    ///
    /// In contrast to the `syscall` function, the syscall stopped at will not be executed.
    /// Thus the the tracee will only be stopped once per syscall,
    /// optionally delivering a signal specified by `sig`.
    #[cfg(all(
        target_os = "linux",
        target_env = "gnu",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    pub fn sysemu<T: Into<Option<Signal>>>(&self, pid: Pid, sig: T) -> Result<()> {
        let data = match sig.into() {
            Some(s) => s as i32 as usize,
            None => 0,
        };
        self.send(PtraceRequest {
            ty: Request::PTRACE_SYSEMU,
            pid,
            addr: 0,
            data,
        })
        .map(drop)
    }

    /// Attach to a running process, as with `ptrace(PTRACE_ATTACH, ...)`
    ///
    /// Attaches to the process specified by `pid`, making it a tracee of the calling process.
    pub fn attach(&self, pid: Pid) -> Result<()> {
        self.send(PtraceRequest {
            ty: Request::PTRACE_ATTACH,
            pid,
            addr: 0,
            data: 0,
        })
        .map(drop)
    }

    /// Attach to a running process, as with `ptrace(PTRACE_SEIZE, ...)`
    ///
    /// Attaches to the process specified in pid, making it a tracee of the calling process.
    #[cfg(target_os = "linux")]
    pub fn seize(&self, pid: Pid, options: Options) -> Result<()> {
        self.send(PtraceRequest {
            ty: Request::PTRACE_SEIZE,
            pid,
            addr: 0,
            data: options.bits() as usize,
        })
        .map(drop)
    }

    /// Detaches the current running process, as with `ptrace(PTRACE_DETACH, ...)`
    ///
    /// Detaches from the process specified by `pid` allowing it to run freely, optionally
    /// delivering a signal specified by `sig`.
    pub fn detach<T: Into<Option<Signal>>>(&self, pid: Pid, sig: T) -> Result<()> {
        let data = match sig.into() {
            Some(s) => s as i32 as usize,
            None => 0,
        };
        self.send(PtraceRequest {
            ty: Request::PTRACE_DETACH,
            pid,
            addr: 0,
            data,
        })
        .map(drop)
    }

    /// Stop a tracee, as with `ptrace(PTRACE_INTERRUPT, ...)`
    ///
    /// This request is equivalent to `ptrace(PTRACE_INTERRUPT, ...)`
    #[cfg(target_os = "linux")]
    pub fn interrupt(&self, pid: Pid) -> Result<()> {
        self.send(PtraceRequest {
            ty: Request::PTRACE_INTERRUPT,
            pid,
            addr: 0,
            data: 0,
        })
        .map(drop)
    }

    /// Issues a kill request as with `ptrace(PTRACE_KILL, ...)`
    ///
    /// This request is equivalent to `ptrace(PTRACE_CONT, ..., SIGKILL);`
    pub fn kill(&self, pid: Pid) -> Result<()> {
        self.send(PtraceRequest {
            ty: Request::PTRACE_KILL,
            pid,
            addr: 0,
            data: 0,
        })
        .map(drop)
    }

    /// Move the stopped tracee process forward by a single step as with
    /// `ptrace(PTRACE_SINGLESTEP, ...)`
    ///
    /// Advances the execution of the process with PID `pid` by a single step optionally delivering a
    /// signal specified by `sig`.
    ///
    /// # Example
    /// ```rust
    /// use nix::sys::ptrace::step;
    /// use nix::unistd::Pid;
    /// use nix::sys::signal::Signal;
    /// use nix::sys::wait::*;
    ///
    /// // If a process changes state to the stopped state because of a SIGUSR1
    /// // signal, this will step the process forward and forward the user
    /// // signal to the stopped process
    /// match waitpid(Pid::from_raw(-1), None) {
    ///     Ok(WaitStatus::Stopped(pid, Signal::SIGUSR1)) => {
    ///         let _ = step(pid, Signal::SIGUSR1);
    ///     }
    ///     _ => {},
    /// }
    /// ```
    pub fn step<T: Into<Option<Signal>>>(&self, pid: Pid, sig: T) -> Result<()> {
        let data = match sig.into() {
            Some(s) => s as i32 as usize,
            None => 0,
        };
        self.send(PtraceRequest {
            ty: Request::PTRACE_SINGLESTEP,
            pid,
            addr: 0,
            data,
        })
        .map(drop)
    }

    /// Move the stopped tracee process forward by a single step or stop at the next syscall
    /// as with `ptrace(PTRACE_SYSEMU_SINGLESTEP, ...)`
    ///
    /// Advances the execution by a single step or until the next syscall.
    /// In case the tracee is stopped at a syscall, the syscall will not be executed.
    /// Optionally, the signal specified by `sig` is delivered to the tracee upon continuation.
    #[cfg(all(
        target_os = "linux",
        target_env = "gnu",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    pub fn sysemu_step<T: Into<Option<Signal>>>(&self, pid: Pid, sig: T) -> Result<()> {
        let data = match sig.into() {
            Some(s) => s as i32 as usize,
            None => 0,
        };
        self.send(PtraceRequest {
            ty: Request::PTRACE_SYSEMU_SINGLESTEP,
            pid,
            addr: 0,
            data,
        })
        .map(drop)
    }
}
