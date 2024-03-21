use nix::Error;
use nix::libc;
use nix::sys::ptrace::{Request, RequestType};
use nix::sys::signal::Signal;
use nix::unistd::{fork, ForkResult, Pid};
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

    unsafe fn peek(self) -> c_long {
        let ret = unsafe {
            Error::clear();
            libc::ptrace(
                self.ty as RequestType,
                libc::pid_t::from(self.pid),
                self.addr,
                self.data,
            )
        };

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
            Request::PTRACE_PEEKDATA | Request::PTRACE_PEEKUSER => unsafe { self.peek() },
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
    pub fn new() -> Self {
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
}
