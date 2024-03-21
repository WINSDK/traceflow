use std::io::Write;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::sync::Arc;
use std::{ffi::CString, path::Path};

use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use nix::libc;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;

use traceflow::Tracer;

fn spawn<P: AsRef<Path>>(tracer: &Tracer, path: P) -> Result<Pid, nix::Error> {
    let c_path = CString::new(path.as_ref().as_os_str().as_encoded_bytes()).unwrap();

    let mut c_args = Vec::with_capacity(1);

    // Push program as first argument.
    c_args.push(c_path.clone());

    // Create a communication pipe for error handling.
    let (pipe_read, pipe_write) = nix::unistd::pipe()?;
    let (pipe_read, pipe_write) = (pipe_read.as_raw_fd(), pipe_write.as_raw_fd());

    // Tell write pipe to close on exec (required for checking successful execution).
    fcntl(pipe_write.as_raw_fd(), FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;

    let child = move || unsafe {
        let _ = nix::unistd::close(pipe_read);

        let report_error = move |err| {
            // Convert error to bytes.
            let errno = (err as i32).to_ne_bytes();

            // Write error status to pipe.
            let _ = nix::unistd::write(std::mem::transmute::<_, BorrowedFd>(pipe_write), &errno);

            // Explicitly close the write end of the pipe to ensure the parent can read EOF
            // if exec hasn't been called.
            let _ = nix::unistd::close(pipe_write);

            libc::_exit(0);
        };

        // Disable address-space-layout randomization (might not be necessary).
        let persona = nix::sys::personality::Persona::ADDR_NO_RANDOMIZE;
        if let Err(err) = nix::sys::personality::set(persona) {
            report_error(err);
        }

        // Signal child process to be traced.
        if let Err(err) = nix::sys::ptrace::traceme() {
            report_error(err);
        }

        // Inherit environmental variables.
        let c_env: Vec<CString> = std::env::vars()
            .flat_map(|(key, val)| CString::new(format!("{key}={val}")))
            .collect();

        // Execute program.
        if let Err(err) = nix::unistd::execvpe(&c_path, &c_args, &c_env) {
            report_error(err);
        }

        std::hint::unreachable_unchecked();
    };

    let child = tracer.fork(Box::new(child))?;
    let _ = nix::unistd::close(pipe_write);

    let mut errno = [0; 4];
    match nix::unistd::read(pipe_read.as_raw_fd(), &mut errno) {
        // Child ran into error.
        Ok(4) => {
            let errno = i32::from_ne_bytes(errno);
            let errno = nix::Error::from_raw(errno);
            return Err(errno);
        }
        // Child ran successfully.
        Ok(..) => {}
        // Unexpected error.
        Err(..) => {}
    }

    let _ = nix::unistd::close(pipe_read);
    Ok(child)
}

fn main_loop(tracer: &Arc<Tracer>, pid: Pid) -> Result<(), nix::Error> {
    loop {
        // Wait for any children to emit an event. Only peek at the status though.
        let status = waitpid(pid, Some(WaitPidFlag::WSTOPPED))?;

        if let WaitStatus::Exited(_, code) = status {
            println!("process exited with code: '{code}'");
            break Ok(());
        }

        let tracer = Arc::clone(&tracer);
        std::thread::spawn(move || -> Result<(), nix::Error> {
            let mut buf = String::new();

            let mut regs = tracer.getregs(pid)?;
            let new_rip = 0x123456789;
            regs.rip = new_rip;
            tracer.setregs(pid, regs)?;
            if tracer.getregs(pid)?.rip == new_rip {
                println!("settings registers works!!!");
            }

            print!("address to read: ");
            std::io::stdout().flush().unwrap();

            std::io::stdin().read_line(&mut buf).unwrap();
            let buf = buf.strip_prefix("0x").unwrap_or(&buf);
            let buf = buf.strip_prefix("0X").unwrap_or(&buf);
            let buf = buf.strip_suffix("\n").unwrap_or(&buf);

            let addr = usize::from_str_radix(buf, 16).unwrap();
            let word = tracer.read(pid, addr)?.to_ne_bytes();
            println!("{word:X?}");

            tracer.cont(pid, None)?;
            Ok(())
        })
        .join()
        .unwrap()?;
    }
}

fn main() -> Result<(), nix::Error> {
    let tracer = Arc::new(Tracer::new());
    let pid = spawn(&tracer, "./loop")?;
    println!("pid: {pid}");

    if let Err(err) = main_loop(&tracer, pid) {
        eprintln!("{err}");
        signal::kill(pid, Signal::SIGKILL)?;
    }

    Ok(())
}
