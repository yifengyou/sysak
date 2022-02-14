use anyhow::anyhow;
use anyhow::Result;
use core::ffi::c_void;
use libbpf_sys;
use std::boxed::Box;
use std::slice;
use std::time::Duration;
use log::*;
use once_cell::sync::Lazy;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use crossbeam_channel::{Sender, Receiver};

fn is_power_of_two(i: usize) -> bool {
    i > 0 && (i & (i - 1)) == 0
}

// Workaround for `trait_alias`
// (https://doc.rust-lang.org/unstable-book/language-features/trait-alias.html)
// not being available yet. This is just a custom trait plus a blanket implementation.
pub trait SampleCb: FnMut(i32, &[u8]) + 'static {}
impl<T> SampleCb for T where T: FnMut(i32, &[u8]) + 'static {}

pub trait LostCb: FnMut(i32, u64) + 'static {}
impl<T> LostCb for T where T: FnMut(i32, u64) + 'static {}

struct CbStruct {
    sample_cb: Option<Box<dyn SampleCb>>,
    lost_cb: Option<Box<dyn LostCb>>,
}

/// Builds [`PerfBuffer`] instances.
pub struct PerfBufferBuilder {
    mapfd: i32,
    pages: usize,
    sample_cb: Option<Box<dyn SampleCb>>,
    lost_cb: Option<Box<dyn LostCb>>,
}

impl PerfBufferBuilder {
    pub fn new(mapfd: i32) -> Self {
        Self {
            mapfd,
            pages: 128,
            sample_cb: None,
            lost_cb: None,
        }
    }
}

impl PerfBufferBuilder {
    /// Callback to run when a sample is received.
    ///
    /// This callback provides a raw byte slice. You may find libraries such as
    /// [`plain`](https://crates.io/crates/plain) helpful.
    ///
    /// Callback arguments are: `(cpu, data)`.
    pub fn sample_cb<NewCb: SampleCb>(self, cb: NewCb) -> PerfBufferBuilder {
        PerfBufferBuilder {
            mapfd: self.mapfd,
            pages: self.pages,
            sample_cb: Some(Box::new(cb)),
            lost_cb: self.lost_cb,
        }
    }

    /// Callback to run when a sample is received.
    ///
    /// Callback arguments are: `(cpu, lost_count)`.
    pub fn lost_cb<NewCb: LostCb>(self, cb: NewCb) -> PerfBufferBuilder {
        PerfBufferBuilder {
            mapfd: self.mapfd,
            pages: self.pages,
            sample_cb: self.sample_cb,
            lost_cb: Some(Box::new(cb)),
        }
    }

    /// The number of pages to size the ring buffer.
    pub fn pages(&mut self, pages: usize) -> &mut Self {
        self.pages = pages;
        self
    }

    pub fn build(self) -> Result<PerfBuffer> {
        if !is_power_of_two(self.pages) {
            return Err(anyhow!("Page count must be power of two"));
        }

        let c_sample_cb: libbpf_sys::perf_buffer_sample_fn = if self.sample_cb.is_some() {
            Some(Self::call_sample_cb)
        } else {
            None
        };

        let c_lost_cb: libbpf_sys::perf_buffer_lost_fn = if self.lost_cb.is_some() {
            Some(Self::call_lost_cb)
        } else {
            None
        };

        let callback_struct_ptr = Box::into_raw(Box::new(CbStruct {
            sample_cb: self.sample_cb,
            lost_cb: self.lost_cb,
        }));

        let ptr = unsafe {
            libbpf_sys::perf_buffer__new(
                self.mapfd,
                self.pages as libbpf_sys::size_t,
                c_sample_cb,
                c_lost_cb,
                callback_struct_ptr as *mut _,
                std::ptr::null(),
            )
        };
        let err = unsafe { libbpf_sys::libbpf_get_error(ptr as *const _) };
        if err != 0 {
            Err(anyhow!("Unable to create perf buffer"))
        } else {
            Ok(PerfBuffer {
                ptr,
                _cb_struct: unsafe { Box::from_raw(callback_struct_ptr) },
            })
        }
    }

    unsafe extern "C" fn call_sample_cb(ctx: *mut c_void, cpu: i32, data: *mut c_void, size: u32) {
        let callback_struct = ctx as *mut CbStruct;

        if let Some(cb) = &mut (*callback_struct).sample_cb {
            cb(cpu, slice::from_raw_parts(data as *const u8, size as usize));
        }
    }

    unsafe extern "C" fn call_lost_cb(ctx: *mut c_void, cpu: i32, count: u64) {
        let callback_struct = ctx as *mut CbStruct;

        if let Some(cb) = &mut (*callback_struct).lost_cb {
            cb(cpu, count);
        }
    }
}

/// Represents a special kind of [`Map`]. Typically used to transfer data between
/// [`Program`]s and userspace.
pub struct PerfBuffer {
    pub ptr: *mut libbpf_sys::perf_buffer,
    // Hold onto the box so it'll get dropped when PerfBuffer is dropped
    _cb_struct: Box<CbStruct>,
}

unsafe impl Send for PerfBuffer {}

impl PerfBuffer {
    pub fn poll(&self, timeout: Duration) -> Result<()> {
        let ret = unsafe { libbpf_sys::perf_buffer__poll(self.ptr, timeout.as_millis() as i32) };
        if ret < 0 {
            Err(anyhow!("Err({}) occurs on perf poll", ret))
        } else {
            Ok(())
        }
    }
}

impl Drop for PerfBuffer {
    fn drop(&mut self) {
        unsafe {
            libbpf_sys::perf_buffer__free(self.ptr);
        }
    }
}

static GLOBAL_TX: Lazy<Mutex<Option<crossbeam_channel::Sender<(usize, Vec<u8>)>>>> =
    Lazy::new(|| Mutex::new(None));

static GLOBAL_RX: Lazy<Mutex<Option<crossbeam_channel::Receiver<(usize, Vec<u8>)>>>> =
    Lazy::new(|| Mutex::new(None));

fn handle_lost_events(cpu: i32, count: u64) {
    error!("Lost {} events on CPU {}", count, cpu);
}

fn handle_event(_cpu: i32, data: &[u8]) {
    let event = Vec::from(data);
    GLOBAL_TX
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .send((_cpu as usize, event))
        .unwrap();
}

fn thread_perf_handle(fd: i32) {
    if fd < 0 {
        return;
    }

    let perf = Arc::new(Mutex::new(
        PerfBufferBuilder::new(fd)
            .sample_cb(handle_event)
            .lost_cb(handle_lost_events)
            .build()
            .unwrap(),
    ));
    let clone_perf = perf.clone();

    thread::spawn(move || loop {
        unsafe {
            libbpf_sys::perf_buffer__consume(perf.lock().unwrap().ptr);
        }
        thread::sleep(Duration::from_millis(100));
    });

    loop {
        clone_perf
            .lock()
            .unwrap()
            .poll(Duration::from_millis(100))
            .unwrap();
    }
}

pub fn perf_inital_thread(fd: i32) {
    let (tx, rx) = crossbeam_channel::unbounded();
    *GLOBAL_TX.lock().unwrap() = Some(tx);
    *GLOBAL_RX.lock().unwrap() = Some(rx);
    thread::spawn(move || thread_perf_handle(fd));
}

pub fn perf_inital_thread2(fd: i32, cs: (Sender<(usize, Vec<u8>)>, Receiver<(usize, Vec<u8>)>)) {
    *GLOBAL_TX.lock().unwrap() = Some(cs.0);
    *GLOBAL_RX.lock().unwrap() = Some(cs.1);
    thread::spawn(move || thread_perf_handle(fd));
}

pub fn perf_recv() -> (usize, Vec<u8>) {
    GLOBAL_RX.lock().unwrap().as_ref().unwrap().recv().unwrap()
}

pub fn perf_recv_timeout(
    timeout: Duration,
) -> std::result::Result<(usize, Vec<u8>), crossbeam_channel::RecvTimeoutError> {
    GLOBAL_RX
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .recv_timeout(timeout)
}


#[cfg(test)]
mod tests {
    use super::*;

    fn is_power_of_two_slow(i: usize) -> bool {
        if i == 0 {
            return false;
        }

        let mut n = i;
        while n > 1 {
            if n & 0x01 as usize == 1 {
                return false;
            }
            n >>= 1;
        }
        true
    }

    #[test]
    fn test_is_power_of_two() {
        for i in 0..=256 {
            assert_eq!(is_power_of_two(i), is_power_of_two_slow(i));
        }
    }
}
