use anyhow::anyhow;
use anyhow::Result;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::Path;
use nix::libc;

pub fn str_to_cstring(s: &str) -> Result<CString> {
    CString::new(s).map_err(|e| anyhow!(e.to_string()))
}

pub fn path_to_cstring<P: AsRef<Path>>(path: P) -> Result<CString> {
    let path_str = path
        .as_ref()
        .to_str()
        .ok_or_else(|| anyhow!(format!("{} is not valid unicode", path.as_ref().display())))?;

    str_to_cstring(path_str)
}

pub fn c_ptr_to_string(p: *const c_char) -> Result<String> {
    if p.is_null() {
        return Err(anyhow!("Null string".to_owned()));
    }

    let c_str = unsafe { CStr::from_ptr(p) };
    Ok(c_str
        .to_str()
        .map_err(|e| anyhow!(e.to_string()))?
        .to_owned())
}

pub fn get_timestamp() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as u64) * 1000000000 + (ts.tv_nsec as u64)
}

pub fn get_index_table(row: usize) -> Vec<Vec<usize>> {
    let mut index_table = Vec::new();

    for i in 0..row {
        let mut tmp = Vec::new();
        for j in 0..row {
            tmp.push(0);
        }
        index_table.push(tmp);
    }
    // 4tt
    // 0 7 8
    // 1 6 9
    // 2 5 10
    // 3 4
    let mut index = 0;
    for i in 0..row {
        let add1 = (row * 2 - 1) - i * 2;
        let add2 = row * 2 - add1;
        let mut switch = false;
        for j in 0..row {
            if j == 0 {
                index = i;
            } else {
                if switch {
                    index += add1;
                } else {
                    index += add2;
                }
            }
            switch = !switch;
            index_table[i][j] = index;
        }
    }
    index_table
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_index_table() {
        let table = get_index_table(2);
        println!("{:#?}", table);
        let table = get_index_table(5);
        println!("{:#?}", table);
    }
}
