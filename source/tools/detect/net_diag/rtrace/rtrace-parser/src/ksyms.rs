use anyhow::Result;
use once_cell::sync::Lazy;
use std::fs::File;
use std::io::{self, BufRead};
use std::sync::Mutex;
use log::*;
#[derive(Debug, Default)]
pub struct Ksyms {
    syms: Vec<(String, u64)>,
}

impl Ksyms {
    pub fn new() -> Self {
        Ksyms { syms: Vec::new() }
    }

    pub(crate) fn insert(&mut self, sym_name: String, sym_addr: u64) {
        self.syms.push((sym_name, sym_addr));
    }

    pub(crate) fn get_ksyms_num(&self) -> usize {
        self.syms.len()
    }

    pub fn load(&mut self, filename: &String) -> Result<()> {
        self.syms.clear();
        let file = File::open(filename)?;
        let lines = io::BufReader::new(file).lines();
        for line in lines {
            if let Ok(l) = line {
                let mut iter = l.trim().split_whitespace();
                if let Some(x) = iter.next() {
                    iter.next();
                    if let Some(y) = iter.next() {
                        self.insert(y.to_string(), u64::from_str_radix(x, 16).unwrap());
                    }
                }
            }
        }
        self.syms.sort_by(|a, b| a.1.cmp(&b.1));
        debug!(
            "Load ksyms done from {:?}, symbols length: {}",
            filename,
            self.syms.len()
        );
        Ok(())
    }

    pub fn addr_to_name(&self, addr: u64) -> String {
        let mut start = 0;
        let mut end = self.syms.len() - 1;
        let mut mid;
        let mut sym_addr;

        while start < end {
            mid = start + (end - start + 1) / 2;
            sym_addr = self.syms[mid].1;

            if sym_addr <= addr {
                start = mid;
            } else {
                end = mid - 1;
            }
        }

        if start == end && self.syms[start].1 <= addr {
            let mut name = self.syms[start].0.clone();
            name.push_str(&format!("+{}", addr - self.syms[start].1 - 1));
            return name;
        }

        return String::from("Not Found");
    }
}

/// 
static GLOBAL_KSYMS: Lazy<Mutex<Ksyms>> = Lazy::new(|| {
    let ksyms = Ksyms::new();
    Mutex::new(ksyms)
});

/// load all kernel symbols
pub fn ksyms_load(filename: &String) {
    GLOBAL_KSYMS.lock().unwrap().load(filename).unwrap();
}

/// Convert the kernel symbol address to the form of function name + offset
pub fn ksyms_addr_to_name(addr: u64) -> String {
    GLOBAL_KSYMS.lock().unwrap().addr_to_name(addr)
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn test_ksyms_load() {
        let mut ksym = Ksyms::new();
        let err = ksym.load(&PathBuf::from("/proc/kallsyms"));
        assert_eq!(err.is_ok(), true);
        let pre_len = ksym.get_ksyms_num();

        let err = ksym.load(&PathBuf::from("/3124/2123"));
        assert_eq!(err.is_ok(), false);
        let aft_len = ksym.get_ksyms_num();
        assert_ne!(pre_len, aft_len);
    }

    #[test]
    fn test_ksyms_search() {
        let mut ksym = Ksyms::new();
        ksym.insert(String::from("test3"), 3);
        ksym.insert(String::from("test1"), 1);
        ksym.insert(String::from("test2"), 2);
    }
}
