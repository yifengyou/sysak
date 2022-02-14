use anyhow::Result;
use std::io;
use anyhow::anyhow;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::process;
use regex::Regex;

pub struct Gdb {
    stdin: BufWriter<process::ChildStdin>,
    stdout: BufReader<process::ChildStdout>,
}

impl Gdb {
    pub fn new(vmlinux: &String) -> Result<Gdb> {
        let mut child = process::Command::new("gdb")
            .args(&["--interpreter=mi"])
            .stdout(process::Stdio::piped())
            .stdin(process::Stdio::piped())
            .stderr(process::Stdio::piped())
            .spawn()?;
        let mut gdb = Gdb {
            stdin: BufWriter::new(child.stdin.take().expect("broken stdin")),
            stdout: BufReader::new(child.stdout.take().expect("broken stdout")),
        };
        gdb.read_response()?;
        let output = gdb.send_cmd_raw(&format!("file {}\n", vmlinux)[..]);
        // println!("{:?}", output);
        Ok(gdb)
    }

    fn read_sequence(&mut self) -> Result<Vec<String>> {
        let mut result = Vec::new();
        let mut line = String::new();
        self.stdout.read_line(&mut line)?;
        while line != "(gdb) \n" {
            result.push(line.clone());
            line.clear();
            self.stdout.read_line(&mut line)?;
        }
        Ok(result)
    }

    fn read_response(&mut self) -> Result<Vec<String>> {
        loop {
            let sequence = self.read_sequence();
            if let Some(resp) = sequence.into_iter().nth(0) {
                return Ok(resp);
            }
        }
    }

    fn send_cmd_raw(&mut self, cmd: &str) -> Result<Vec<String>> {
        self.stdin.write_all(cmd.as_ref())?;
        self.stdin.flush()?;
        self.read_response()
    }

    pub fn infoline(&mut self, line: &String) -> Result<u64> {
        let string = format!("info line {}\n", line);
        let output = self.send_cmd_raw(&string)?;
        let regex = Regex::new(r"\+(\d+)")?;
        for cap in regex.captures_iter(&output[1]) {
            return Ok(*(&cap[1].parse::<u64>()?));
        }
        Err(anyhow!("unable to get offset"))
    }
}

impl Drop for Gdb {
    fn drop(&mut self) {
        let _ = self.stdin.write_all(b"-gdb-exit\n");
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn test_gdb() {
        let mut g = Gdb::new(
            &"/work/vmlinux-btf/vmlinux/vmlinux-4.19.91-007.ali4000.alios7.x86_64".to_owned(),
        )
        .unwrap();
        g.infoline(&"net/ipv4/tcp.c:400".to_owned()).unwrap();
    }
}
