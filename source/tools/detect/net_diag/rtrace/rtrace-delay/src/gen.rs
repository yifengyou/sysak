use anyhow::Result;
use rtrace_rs::rtrace::Config;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use uname::uname;

fn get_btf_path() -> String {
    let mut default = String::from("/boot/vmlinux-");
    let info = uname().expect("uname failed");
    default.push_str(&info.release[..]);
    default
}

fn gen_config_common(path: &PathBuf, text: &str) -> Result<()> {
    let mut config = Config::from_str(text)?;
    config.basic.btf_path = Some(get_btf_path());
    let string = Config::to_string(&config)?;
    let mut output = File::create(path)?;
    write!(output, "{}", string);
    Ok(())
}

fn gen_config_ping_receiver(path: &mut PathBuf) -> Result<()> {
    let text = r#"
[basic]
debug = false
duration = 0
protocol = "icmp"
recv = true

[[filter]]
pid = 0
dst = "0.0.0.0:0"
src = "0.0.0.0:0"

[[function]]
name = "dev_hard_start_xmit"
enable = true
params = ["basic"]

[[function]]
name = "__netif_receive_skb_core"
enable = true
params = ["basic"]

[[function]]
name = "icmp_rcv"
enable = true
params = ["basic"]
    "#;

    path.push("ping-receiver.toml");
    gen_config_common(path, &text)?;
    path.pop();
    Ok(())
}

fn gen_config_ping_sender(path: &mut PathBuf) -> Result<()> {
    let text = r#"
[basic]
debug = false
duration = 0
protocol = "icmp"
recv = false

[[filter]]
pid = 0
dst = "0.0.0.0:0"
src = "0.0.0.0:0"

[[function]]
name = "raw_sendmsg"
enable = true
params = ["basic"]

[[function]]
name = "dev_hard_start_xmit"
enable = true
params = ["basic"]

[[function]]
name = "__netif_receive_skb_core"
enable = true
params = ["basic"]

[[function]]
name = "ping_rcv"
enable = true
params = ["basic"]
    "#;
    path.push("ping-sender.toml");
    gen_config_common(path, &text)?;
    path.pop();
    Ok(())
}

fn gen_config_syn_sender(path: &mut PathBuf) -> Result<()> {
    let text = r#"
[basic]
debug = false
duration = 0
protocol = "tcp-syn"
recv = false

[[filter]]
pid = 0
dst = "0.0.0.0:0"
src = "0.0.0.0:0"

[[function]]
name = "__ip_queue_xmit"
enable = true
params = ["basic"]

[[function]]
name = "dev_hard_start_xmit"
enable = true
params = ["basic"]

[[function]]
name = "__netif_receive_skb_core"
enable = true
params = ["basic"]

[[function]]
name = "tcp_rcv_state_process"
enable = true
params = ["basic"]
    "#;
    path.push("syn-sender.toml");
    gen_config_common(path, &text)?;
    path.pop();
    Ok(())
}

fn gen_config_tcp_receiver(path: &mut PathBuf) -> Result<()> {
    let text = r#"
    [basic]
debug = false
duration = 0
protocol = "tcp"
recv = true

[[filter]]
pid = 0
dst = "0.0.0.0:0"
src = "0.0.0.0:0"

[[function]]
name = "__ip_queue_xmit"
enable = true
params = ["basic"]

[[function]]
name = "dev_hard_start_xmit"
enable = true
params = ["basic"]

[[function]]
name = "__netif_receive_skb_core"
enable = true
params = ["basic"]

[[function]]
name = "tcp_rcv_established"
enable = true
params = ["basic"]

[[function]]
name = "tcp_queue_rcv"
enable = true
params = ["basic"]

[[function]]
name = "tcp_cleanup_rbuf"
enable = true
params = ["basic"]
    "#;
    path.push("tcp-receiver.toml");
    gen_config_common(path, &text)?;
    path.pop();
    Ok(())
}

fn gen_config_tcp_sender(path: &mut PathBuf) -> Result<()> {
    let text = r#"
    # sudo  RUST_BACKTRACE=1 cargo run -- --config /work/rtrace_parser/delay_send.toml --delay

[basic]
debug = false
duration = 0
protocol = "tcp"
recv = false

[[filter]]
pid = 0
dst = "0.0.0.0:0"
src = "0.0.0.0:0"

[[function]]
name = "tcp_sendmsg"
enable = true
params = ["basic"]

[[function]]
name = "__ip_queue_xmit"
enable = true
params = ["basic"]

[[function]]
name = "dev_hard_start_xmit"
enable = true
params = ["basic"]

[[function]]
name = "__netif_receive_skb_core"
enable = true
params = ["basic"]

[[function]]
name = "tcp_ack"
enable = true
params = ["basic"]
    "#;
    path.push("tcp-sender.toml");
    gen_config_common(path, &text)?;
    path.pop();
    Ok(())
}

pub fn gen_config(path: &str) -> Result<()> {
    let mut p = PathBuf::from(path);
    std::fs::create_dir_all(&p)?;
    gen_config_ping_receiver(&mut p)?;
    gen_config_ping_sender(&mut p)?;
    gen_config_syn_sender(&mut p)?;
    gen_config_tcp_receiver(&mut p)?;
    gen_config_tcp_sender(&mut p)?;
    Ok(())
}
