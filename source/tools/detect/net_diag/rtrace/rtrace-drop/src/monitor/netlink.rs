use crate::base::{RtraceDrop, RtraceDropAction};
use anyhow::Result;
use netlink_packet_route::traits::Parseable;
use netlink_packet_route::{
    nlas::link::Nla, nlas::link::Stats64, nlas::link::Stats64Buffer, nlas::NlaBuffer, LinkMessage,
    NetlinkHeader, NetlinkMessage, NetlinkPayload, RtnlMessage, NLM_F_DUMP, NLM_F_REQUEST,
};
use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};
use std::collections::HashMap;

#[derive(Default, Clone)]
struct Index {
    overrun: u64,
}

#[derive(Default, Clone)]
pub struct Netlink {
    index_hm: HashMap<String, Index>,
}

impl RtraceDrop for Netlink {
    fn get_name(&self) -> &str {
        "netlink"
    }

    fn get_status(&self) -> &str {
        "[Support: overrun]"
    }

    fn is_periodic(&self) -> bool {
        true
    }

    fn run_periodically(&mut self) -> RtraceDropAction {
        let mut socket = Socket::new(NETLINK_ROUTE).unwrap();
        let _port_number = socket.bind_auto().unwrap().port_number();
        socket.connect(&SocketAddr::new(0, 0)).unwrap();
        let mut packet = NetlinkMessage {
            header: NetlinkHeader::default(),
            payload: NetlinkPayload::from(RtnlMessage::GetLink(LinkMessage::default())),
        };
        packet.header.flags = NLM_F_DUMP | NLM_F_REQUEST;
        packet.header.sequence_number = 1;
        packet.finalize();
        let mut buf = vec![0; packet.header.length as usize];
        packet.serialize(&mut buf[..]);
        socket.send(&buf[..], 0).unwrap();
        let mut receive_buffer = vec![0; 4096];
        let mut offset = 0;
        let mut stat = None;
        let mut name = None;

        loop {
            let size = socket.recv(&mut &mut receive_buffer[..], 0).unwrap();
            loop {
                let bytes = &receive_buffer[offset..];
                let rx_packet: NetlinkMessage<RtnlMessage> =
                    NetlinkMessage::deserialize(bytes).unwrap();
                match rx_packet.payload {
                    NetlinkPayload::Done => return RtraceDropAction::Continue,
                    NetlinkPayload::InnerMessage(RtnlMessage::NewLink(link)) => {
                        for item in link.nlas.iter() {
                            match item {
                                Nla::Stats64(buff) => {
                                    stat = Some(
                                        Stats64::parse(&Stats64Buffer::new(buff))
                                            .expect("failed to parse")
                                            .clone(),
                                    );
                                }
                                Nla::IfName(n) => {
                                    name = Some(n.clone());
                                }
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }

                if let Some(x) = &name {
                    if let Some(y) = stat {
                        let mut idx = self.index_hm.entry(x.clone()).or_insert(Index::default());
                        let pre_overrun = idx.overrun;
                        idx.overrun = y.rx_over_errors;
                        if idx.overrun > pre_overrun {
                            return RtraceDropAction::Consume(format!(
                                "NIC: {} ring buffer overflow, {} > {}",
                                x, idx.overrun, pre_overrun
                            ));
                        }
                    }
                }

                offset += rx_packet.header.length as usize;
                if offset == size || rx_packet.header.length == 0 {
                    offset = 0;
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iproute() {
        let mut ip = Iproute::default();
        ip.run_periodically();
    }
}
