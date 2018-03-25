extern crate byteorder;
extern crate ip_network;

use std::io;
use std::str;
use std::net::{Ipv6Addr, Ipv4Addr, IpAddr};
use byteorder::{BigEndian, ReadBytesExt};
use ip_network::{IpNetwork, Ipv4Network, Ipv6Network};

pub mod bgp;
pub mod processor;

fn read_ip_addr<R: ReadBytesExt>(rdr: &mut R, is_ipv6: bool) -> io::Result<IpAddr> {
    if is_ipv6 {
        Ok(IpAddr::V6(Ipv6Addr::new(
            rdr.read_u16::<BigEndian>()?,
            rdr.read_u16::<BigEndian>()?,
            rdr.read_u16::<BigEndian>()?,
            rdr.read_u16::<BigEndian>()?,
            rdr.read_u16::<BigEndian>()?,
            rdr.read_u16::<BigEndian>()?,
            rdr.read_u16::<BigEndian>()?,
            rdr.read_u16::<BigEndian>()?,
        )))
    } else {
        Ok(IpAddr::V4(Ipv4Addr::from(rdr.read_u32::<BigEndian>()?)))
    }
}

pub struct Parser<R: ReadBytesExt> {
    reader: R,
}

impl<R: ReadBytesExt> Parser<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader
        }
    }

    pub fn read_header(&mut self) -> io::Result<MrtHeader> {
        let timestamp = self.reader.read_u32::<BigEndian>()?;
        let typ = self.reader.read_u16::<BigEndian>()?;
        let subtype = self.reader.read_u16::<BigEndian>()?;
        let length = self.reader.read_u32::<BigEndian>()?;

        let typ = match typ {
            12 => MrtType::TableDump(match subtype {
                1 => TableDump::AfiIpv4,
                2 => TableDump::AfiIpv6,
                _ => TableDump::Unknown(subtype),
            }),
            13 => MrtType::TableDumpV2(match subtype {
                1 => TableDumpV2::PeerIndex,
                2 => TableDumpV2::RibIpv4Unicast,
                4 => TableDumpV2::RibIpv6Unicast,
                _ => TableDumpV2::Unknown(subtype),
            }),
            _ => MrtType::Unknown(typ),
        };

        Ok(MrtHeader {
            timestamp,
            typ,
            length,
        })
    }

    pub fn skip_table(&mut self, header: &MrtHeader) -> io::Result<()> {
        read_exact(&mut self.reader, header.length as usize)?;
        Ok(())
    }

    pub fn read_afi(&mut self, subtype: TableDump) -> io::Result<Afi> {
        let is_ipv6 = match subtype {
            TableDump::AfiIpv4 => false,
            TableDump::AfiIpv6 => true,
            _ => unimplemented!("Only AFI_IPv4 and AFI_IPv6 subtypes are supported"),
        };

        let view_number = self.reader.read_u16::<BigEndian>()?;
        let sequence_number = self.reader.read_u16::<BigEndian>()?;
        let prefix_ip = read_ip_addr(&mut self.reader, is_ipv6)?;
        let prefix_length = self.reader.read_u8()?;
        let prefix = match prefix_ip {
            IpAddr::V4(ip) => IpNetwork::V4(Ipv4Network::from(ip, prefix_length).unwrap()),
            IpAddr::V6(ip) => IpNetwork::V6(Ipv6Network::from(ip, prefix_length).unwrap()),
        };
        let status = self.reader.read_u8()?;
        let originated_time = self.reader.read_u32::<BigEndian>()?;
        let peer_ip = read_ip_addr(&mut self.reader, is_ipv6)?;
        let peer_as = self.reader.read_u16::<BigEndian>()?;
        let attribute_length = self.reader.read_u16::<BigEndian>()?;
        let data = read_exact(&mut self.reader, attribute_length as usize)?;

        Ok(Afi {
            view_number,
            sequence_number,
            prefix,
            status,
            originated_time,
            peer_ip,
            peer_as,
            data,
        })
    }

    pub fn read_peer_index_table(&mut self) -> io::Result<PeerIndexTable> {
        let collector_bgp_id = self.reader.read_u32::<BigEndian>()?;

        let view_name_length = self.reader.read_u16::<BigEndian>()?;
        let view_name_buffer = read_exact(&mut self.reader, view_name_length as usize)?;
        let view_name = str::from_utf8(&view_name_buffer)
            .map(|x| x.to_string())
            .map_err(|_| io::Error::new(
                io::ErrorKind::InvalidData,
                "PeerIndexTable view name did not contain valid UTF-8"
            ))?;

        let peer_count = self.reader.read_u16::<BigEndian>()?;

        let mut peer_entries = Vec::with_capacity(peer_count as usize);
        for _ in 0..peer_count {
            peer_entries.push(PeerEntry::parse(&mut self.reader)?);
        }

        Ok(PeerIndexTable {
            collector_bgp_id,
            view_name,
            peer_entries,
        })
    }

    pub fn read_rib_entry(&mut self, typ: MrtType) -> io::Result<RibEntry> {
        let sequence_number = self.reader.read_u32::<BigEndian>()?;

        let prefix_length = self.reader.read_u8()?;
        let prefix_bytes = ((prefix_length + 7) / 8) as usize;
        let prefix_buffer = read_exact(&mut self.reader, prefix_bytes)?;

        let prefix = match typ {
            MrtType::TableDumpV2(subtype) => {
                match subtype {
                    TableDumpV2::RibIpv4Unicast => {
                        debug_assert!(prefix_length <= 32);
                        let mut parts: [u8; 4] = [0; 4];
                        parts[..prefix_bytes].copy_from_slice(prefix_buffer.as_slice());
                        let ip = Ipv4Addr::from(parts);
                        IpNetwork::V4(Ipv4Network::from(ip, prefix_length).unwrap())
                    },
                    TableDumpV2::RibIpv6Unicast => {
                        debug_assert!(prefix_length <= 128);
                        let mut parts: [u8; 16] = [0; 16];
                        parts[..prefix_bytes].copy_from_slice(prefix_buffer.as_slice());
                        let ip = Ipv6Addr::from(parts);
                        IpNetwork::V6(Ipv6Network::from(ip, prefix_length).unwrap())
                    },
                    _ => unimplemented!("TableDumpV2 {:?} subtype", subtype),
                }
            },
            _ => unimplemented!("{:?} MrtType", typ),
        };

        let entry_count = self.reader.read_u16::<BigEndian>()?;
        let mut sub_entries = Vec::with_capacity(entry_count as usize);
        for _ in 0..entry_count {
            sub_entries.push(RibSubEntry::parse(&mut self.reader)?);
        }

        Ok(RibEntry {
            sequence_number,
            prefix,
            sub_entries,
        })
    }
}

#[derive(Debug, Clone)]
pub enum TableDump {
    AfiIpv4,
    AfiIpv6,
    Unknown(u16),
}

#[derive(Debug, Clone)]
pub enum TableDumpV2 {
    PeerIndex,
    RibIpv4Unicast,
    RibIpv6Unicast,
    Unknown(u16),
}

#[derive(Debug, Clone)]
pub enum MrtType {
    TableDump(TableDump),
    TableDumpV2(TableDumpV2),
    Unknown(u16),
}

#[derive(Debug)]
pub struct MrtHeader {
    pub timestamp: u32,
    pub typ: MrtType,
    pub length: u32,
}

#[derive(Debug)]
pub struct PeerIndexTable {
    pub collector_bgp_id: u32,
    pub view_name: String,
    pub peer_entries: Vec<PeerEntry>,
}

#[derive(Debug)]
pub struct PeerEntry {
    pub peer_bgp_id: u32,
    pub ip_addr: IpAddr,
    pub asn: u32,
}

impl PeerEntry {
    fn parse<R: ReadBytesExt>(rdr: &mut R) -> io::Result<Self> {
        let type_ = rdr.read_u8()?;
        let is_ipv6 = ((type_) & 0x1) == 1;
        let is_asn_32bit = ((type_ >> 1) & 0x1) == 1;

        let peer_bgp_id = rdr.read_u32::<BigEndian>()?;
        let ip_addr = read_ip_addr(rdr, is_ipv6)?;
        let asn = if is_asn_32bit {
            rdr.read_u32::<BigEndian>()?
        } else {
            rdr.read_u16::<BigEndian>()? as u32
        };

        Ok(Self {
            peer_bgp_id,
            ip_addr,
            asn
        })
    }
}

#[derive(Debug)]
pub struct Afi {
    pub view_number: u16,
    pub sequence_number: u16,
    pub prefix: IpNetwork,
    pub status: u8,
    pub originated_time: u32,
    pub peer_ip: IpAddr,
    pub peer_as: u16,
    data: Vec<u8>,
}

impl Afi {
    pub fn get_bgp_attributes(&self) -> io::Result<Vec<bgp::Attribute>> {
        bgp::Attribute::parse_all(&self.data)
    }
}

#[derive(Debug)]
pub struct RibEntry {
    pub sequence_number: u32,
    pub prefix: IpNetwork,
    pub sub_entries: Vec<RibSubEntry>,
}

#[derive(Debug)]
pub struct RibSubEntry {
    pub peer_index: u16,
    pub originated_time: u32,
    data: Vec<u8>,
}

impl RibSubEntry {
    fn parse<R: ReadBytesExt>(rdr: &mut R) -> io::Result<RibSubEntry> {
        let peer_index = rdr.read_u16::<BigEndian>()?;
        let originated_time = rdr.read_u32::<BigEndian>()?;
        let attribute_length = rdr.read_u16::<BigEndian>()?;
        let data = read_exact(rdr, attribute_length as usize)?;

        Ok(RibSubEntry {
            peer_index,
            originated_time,
            data,
        })
    }

    pub fn get_bgp_attributes(&self) -> io::Result<Vec<bgp::Attribute>> {
        bgp::Attribute::parse_all(&self.data)
    }
}

#[inline]
fn read_exact<R: ReadBytesExt>(rdr: &mut R, length: usize) -> io::Result<Vec<u8>> {
    let mut buffer = vec![0; length as usize];
    rdr.read_exact(buffer.as_mut_slice())?;
    Ok(buffer)
}