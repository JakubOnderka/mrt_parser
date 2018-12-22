use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str;
use byteorder::{BigEndian, ReadBytesExt};
use ip_network::{IpNetwork, Ipv4Network, Ipv6Network};

pub mod bgp;
pub mod processor;

pub trait Message<M> {
    fn parse<R: ReadBytesExt>(reader: &mut R, header: &MrtHeader) -> io::Result<M>;
    fn can_parse(typ: MrtType) -> bool;
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum TableDump {
    AfiIpv4,
    AfiIpv6,
    Unknown(u16),
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum TableDumpV2 {
    PeerIndex,
    RibIpv4Unicast,
    RibIpv6Unicast,
    Unknown(u16),
}

#[derive(Debug, Copy, Clone, PartialEq)]
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

pub struct Parser<R: ReadBytesExt> {
    reader: R,
}

impl<R: ReadBytesExt> Parser<R> {
    pub fn new(reader: R) -> Self {
        Self { reader }
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

    pub fn skip_message(&mut self, header: &MrtHeader) -> io::Result<()> {
        read_exact(&mut self.reader, header.length as usize)?;
        Ok(())
    }

    pub fn read_message<M: Message<M>>(&mut self, header: &MrtHeader) -> io::Result<M> {
        if !M::can_parse(header.typ) {
            panic!("This parser cannot parse {:?}", header.typ);
        }

        M::parse(&mut self.reader, header)
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

impl Message<Afi> for Afi {
    fn parse<R: ReadBytesExt>(reader: &mut R, header: &MrtHeader) -> io::Result<Self> {
        let is_ipv6 = match header.typ {
            MrtType::TableDump(subtype) => match subtype {
                TableDump::AfiIpv4 => false,
                TableDump::AfiIpv6 => true,
                _ => panic!("Only AFI_IPv4 and AFI_IPv6 subtypes are supported"),
            },
            _ => panic!("Only TableDump types is supported"),
        };

        let view_number = reader.read_u16::<BigEndian>()?;
        let sequence_number = reader.read_u16::<BigEndian>()?;
        let prefix_ip = read_ip_addr(reader, is_ipv6)?;
        let prefix_length = reader.read_u8()?;
        let prefix = IpNetwork::from(prefix_ip, prefix_length).unwrap();
        let status = reader.read_u8()?;
        let originated_time = reader.read_u32::<BigEndian>()?;
        let peer_ip = read_ip_addr(reader, is_ipv6)?;
        let peer_as = reader.read_u16::<BigEndian>()?;
        let attribute_length = reader.read_u16::<BigEndian>()?;
        let data = read_exact(reader, attribute_length as usize)?;

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

    fn can_parse(typ: MrtType) -> bool {
        typ == MrtType::TableDump(TableDump::AfiIpv4)
            || typ == MrtType::TableDump(TableDump::AfiIpv6)
    }
}

impl Afi {
    pub fn get_bgp_attributes(&self) -> io::Result<Vec<bgp::Attribute>> {
        bgp::Attribute::parse_all(&self.data)
    }
}

#[derive(Debug)]
pub struct PeerIndexTable {
    pub collector_bgp_id: u32,
    pub view_name: String,
    pub peer_entries: Vec<PeerEntry>,
}

impl Message<PeerIndexTable> for PeerIndexTable {
    fn parse<R: ReadBytesExt>(reader: &mut R, _: &MrtHeader) -> io::Result<Self> {
        let collector_bgp_id = reader.read_u32::<BigEndian>()?;

        let view_name_length = reader.read_u16::<BigEndian>()?;
        let view_name_buffer = read_exact(reader, view_name_length as usize)?;
        let view_name = str::from_utf8(&view_name_buffer)
            .map(|x| x.to_string())
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "PeerIndexTable view name did not contain valid UTF-8",
                )
            })?;

        let peer_count = reader.read_u16::<BigEndian>()?;

        let mut peer_entries = Vec::with_capacity(peer_count as usize);
        for _ in 0..peer_count {
            peer_entries.push(PeerEntry::parse(reader)?);
        }

        Ok(PeerIndexTable {
            collector_bgp_id,
            view_name,
            peer_entries,
        })
    }

    fn can_parse(typ: MrtType) -> bool {
        typ == MrtType::TableDumpV2(TableDumpV2::PeerIndex)
    }
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
            asn,
        })
    }
}

#[derive(Debug)]
pub struct RibEntry {
    pub sequence_number: u32,
    pub prefix: IpNetwork,
    pub sub_entries: Vec<RibSubEntry>,
}

impl Message<RibEntry> for RibEntry {
    fn parse<R: ReadBytesExt>(reader: &mut R, header: &MrtHeader) -> io::Result<Self> {
        let sequence_number = reader.read_u32::<BigEndian>()?;

        let prefix_length = reader.read_u8()?;
        let prefix_bytes = ((prefix_length + 7) / 8) as usize;
        let prefix_buffer = read_exact(reader, prefix_bytes)?;

        let prefix = match header.typ {
            MrtType::TableDumpV2(subtype) => match subtype {
                TableDumpV2::RibIpv4Unicast => {
                    debug_assert!(prefix_length <= 32);
                    let mut parts: [u8; 4] = [0; 4];
                    parts[..prefix_bytes].copy_from_slice(prefix_buffer.as_slice());
                    let ip = Ipv4Addr::from(parts);
                    IpNetwork::V4(Ipv4Network::from(ip, prefix_length).unwrap())
                }
                TableDumpV2::RibIpv6Unicast => {
                    debug_assert!(prefix_length <= 128);
                    let mut parts: [u8; 16] = [0; 16];
                    parts[..prefix_bytes].copy_from_slice(prefix_buffer.as_slice());
                    let ip = Ipv6Addr::from(parts);
                    IpNetwork::V6(Ipv6Network::from(ip, prefix_length).unwrap())
                }
                _ => panic!("This parser cannot parse TableDumpV2 {:?} subtype", subtype),
            },
            _ => panic!("This parser cannot parse {:?} type", header.typ),
        };

        let entry_count = reader.read_u16::<BigEndian>()?;
        let mut sub_entries = Vec::with_capacity(entry_count as usize);
        for _ in 0..entry_count {
            sub_entries.push(RibSubEntry::parse(reader)?);
        }

        Ok(RibEntry {
            sequence_number,
            prefix,
            sub_entries,
        })
    }

    fn can_parse(typ: MrtType) -> bool {
        typ == MrtType::TableDumpV2(TableDumpV2::RibIpv4Unicast)
            || typ == MrtType::TableDumpV2(TableDumpV2::RibIpv6Unicast)
    }
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

fn read_ip_addr<R: ReadBytesExt>(rdr: &mut R, is_ipv6: bool) -> io::Result<IpAddr> {
    if is_ipv6 {
        let mut buffer = [0; 16];
        rdr.read_exact(&mut buffer)?;
        Ok(IpAddr::V6(Ipv6Addr::from(buffer)))
    } else {
        Ok(IpAddr::V4(Ipv4Addr::from(rdr.read_u32::<BigEndian>()?)))
    }
}

#[inline]
fn read_exact<R: ReadBytesExt>(rdr: &mut R, length: usize) -> io::Result<Vec<u8>> {
    let mut buffer = vec![0; length as usize];
    rdr.read_exact(buffer.as_mut_slice())?;
    Ok(buffer)
}
