extern crate byteorder;
extern crate ip_network;

use std::io::{self, Cursor};
use std::str;
use byteorder::{BigEndian, ReadBytesExt};
use std::net::{Ipv6Addr, Ipv4Addr, IpAddr};
use ip_network::{IpNetwork, Ipv4Network, Ipv6Network};

pub mod processor;

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
        let ts = self.reader.read_u32::<BigEndian>()?;
        let type_ = self.reader.read_u16::<BigEndian>()?;
        let subtype = self.reader.read_u16::<BigEndian>()?;
        let length = self.reader.read_u32::<BigEndian>()?;

        let typ = match type_ {
            12 => TableType::Dump(match subtype {
                1 => T1::AfiIpv4,
                2 => T1::AfiIpv6,
                _ => T1::Unknown(subtype),
            }),
            13 => TableType::DumpV2(match subtype {
                1 => T2::PeerIndex,
                2 => T2::RibIpv4Unicast,
                4 => T2::RibIpv6Unicast,
                _ => T2::Unknown(subtype),
            }),
            _ => TableType::Unknown(type_),
        };

        Ok(MrtHeader {
            ts,
            typ,
            data_len: length,
        })
    }

    pub fn skip_table(&mut self, header: &MrtHeader) -> io::Result<()> {
        read_exact(&mut self.reader, header.data_len as usize)?;
        Ok(())
    }

    pub fn read_peer_index_table(&mut self) -> io::Result<PeerIndexTable> {
        let collector_bgp_id = self.reader.read_u32::<BigEndian>()?;

        let view_name_length = self.reader.read_u16::<BigEndian>()?;
        let view_name_buffer = read_exact(&mut self.reader, view_name_length as usize)?;
        let view_name: String = str::from_utf8(&view_name_buffer).unwrap().into();

        let peer_count = self.reader.read_u16::<BigEndian>()?;

        let mut peer_entries = Vec::with_capacity(peer_count as usize);
        for _ in 0..peer_count {
            peer_entries.push(read_peer_entry(&mut self.reader)?);
        }

        Ok(PeerIndexTable {
            collector_bgp_id,
            view_name,
            peer_entries,
        })
    }

    pub fn read_rib_entry(&mut self, type_: TableType) -> io::Result<RibEntry> {
        let sequence_number = self.reader.read_u32::<BigEndian>()?;

        let prefix_length = self.reader.read_u8()?;
        let prefix_bytes = ((prefix_length + 7) / 8) as usize;
        let prefix_buffer = read_exact(&mut self.reader, prefix_bytes)?;

        let prefix = match type_ {
            TableType::DumpV2(subtype) => {
                match subtype {
                    T2::RibIpv4Unicast => {
                        debug_assert!(prefix_length <= 32);
                        let mut parts: [u8; 4] = [0; 4];
                        parts[..prefix_bytes].copy_from_slice(prefix_buffer.as_slice());
                        let ip = Ipv4Addr::from(parts);
                        IpNetwork::V4(Ipv4Network::from(ip, prefix_length).unwrap())
                    },
                    T2::RibIpv6Unicast => {
                        debug_assert!(prefix_length <= 128);
                        let mut parts: [u8; 16] = [0; 16];
                        parts[..prefix_bytes].copy_from_slice(prefix_buffer.as_slice());
                        let ip = Ipv6Addr::from(parts);
                        IpNetwork::V6(Ipv6Network::from(ip, prefix_length).unwrap())
                    },
                    _ => unimplemented!(),
                }
            },
            _ => unimplemented!(),
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
pub enum T1 {
    AfiIpv4,
    AfiIpv6,
    Unknown(u16),
}

#[derive(Debug, Clone)]
pub enum T2 {
    PeerIndex,
    RibIpv4Unicast,
    RibIpv6Unicast,
    Unknown(u16),
}

#[derive(Debug, Clone)]
pub enum TableType {
    Dump(T1),
    DumpV2(T2),
    Unknown(u16),
}

#[derive(Debug)]
pub struct MrtHeader {
    pub ts: u32,
    pub typ: TableType,
    pub data_len: u32,
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

fn read_peer_entry<R: ReadBytesExt>(rdr: &mut R) -> io::Result<PeerEntry> {
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

    Ok(PeerEntry {
        peer_bgp_id,
        ip_addr,
        asn
    })
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
    pub fn parse<R: ReadBytesExt>(rdr: &mut R) -> io::Result<RibSubEntry> {
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

    pub fn get_bgp_attributes(&self) -> Vec<BgpAttribute> {
        let mut cursor = Cursor::new(&self.data);
        let mut output = vec![];
        while cursor.position() < self.data.len() as u64 {
            output.push(BgpAttribute::parse(&mut cursor).unwrap());
        }
        output
    }
}

#[derive(Debug)]
pub enum BgpAttribute {
    AsPath(BgpAttributeAsPath),
    Unknown(u8),
}

impl BgpAttribute {
    pub fn parse<R: ReadBytesExt>(rdr: &mut R) -> io::Result<Self> {
        let flags = rdr.read_u8()?;
        let has_extra_length = (flags >> 4) & 0x1 == 1;
        let type_id = rdr.read_u8()?;

        let length = if has_extra_length {
            rdr.read_u16::<BigEndian>()?
        } else {
            rdr.read_u8()? as u16
        };

        let mut data = vec![0; length as usize];
        rdr.read_exact(data.as_mut_slice())?;

        Ok(match type_id {
            2 => BgpAttribute::AsPath(BgpAttributeAsPath {
                data,
            }),
            _ => BgpAttribute::Unknown(type_id),
        })
    }
}

#[derive(Debug)]
pub struct BgpAttributeAsPath {
    data: Vec<u8>,
}

impl BgpAttributeAsPath {
    pub fn get_path_segments(&self) -> Vec<BgpPathSegment> {
        let mut cursor = Cursor::new(&self.data);
        let mut output = vec![];
        while cursor.position() < self.data.len() as u64 {
            output.push(BgpPathSegment::parse(&mut cursor).unwrap());
        }
        output
    }
}

#[derive(Debug)]
pub struct BgpPathSegment {
    pub typ: BgpPathSegmentType,
    pub values: Vec<u32>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum BgpPathSegmentType {
    AsSet,
    AsSequence,
    AsConfedSequence,
    AsConfedSet,
    Unknown(u8),
}

impl BgpPathSegment {
    pub fn parse<R: ReadBytesExt>(rdr: &mut R) -> io::Result<Self> {
        let seg_type = rdr.read_u8()?;
        let typ = match seg_type {
            1 => BgpPathSegmentType::AsSet,
            2 => BgpPathSegmentType::AsSequence,
            3 => BgpPathSegmentType::AsConfedSequence,
            4 => BgpPathSegmentType::AsConfedSet,
            _ => BgpPathSegmentType::Unknown(seg_type),
        };

        let count = rdr.read_u8()?;

        let mut values = Vec::with_capacity(count as usize);
        for _ in 0..count {
            values.push(rdr.read_u32::<BigEndian>()?);
        }

        Ok(Self {
            typ,
            values,
        })
    }
}

#[inline]
fn read_exact<R: ReadBytesExt>(rdr: &mut R, length: usize) -> io::Result<Vec<u8>> {
    let mut buffer = vec![0; length as usize];
    rdr.read_exact(buffer.as_mut_slice())?;
    Ok(buffer)
}