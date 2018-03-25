use std::io::{self, Cursor};
use byteorder::{BigEndian, ReadBytesExt};
use read_exact;

#[derive(Debug)]
pub enum BgpAttribute {
    AsPath(BgpAttributeAsPath),
    Unknown(u8),
}

impl BgpAttribute {
    pub fn parse_all(input: &[u8]) -> io::Result<Vec<BgpAttribute>> {
        let mut cursor = Cursor::new(input);
        let mut output = vec![];
        while cursor.position() < input.len() as u64 {
            output.push(BgpAttribute::parse(&mut cursor)?);
        }
        Ok(output)
    }

    pub fn parse<R: ReadBytesExt>(rdr: &mut R) -> io::Result<Self> {
        let flags = rdr.read_u8()?;
        let has_extra_length = (flags >> 4) & 0x1 == 1;
        let type_id = rdr.read_u8()?;

        let length = if has_extra_length {
            rdr.read_u16::<BigEndian>()?
        } else {
            rdr.read_u8()? as u16
        };

        let data = read_exact(rdr, length as usize)?;

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
    pub fn get_path_segments(&self) -> io::Result<Vec<BgpPathSegment>> {
        let mut cursor = Cursor::new(&self.data);
        let mut output = vec![];
        while cursor.position() < self.data.len() as u64 {
            output.push(BgpPathSegment::parse(&mut cursor)?);
        }
        Ok(output)
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