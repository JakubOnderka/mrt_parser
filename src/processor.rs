use std::error::Error;
use RibEntry;
use bgp::{BgpAttribute, BgpPathSegmentType, BgpAttributeAsPath};

fn is_asn_bogus(input: u32) -> bool {
    input == 0 || (input >= 64_496 && input <= 131_071) || input >= 4_200_000_000 || input > 1_000_000
}

pub fn get_origin_as_from_bgp_attrbite_as_path(path: &BgpAttributeAsPath) -> Result<Vec<u32>, Box<Error>> {
    let path_segments = path.get_path_segments()?;
    debug_assert!(path_segments[0].typ == BgpPathSegmentType::AsSequence);

    for path_segment in path_segments.iter().rev() {
        match path_segment.typ {
            BgpPathSegmentType::AsSequence => {
                for value in path_segment.values.iter().rev() {
                    if !is_asn_bogus(*value) {
                        return Ok(vec![*value]);
                    }
                }
            },
            BgpPathSegmentType::AsSet => {
                return Ok(path_segment.values.iter()
                    .filter(|val| !is_asn_bogus(**val))
                    .cloned()
                    .collect());
            },
            _ => return Err(From::from(format!("Invalid/Legacy BGP Path Segment: {:?}", path_segment.typ))),
        }
    }

    Err(From::from("No origin"))
}

pub fn get_origin_as_from_rib_entry(input: &RibEntry) -> Result<Vec<u32>, Box<Error>> {
    let mut output = vec![];
    for sub_entry in &input.sub_entries {
        for attribute in sub_entry.get_bgp_attributes()? {
            if let BgpAttribute::AsPath(ref as_path) = attribute {
                output.append(&mut get_origin_as_from_bgp_attrbite_as_path(as_path)?)
            }
        }
    }

    output.sort_unstable();
    output.dedup();
    Ok(output)
}