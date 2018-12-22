use std::error::Error;
use crate::bgp::{Attribute, AttributeAsPath, PathSegmentType};
use crate::{Afi, RibEntry};

fn is_asn_bogus(input: u32) -> bool {
    input == 0 || (input >= 64_496 && input <= 131_071) || input >= 4_200_000_000
        || input > 1_000_000
}

pub fn get_origin_as_from_bgp_attribute_as_path(
    path: &AttributeAsPath,
    is_asn_32bit: bool,
) -> Result<Vec<u32>, Box<Error>> {
    let path_segments = path.get_path_segments(is_asn_32bit)?;
    debug_assert!(path_segments[0].typ == PathSegmentType::AsSequence);

    for path_segment in path_segments.iter().rev() {
        match path_segment.typ {
            PathSegmentType::AsSequence => {
                for value in path_segment.values.iter().rev() {
                    if !is_asn_bogus(*value) {
                        return Ok(vec![*value]);
                    }
                }
            }
            PathSegmentType::AsSet => {
                return Ok(path_segment
                    .values
                    .iter()
                    .filter(|val| !is_asn_bogus(**val))
                    .cloned()
                    .collect());
            }
            _ => {
                return Err(From::from(format!(
                    "Invalid/Legacy BGP Path Segment: {:?}",
                    path_segment.typ
                )))
            }
        }
    }

    Err(From::from("No origin"))
}

pub fn get_origin_as_from_rib_entry(input: &RibEntry) -> Result<Vec<u32>, Box<Error>> {
    let mut output = vec![];
    for sub_entry in &input.sub_entries {
        for attribute in sub_entry.get_bgp_attributes()? {
            if let Attribute::AsPath(ref as_path) = attribute {
                output.append(&mut get_origin_as_from_bgp_attribute_as_path(
                    as_path,
                    true,
                )?)
            }
        }
    }

    output.sort_unstable();
    output.dedup();
    Ok(output)
}

pub fn get_origin_as_from_afi(afi: &Afi) -> Result<Vec<u32>, Box<Error>> {
    let mut output = vec![];
    for attribute in afi.get_bgp_attributes()? {
        if let Attribute::AsPath(ref as_path) = attribute {
            output.append(&mut get_origin_as_from_bgp_attribute_as_path(
                as_path,
                false,
            )?)
        }
    }

    output.sort_unstable();
    output.dedup();
    Ok(output)
}
