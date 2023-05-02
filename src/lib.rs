use std::ffi::{c_char, c_uchar, CStr, CString};
use std::slice;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
#[repr(C)]
pub enum ParserError {
    InvalidAddress,
    InvalidType,
    InvalidValue,
    InvalidFormat,
}

#[derive(Debug)]
#[repr(C)]
pub struct OscValue {
    int: i32,
    float: [f32; 6],
    bool: bool,
    string: *const c_char,
}

impl Default for OscValue {
    fn default() -> OscValue {
        OscValue { int: 0, float: [0.0, 0.0, 0.0, 0.0, 0.0, 0.0], bool: false, string: std::ptr::null() }
    }
}

#[derive(Debug)]
#[repr(C)]
pub enum OscType {
    Int,
    Float,
    Bool,
    String,
    Vector2,
    Vector3,
    Vector4,
    Vector6,
}

#[repr(C)]
pub struct OscMessage {
    pub address: *const c_char,
    pub osc_type: OscType,
    pub value: OscValue,
}

fn extract_osc_address(buf: &[u8], ix: &mut usize) -> Result<String, ParserError> {
    // First, we wanna ensure the first char is a '/'
    if buf[0] != 47 {
        return Err(ParserError::InvalidAddress);
    }

    let mut address = String::new();

    /*
     * Patching OBO bug
     * ~ Sutekh
     */
    while *ix <= buf.len()-1 && buf[*ix] != 0 { // *ix >= buf.len() // Cheers sutekh!
        address.push(buf[*ix] as char);
        *ix += 1;
    }

    // Ensure we include the null terminator in the index
    *ix += 1;

    // Now round up to 4 bytes. If we're already on a 4 byte boundary, we don't need to do anything
    if *ix % 4 != 0 {
        *ix += 4 - (*ix % 4);
    }

    return Ok(address);
}

fn extract_osc_value(buf: &[u8], ix: &mut usize) -> Result<(OscType, OscValue), ParserError> {
    // First, we wanna ensure the first char is a ','
    if buf[*ix] != 44 {
        return Err(ParserError::InvalidType);
    }

    *ix += 1;

    // Read until we hit a null terminator
    let types: Vec<char> = buf[*ix..].iter().take_while(|&&c| c != 0).map(|&c| c as char).collect();
    *ix += types.len();

    // Pad with one null
    *ix += 1;

    // Round up to 4 bytes
    if *ix % 4 != 0 {
        *ix += 4 - (*ix % 4);
    }

    let mut value = OscValue {..Default::default()};

    // Now we convert this to an OscValue based on the type
    return match types[..] {
        ['i'] => {
            let mut bytes = [0; 4];
            bytes.copy_from_slice(&buf[*ix..*ix + 4]);
            value.int = i32::from_be_bytes(bytes);
            Ok((OscType::Int, value))
        }
        ['f'] => {
            let mut bytes = [0; 4];
            bytes.copy_from_slice(&buf[*ix..*ix + 4]);
            value.float[0] = f32::from_be_bytes(bytes);
            Ok((OscType::Float, value))
        }
        ['T'] => {
            value.bool = true;
            Ok((OscType::Bool, value))
        }
        ['F'] => {
            value.bool = false;
            Ok((OscType::Bool, value))
        }
        ['s'] => {
            let mut string = String::new();
            while buf[*ix] != 0 {
                string.push(buf[*ix] as char);
                *ix += 1;
            }
            *ix += 1;
            value.string = CString::new(string).unwrap().into_raw();
            Ok((OscType::String, value))
        }
        //TODO: Should probably write some logic to properly parse any amount of these once I figure out how to FFI a vec properly
        ['f', 'f'] => {
            let mut bytes = [0; 4];
            bytes.copy_from_slice(&buf[*ix..*ix + 4]);
            value.float[0] = f32::from_be_bytes(bytes);
            *ix += 4;
            bytes.copy_from_slice(&buf[*ix..*ix + 4]);
            value.float[1] = f32::from_be_bytes(bytes);
            *ix += 4;
            Ok((OscType::Vector2, value))
        }
        ['f', 'f', 'f'] => {
            let mut bytes = [0; 4];
            bytes.copy_from_slice(&buf[*ix..*ix + 4]);
            value.float[0] = f32::from_be_bytes(bytes);
            *ix += 4;
            bytes.copy_from_slice(&buf[*ix..*ix + 4]);
            value.float[1] = f32::from_be_bytes(bytes);
            *ix += 4;
            bytes.copy_from_slice(&buf[*ix..*ix + 4]);
            value.float[2] = f32::from_be_bytes(bytes);
            *ix += 4;
            Ok((OscType::Vector3, value))
        }
        ['f', 'f', 'f', 'f'] => {
            let mut bytes = [0; 4];
            bytes.copy_from_slice(&buf[*ix..*ix + 4]);
            value.float[0] = f32::from_be_bytes(bytes);
            *ix += 4;
            bytes.copy_from_slice(&buf[*ix..*ix + 4]);
            value.float[1] = f32::from_be_bytes(bytes);
            *ix += 4;
            bytes.copy_from_slice(&buf[*ix..*ix + 4]);
            value.float[2] = f32::from_be_bytes(bytes);
            *ix += 4;
            bytes.copy_from_slice(&buf[*ix..*ix + 4]);
            value.float[3] = f32::from_be_bytes(bytes);
            *ix += 4;
            Ok((OscType::Vector4, value))
        }
        ['f', 'f', 'f', 'f', 'f', 'f'] => {
            let mut bytes = [0; 4];
            bytes.copy_from_slice(&buf[*ix..*ix + 4]);
            value.float[0] = f32::from_be_bytes(bytes);
            *ix += 4;
            bytes.copy_from_slice(&buf[*ix..*ix + 4]);
            value.float[1] = f32::from_be_bytes(bytes);
            *ix += 4;
            bytes.copy_from_slice(&buf[*ix..*ix + 4]);
            value.float[2] = f32::from_be_bytes(bytes);
            *ix += 4;
            bytes.copy_from_slice(&buf[*ix..*ix + 4]);
            value.float[3] = f32::from_be_bytes(bytes);
            *ix += 4;
            bytes.copy_from_slice(&buf[*ix..*ix + 4]);
            value.float[4] = f32::from_be_bytes(bytes);
            *ix += 4;
            bytes.copy_from_slice(&buf[*ix..*ix + 4]);
            value.float[5] = f32::from_be_bytes(bytes);
            *ix += 4;
            Ok((OscType::Vector6, value))
        }
        _ => {
            Err(ParserError::InvalidType)
        }
    }
}

fn parse(buf: &[u8]) -> Result<OscMessage, ParserError> {
    // Ensure our buffer is at least 4 bytes long
    if buf.len() < 4 {  // Cheers sutekh!
        return Err(ParserError::InvalidFormat);
    }

    let mut index = 0;
    let address = extract_osc_address(&buf, &mut index);
    println!("Address: {:?}", address);

    // Ensure we still have data
    if index >= buf.len() { // Cheers sutekh!
        return Err(ParserError::InvalidFormat);
    }

    let value = extract_osc_value(&buf, &mut index);
    println!("Value: {:?}", value);

    return match (address, value) {
        (Ok(address), Ok(value)) => {
            Ok(OscMessage {
                address: CString::new(address).unwrap().into_raw(),
                osc_type: value.0,
                value: value.1
            })
        }
        (Err(e), _) => {
            Err(e)
        }
        (_, Err(e)) => {
            Err(e)
        }
    };
}

// Import a byte array from C# and parse it
#[no_mangle]
pub extern "C" fn parse_osc(buf: *const c_uchar, len: usize, msg: &mut OscMessage) -> bool {
    let buf = unsafe { slice::from_raw_parts(buf, len) };
    match parse(buf) {
        Ok(parsed_msg) => {
            *msg = parsed_msg; // update the provided OscMessage with the parsed message
            true
        }
        Err(_) => false,
    }
}

fn write_address(buf: &mut [u8], ix: &mut usize, address: &str) {
    let address_bytes = address.as_bytes();
    buf[*ix..*ix + address_bytes.len()].copy_from_slice(address_bytes);
    *ix += address_bytes.len();
    buf[*ix] = 0;
    *ix += 1;
    if *ix % 4 != 0 {
        buf[*ix..*ix + 4 - (*ix % 4)].copy_from_slice(&[0, 0, 0][..4 - (*ix % 4)]);
        *ix += 4 - (*ix % 4);
    }
}

#[no_mangle]
pub extern "C" fn create_osc_message(buf: *mut c_uchar, osc_template: &OscMessage) -> usize {
    let buf = unsafe { slice::from_raw_parts_mut(buf, 4096) };
    let address = unsafe { CStr::from_ptr(osc_template.address) }.to_str().unwrap();
    let mut ix = 0;
    write_address(buf, &mut ix, address);
    buf[ix] = 44; // ,
    ix += 1;
    match osc_template.osc_type {
        OscType::Int => {
            buf[ix] = 105; // i
            buf[ix+1..ix + 3].copy_from_slice(&[0, 0]);
            ix += 3;
            let bytes = osc_template.value.int.to_be_bytes();
            buf[ix..ix + 4].copy_from_slice(&bytes);
            ix += 4;
        }
        OscType::Float => {
            buf[ix] = 102; // f
            buf[ix+1..ix + 3].copy_from_slice(&[0, 0]);
            ix += 3;
            let bytes = osc_template.value.float[0].to_be_bytes();
            buf[ix..ix + 4].copy_from_slice(&bytes);
            ix += 4;
        }
        OscType::Bool => {
            buf[ix] = if osc_template.value.bool { 84 } else { 70 }; // T or F
            buf[ix + 1 ..ix + 3].copy_from_slice(&[0, 0]);
            ix += 3;
        }
        OscType::String => {
            println!("Not implemented yet!")
        }
        OscType::Vector2 => {
            buf[ix] = 102; // f
            buf[ix + 1] = 102;
            buf[ix + 2] = 0;
            ix += 3;
            let bytes = osc_template.value.float[0].to_be_bytes();
            buf[ix..ix + 4].copy_from_slice(&bytes);
            ix += 4;
            let bytes = osc_template.value.float[1].to_be_bytes();
            buf[ix..ix + 4].copy_from_slice(&bytes);
            ix += 4;
        }
        OscType::Vector3 => {
            buf[ix] = 102; // f
            buf[ix + 1] = 102;
            buf[ix + 2] = 102;
            buf[ix + 3..ix + 7].copy_from_slice(&[0, 0, 0, 0]);
            ix += 7;
            let bytes = osc_template.value.float[0].to_be_bytes();
            buf[ix..ix + 4].copy_from_slice(&bytes);
            ix += 4;
            let bytes = osc_template.value.float[1].to_be_bytes();
            buf[ix..ix + 4].copy_from_slice(&bytes);
            ix += 4;
            let bytes = osc_template.value.float[2].to_be_bytes();
            buf[ix..ix + 4].copy_from_slice(&bytes);
            ix += 4;
        }
        OscType::Vector4 => {
            buf[ix] = 102; // f
            buf[ix + 1] = 102;
            buf[ix + 2] = 102;
            buf[ix + 3] = 102;
            buf[ix + 4..ix + 7].copy_from_slice(&[0, 0, 0]);
            ix += 7;
            let bytes = osc_template.value.float[0].to_be_bytes();
            buf[ix..ix + 4].copy_from_slice(&bytes);
            ix += 4;
            let bytes = osc_template.value.float[1].to_be_bytes();
            buf[ix..ix + 4].copy_from_slice(&bytes);
            ix += 4;
            let bytes = osc_template.value.float[2].to_be_bytes();
            buf[ix..ix + 4].copy_from_slice(&bytes);
            ix += 4;
            let bytes = osc_template.value.float[3].to_be_bytes();
            buf[ix..ix + 4].copy_from_slice(&bytes);
            ix += 4;
        }
        OscType::Vector6 => {
            buf[ix] = 102; // f
            buf[ix + 1] = 102;
            buf[ix + 2] = 102;
            buf[ix + 3] = 102;
            buf[ix + 4] = 102;
            buf[ix + 5] = 102;
            buf[ix + 6..ix + 7].copy_from_slice(&[0]);
            ix += 7;
            let bytes = osc_template.value.float[0].to_be_bytes();
            buf[ix..ix + 4].copy_from_slice(&bytes);
            ix += 4;
            let bytes = osc_template.value.float[1].to_be_bytes();
            buf[ix..ix + 4].copy_from_slice(&bytes);
            ix += 4;
            let bytes = osc_template.value.float[2].to_be_bytes();
            buf[ix..ix + 4].copy_from_slice(&bytes);
            ix += 4;
            let bytes = osc_template.value.float[3].to_be_bytes();
            buf[ix..ix + 4].copy_from_slice(&bytes);
            ix += 4;
            let bytes = osc_template.value.float[4].to_be_bytes();
            buf[ix..ix + 4].copy_from_slice(&bytes);
            ix += 4;
            let bytes = osc_template.value.float[5].to_be_bytes();
            buf[ix..ix + 4].copy_from_slice(&bytes);
            ix += 4;
        }
    }

    ix
}

// Creates a bundle from an array of OscMessages
#[no_mangle]
pub extern "C" fn create_osc_bundle(buf: *mut c_uchar, messages: *const OscMessage, len: usize, messages_index: *mut usize) -> usize {
    // OSC bundles start with the 16 byte header consisting of "#bundle" (with null terminator) followed by a 64-bit big-endian timetag
    let buf = unsafe { slice::from_raw_parts_mut(buf, 4096) };
    let messages = unsafe { slice::from_raw_parts(messages, len) };
    let mut ix = 0;

    // Write the header
    buf[0..8].copy_from_slice(b"#bundle\0");
    ix += 8;

    // Write the current NTP time as the timetag
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap();

    // Ensure we don't overflow the 64-bit integer
    let time = (time.as_secs() as u64) << 32 | (time.subsec_nanos() as u64) << 32 >> 32;

    let bytes = time.to_be_bytes();
    buf[ix..ix + 8].copy_from_slice(&bytes);
    ix += 8;

    // Now we need to write the messages
    let mut message_ix = unsafe { *messages_index };
    for msg in messages.iter().skip(message_ix) {
        // We need to calculate the length of the string and pad it to a multiple of 4 to ensure alignment
        // then add another 4 bytes for the length of the message
        // If adding it would go over the buffer size, return
        // Use the existing function to write the message to the buffer
        let address = unsafe { CStr::from_ptr(msg.address).to_str() }.unwrap();
        let length = address.len() + 1;
        let padded_length = if length % 4 == 0 { length } else { length + 4 - (length % 4) };
        if ix + padded_length + 4 > 4096 {
            return ix;
        }

        let length = create_osc_message(unsafe { buf.as_mut_ptr().add(ix + 4) }, msg);
        // Write the length of the message to the buffer. Ensure we use 4 bytes
        let bytes: [u8; 4] = (length as u32).to_be_bytes();

        buf[ix..ix + 4].copy_from_slice(&bytes);
        ix += length + 4;

        // Update the message index after each iteration
        message_ix += 1;
    }

    // Update the messages_index pointer with the new message index
    unsafe { *messages_index = message_ix; }

    ix
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(test)]
    mod serialize {
        use super::*;

        #[test]
        fn serialize_osc_message() {
            let mut buf: [u8; 4096] = [0; 4096];
            let osc_message = OscMessage {
                address: CString::new("/test_message/meme").unwrap().into_raw(),
                osc_type: OscType::Bool,
                value: OscValue { bool: true, ..Default::default() },
            };

            let id = create_osc_message(buf.as_mut_ptr(), &osc_message);
            match parse(&buf) {
                Ok(message) => {
                    // Convert the address string ptr to a literal string and compare
                    let address = unsafe { CStr::from_ptr(message.address) }.to_str().unwrap();
                    assert_eq!(address, "/test_message/meme", "Address was resolved incorrectly.");
                    assert_eq!(message.value.bool, true, "Value was resolved incorrectly.");
                }
                Err(_) => assert!(false, "Failed to parse message."),
            }
        }

        #[test]
        fn serialize_osc_bundle() {
            // Create an array consisting of three messages
            let osc_message1 = OscMessage {
                address: CString::new("/test_message/meme").unwrap().into_raw(),
                osc_type: OscType::Int,
                value: OscValue { int: 42, ..Default::default() },
            };
            let osc_message2 = OscMessage {
                address: CString::new("/test_message/meme2").unwrap().into_raw(),
                osc_type: OscType::Float,
                value: OscValue { float: [3.14, 0.0, 0.0, 0.0, 0.0, 0.0], ..Default::default() },
            };
            let osc_message3 = OscMessage {
                address: CString::new("/test_message/meme3").unwrap().into_raw(),
                osc_type: OscType::Vector3,
                value: OscValue { float: [1.0, 2.0, 3.0, 0.0, 0.0, 0.0], ..Default::default() },
            };
            let osc_message4 = OscMessage {
                address: CString::new("/test_message/meme3").unwrap().into_raw(),
                osc_type: OscType::Bool,
                value: OscValue { bool: true, ..Default::default() },
            };
            let messages = [osc_message1, osc_message2, osc_message3, osc_message4];

            let mut buf: [u8; 4096] = [0; 4096];
            let mut index: usize = 0;
            let len1 = create_osc_bundle(buf.as_mut_ptr(), messages.as_ptr(), messages.len(), &mut index);

            index = 1;
            let len2 = create_osc_bundle(buf.as_mut_ptr(), messages.as_ptr(), messages.len(), &mut index);

            assert!(len2 < len1, "Length of bundle was not calculated correctly. Second bundle should be smaller than the first.");
        }
    }

    #[cfg(test)]
    mod parse {
        use super::*;

        #[test]
        fn parse_bool() {
            let buf = [47, 116, 101, 115, 116, 0, 0, 0, 44, 84, 0, 0];
            match parse(&buf) {
                Ok(message) => {
                    // Convert the address string ptr to a literal string and compare
                    let address = unsafe { CStr::from_ptr(message.address) }.to_str().unwrap();
                    assert_eq!(address, "/test", "Address was resolved incorrectly.");
                    assert_eq!(message.value.bool, true, "Value was resolved incorrectly.");
                }
                Err(e) => {
                    panic!("Error: {:?}", e);
                }
            }
        }

        #[test]
        fn parse_int() {
            let buf = [47, 116, 101, 115, 116, 0, 0, 0, 44, 105, 0, 0, 0, 0, 0, 9];
            match parse(&buf) {
                Ok(message) => {
                    // Convert the address string ptr to a literal string and compare
                    let address = unsafe { CStr::from_ptr(message.address) }.to_str().unwrap();
                    assert_eq!(address, "/test", "Address was resolved incorrectly.");
                    assert_eq!(message.value.int, 9, "Value was resolved incorrectly.");
                }
                Err(e) => {
                    panic!("Error: {:?}", e);
                }
            }
        }

        #[test]
        fn parse_float() {
            // Get 69.42 as a big endian array of bytes
            let bytes = 69.42_f32.to_be_bytes();
            let buf = [47, 116, 101, 115, 116, 0, 0, 0, 44, 102, 0, 0];

            // Concatenate the two arrays
            let mut recv_bytes = [0; 16];
            recv_bytes[..12].copy_from_slice(&buf);
            recv_bytes[12..].copy_from_slice(&bytes);

            match parse(&recv_bytes) {
                Ok(message) => {
                    // Convert the address string ptr to a literal string and compare
                    let address = unsafe { CStr::from_ptr(message.address) }.to_str().unwrap();
                    assert_eq!(address, "/test", "Address was resolved incorrectly.");
                    assert_eq!(message.value.float[0], 69.42, "Value was resolved incorrectly.");
                }
                Err(e) => {
                    panic!("Error: {:?}", e);
                }
            }
        }

        #[test]
        fn parse_string() {
            let buf = [47, 116, 101, 115, 116, 0, 0, 0, 44, 115, 0, 0, 104, 101, 108, 108, 111, 0, 0, 0];
            match parse(&buf) {
                Ok(message) => {
                    // Convert the address string ptr to a literal string and compare
                    let address = unsafe { CStr::from_ptr(message.address) }.to_str().unwrap();
                    assert_eq!(address, "/test", "Address was resolved incorrectly.");
                    // Convert the string ptr to a literal string and compare
                    let string = unsafe { CStr::from_ptr(message.value.string) }.to_str().unwrap();
                    assert_eq!(string, "hello", "Value was resolved incorrectly.");
                }
                Err(e) => {
                    panic!("Error: {:?}", e);
                }
            }
        }

        #[test]
        fn parse_vector2() {
            // Get [1.0, 2.0] as a big endian array of bytes. Should be 8 bytes long.
            let bytes = [1.0_f32, 2.0_f32].iter().fold([0; 8], |mut acc, &x| {
                acc[..4].copy_from_slice(&x.to_be_bytes());
                acc.rotate_left(4);
                acc
            });
            let buf = [47, 116, 101, 115, 116, 0, 0, 0, 44, 102, 102, 0];

            // Concatenate the two arrays
            let mut recv_bytes = [0; 20];
            recv_bytes[..12].copy_from_slice(&buf);
            recv_bytes[12..].copy_from_slice(&bytes);

            match parse(&recv_bytes) {
                Ok(message) => {
                    // Convert the address string ptr to a literal string and compare
                    let address = unsafe { CStr::from_ptr(message.address) }.to_str().unwrap();
                    assert_eq!(address, "/test", "Address was resolved incorrectly.");
                    assert_eq!(message.value.float[..2], [1.0, 2.0], "Value was resolved incorrectly.");
                }
                Err(e) => {
                    panic!("Error: {:?}", e);
                }
            }
        }

        #[test]
        fn parse_vector3() {
            // Get [1.0, 2.0, 3.0] as a big endian array of bytes. Should be 12 bytes long.
            let bytes = [1.0_f32, 2.0_f32, 3.0_f32].iter().fold([0; 12], |mut acc, &x| {
                acc[..4].copy_from_slice(&x.to_be_bytes());
                acc.rotate_left(4);
                acc
            });
            let buf = [47, 116, 101, 115, 116, 0, 0, 0, 44, 102, 102, 102, 0, 0, 0, 0];

            // Concatenate the two arrays
            let mut recv_bytes = [0; 28];
            recv_bytes[..16].copy_from_slice(&buf);
            recv_bytes[16..].copy_from_slice(&bytes);

            match parse(&recv_bytes) {
                Ok(message) => {
                    // Convert the address string ptr to a literal string and compare
                    let address = unsafe { CStr::from_ptr(message.address) }.to_str().unwrap();
                    assert_eq!(address, "/test", "Address was resolved incorrectly.");
                    assert_eq!(message.value.float[..3], [1.0, 2.0, 3.0], "Value was resolved incorrectly.");
                }
                Err(e) => {
                    panic!("Error: {:?}", e);
                }
            }
        }

        #[test]
        fn parse_vector4() {
            // Get [1.0, 2.0, 3.0, 4.0] as a big endian array of bytes. Should be 16 bytes long.
            let bytes = [1.0_f32, 2.0_f32, 3.0_f32, 4.0_f32].iter().fold([0; 16], |mut acc, &x| {
                acc[..4].copy_from_slice(&x.to_be_bytes());
                acc.rotate_left(4);
                acc
            });
            let buf = [47, 116, 101, 115, 116, 0, 0, 0, 44, 102, 102, 102, 102, 0, 0, 0];

            // Concatenate the two arrays
            let mut recv_bytes = [0; 32];
            recv_bytes[..16].copy_from_slice(&buf);
            recv_bytes[16..].copy_from_slice(&bytes);

            match parse(&recv_bytes) {
                Ok(message) => {
                    // Convert the address string ptr to a literal string and compare
                    let address = unsafe { CStr::from_ptr(message.address) }.to_str().unwrap();
                    assert_eq!(address, "/test", "Address was resolved incorrectly.");
                    assert_eq!(message.value.float[..4], [1.0, 2.0, 3.0, 4.0], "Value was resolved incorrectly.");
                }
                Err(e) => {
                    panic!("Error: {:?}", e);
                }
            }
        }

        #[test]
        fn parse_vector6() {
            // Get [1.0, 2.0, 3.0, 4.0, 5.0, 6.0] as a big endian array of bytes. Should be 24 bytes long.
            let bytes = [1.0_f32, 2.0_f32, 3.0_f32, 4.0_f32, 5.0_f32, 6.0_f32].iter().fold([0; 24], |mut acc, &x| {
                acc[..4].copy_from_slice(&x.to_be_bytes());
                acc.rotate_left(4);
                acc
            });
            let buf = [47, 116, 101, 115, 116, 0, 0, 0, 44, 102, 102, 102, 102, 102, 102, 0];

            // Concatenate the two arrays
            let mut recv_bytes = [0; 40];
            recv_bytes[..16].copy_from_slice(&buf);
            recv_bytes[16..].copy_from_slice(&bytes);

            match parse(&recv_bytes) {
                Ok(message) => {
                    // Convert the address string ptr to a literal string and compare
                    let address = unsafe { CStr::from_ptr(message.address) }.to_str().unwrap();
                    assert_eq!(address, "/test", "Address was resolved incorrectly.");
                    assert_eq!(message.value.float[..6], [1.0, 2.0, 3.0, 4.0, 5.0, 6.0], "Value was resolved incorrectly.");
                }
                Err(e) => {
                    panic!("Error: {:?}", e);
                }
            }
        }
    }
}
