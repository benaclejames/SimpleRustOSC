use std::ffi::{c_char, c_uchar, CStr, CString};
use std::ptr::null;
use std::slice;
use std::time::{SystemTime, UNIX_EPOCH};


macro_rules! println {
    ($($arg:tt)*) => ({
        #[cfg(debug_assertions)]
        std::println!($($arg)*);
    })
}

#[derive(Debug)]
#[repr(C)]
pub enum ParserError {
    InvalidAddress,
    InvalidType,
    InvalidValue,
    InvalidFormat,
}

impl Default for OscValue {
    fn default() -> OscValue {
        OscValue { osc_type: OscType::Null, int: 0, float: 0.0, bool: false, string: std::ptr::null() }
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
#[repr(C)]
pub enum OscType {
    Null,
    Int,
    Float,
    Bool,
    String,
    ArrayBegin,
    ArrayEnd
}

#[derive(Debug)]
#[repr(C)]
pub struct OscValue {
    osc_type: OscType,
    int: i32,
    float: f32,
    bool: bool,
    string: *const c_char,
}

#[repr(C)]
pub struct OscMessage {
    pub address: *const c_char,
    pub value_length: i32,
    pub value: *const OscValue
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
    while *ix <= buf.len()-1 && buf[*ix] != 0 {
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

fn extract_osc_values(buf: &[u8], ix: &mut usize) -> Result<Vec<OscValue>, ParserError> {
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

    // for each type
    let mut values = Vec::new();
    for t in types {
        let mut value = OscValue { ..Default::default() };

        // Now we convert this to an OscValue based on the type
        match t {
            'i' => {
                let mut bytes = [0; 4];
                bytes.copy_from_slice(&buf[*ix..*ix + 4]);
                value.int = i32::from_be_bytes(bytes);
                value.osc_type = OscType::Int;
                *ix += 4;
            }
            'f' => {
                let mut bytes = [0; 4];
                bytes.copy_from_slice(&buf[*ix..*ix + 4]);
                value.float = f32::from_be_bytes(bytes);
                value.osc_type = OscType::Float;
                *ix += 4;
            }
            'T' => {
                value.bool = true;
                value.osc_type = OscType::Bool;
            }
            'F' => {
                value.bool = false;
                value.osc_type = OscType::Bool;
            }
            's' => {
                let mut string = String::new();
                while buf[*ix] != 0 {
                    string.push(buf[*ix] as char);
                    *ix += 1;
                }
                *ix += 1;
                value.string = CString::new(string).unwrap().into_raw();
                value.osc_type = OscType::String;

            }
            '[' => {
                value.osc_type = OscType::ArrayBegin;
            }
            ']' => {
                value.osc_type = OscType::ArrayEnd;
            }
            _ => {
                continue;
            }
        }

        if *ix % 4 != 0 {
            *ix += 4 - (*ix % 4);
        }

        values.push(value);
    }

    Ok(values)
}

fn parse(buf: &[u8], index: &mut usize) -> Result<OscMessage, ParserError> {
    // Ensure our buffer is at least 4 bytes long
    if buf.len() < 4 {  // Cheers sutekh!
        return Err(ParserError::InvalidFormat);
    }

    let Ok(address) = extract_osc_address(&buf, index) else {
        return Err(ParserError::InvalidAddress);
    };
    println!("Address: {:?}", address);

    // Ensure we still have data
    if index >= &mut buf.len() { // Cheers sutekh!
        return Err(ParserError::InvalidFormat);
    }

    let Ok(value) = extract_osc_values(&buf, index) else {
        return Err(ParserError::InvalidValue);
    };
    println!("Value: {:?}", value);

    if value.is_empty() {
        return Err(ParserError::InvalidValue);
    }

    Ok(OscMessage {
        address: CString::new(address).unwrap().into_raw(),
        value_length: value.len() as i32,
        value: Box::into_raw(value.into_boxed_slice()) as *const OscValue,
    })

}

// Import a byte array from C# and parse it
#[no_mangle]
pub extern "C" fn parse_osc(buf: *const c_uchar, len: usize, index: &mut i32) -> *const OscMessage {
    let buf = unsafe { slice::from_raw_parts(buf, len) };
    let size: &mut usize = &mut (*index as usize);
    match parse(buf, size) {
        Ok(parsed_msg) => {
            *index += *size as i32;
            let boxed_message = Box::new(parsed_msg);
            let raw_ptr: *const OscMessage = Box::into_raw(boxed_message);

            raw_ptr
        }
        Err(_) => null(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn free_osc_message(ptr: *const OscMessage) {
    if ptr.is_null() {
        return;
    }

    let message = Box::from_raw(ptr as *mut OscMessage);
    let address = CString::from_raw(message.address as *mut c_char);
    let values = Box::from_raw(message.value as *mut OscValue);
    // Should defo be freeing strings from the values array here too, but oh well. VRChat doesn't send em anyways
    drop(address);
    drop(values);
    drop(message);
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
    let values = unsafe { slice::from_raw_parts(osc_template.value, osc_template.value_length as usize) };
    let mut ix = 0;
    write_address(buf, &mut ix, address);
    buf[ix] = 44; // ,
    ix += 1;

    for i in 0..osc_template.value_length {
        let value = &values[i as usize];

        let type_tag = match value.osc_type {
            OscType::Int => 'i', // i
            OscType::Float =>  'f', // f
            OscType::Bool => {if value.bool { 'T' } else { 'F' }}, // T or F
            OscType::ArrayBegin => '[',
            OscType::ArrayEnd => ']',
            _ => '\0',
        } as c_uchar;
        buf[ix] = type_tag;
        ix += 1;
    }

    // Add a null
    buf[ix] = 0;
    ix += 1;
    // Quanitze to 4 bytes
    if ix % 4 != 0 {
        buf[ix..ix + 4 - (ix % 4)].copy_from_slice(&[0, 0, 0][..4 - (ix % 4)]);
        ix += 4 - (ix % 4);
    }

    for i in 0..osc_template.value_length {
        let value = &values[i as usize];

        match value.osc_type {
            OscType::Int => {
                let bytes = value.int.to_be_bytes();
                buf[ix..ix + 4].copy_from_slice(&bytes);
                ix += 4;
            }
            OscType::Float => {
                let bytes = value.float.to_be_bytes();
                buf[ix..ix + 4].copy_from_slice(&bytes);
                ix += 4;
            }
            _ => {}
        }
    }

    ix
}

// Creates a bundle from an array of OscMessages
#[no_mangle]
pub extern "C" fn create_osc_bundle(buf: *mut c_uchar, messages: *const OscMessage, len: i32, messages_index: &mut i32) -> i32 {
    // OSC bundles start with the 16 byte header consisting of "#bundle" (with null terminator) followed by a 64-bit big-endian timetag
    let buf = unsafe { slice::from_raw_parts_mut(buf, 4096) };
    let messages = unsafe { slice::from_raw_parts(messages, len as usize) };
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
    let mut temp_buffer: [c_uchar; 4096] = [0; 4096];
    for msg in messages.iter().skip(*messages_index as usize) {
        // We need to calculate the length of the string and pad it to a multiple of 4 to ensure alignment
        // then add another 4 bytes for the length of the message
        // If adding it would go over the buffer size, return
        // Use the existing function to write the message to the buffer

        //let length = create_osc_message(unsafe { buf.as_mut_ptr().add(ix + 4) }, msg);
        let length = create_osc_message(temp_buffer.as_mut_ptr(), msg);
        if length + ix >= 4096 {
            break;
        }

        // Write the length of the message to the buffer. Ensure we use 4 bytes
        let bytes: [u8; 4] = (length as i32).to_be_bytes();

        buf[ix..ix + 4].copy_from_slice(&bytes);
        ix += 4;

        buf[ix..ix + length].copy_from_slice(&temp_buffer[0..length]);
        ix += length;

        // Update the message index after each iteration
        *messages_index += 1;
    }

    ix as i32
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
            let value = OscValue { osc_type: OscType::Bool, bool: true, ..Default::default() };
            let osc_message = OscMessage {
                address: CString::new("/test_message/meme").unwrap().into_raw(),
                value_length: 1,
                value: Box::into_raw(vec!(value).into_boxed_slice()) as *const OscValue
            };

            let index = create_osc_message(buf.as_mut_ptr(), &osc_message);
            assert_eq!(index, 24, "Incorrect index returned.");
            let mut parse_index = 0;
            match parse(&buf, &mut parse_index) {
                Ok(message) => {
                    // Convert the address string ptr to a literal string and compare
                    let address = unsafe { CStr::from_ptr(message.address) }.to_str().unwrap();
                    assert_eq!(parse_index, 24, "Incorrect parse index returned.");
                    assert_eq!(address, "/test_message/meme", "Address was resolved incorrectly.");
                    assert_eq!(message.value_length, 1, "Value length was resolved incorrectly.");
                    let values = unsafe { slice::from_raw_parts(message.value, message.value_length as usize) };
                    assert_eq!(values[0].osc_type, OscType::Bool, "Value was resolved incorrectly.");
                    assert_eq!(values[0].bool, true, "Value was resolved incorrectly.");
                }
                Err(_) => assert!(false, "Failed to parse message."),
            }
        }

        #[test]
        fn serialize_message_multiple_values() {
            let mut buf: [u8; 4096] = [0; 4096];
            let value1 = OscValue { osc_type: OscType::Bool, bool: true, ..Default::default() };
            let value2 = OscValue { osc_type: OscType::Int, int: 69, ..Default::default() };
            let value3 = OscValue { osc_type: OscType::Float, float: 69.42, ..Default::default() };
            let osc_message = OscMessage {
                address: CString::new("/test_message/meme").unwrap().into_raw(),
                value_length: 3,
                value: Box::into_raw(vec![value1, value2, value3].into_boxed_slice()) as *const OscValue,
            };

            let index = create_osc_message(buf.as_mut_ptr(), &osc_message);
            assert_eq!(index, 36, "Incorrect index returned.");
            let mut parse_index = 0;
            match parse(&buf, &mut parse_index) {
                Ok(message) => {
                    // Convert the address string ptr to a literal string and compare
                    let address = unsafe { CStr::from_ptr(message.address) }.to_str().unwrap();
                    assert_eq!(parse_index, 36, "Incorrect parse index returned.");
                    assert_eq!(address, "/test_message/meme", "Address was resolved incorrectly.");
                    assert_eq!(message.value_length, 3, "Value length was resolved incorrectly.");
                    let value = unsafe { slice::from_raw_parts(message.value, message.value_length as usize) };
                    assert_eq!(value[0].osc_type, OscType::Bool, "Value was resolved incorrectly.");
                    assert_eq!(value[0].bool, true, "Value was resolved incorrectly.");
                    assert_eq!(value[1].osc_type, OscType::Int, "Value was resolved incorrectly.");
                    assert_eq!(value[1].int, 69, "Value was resolved incorrectly.");
                    assert_eq!(value[2].osc_type, OscType::Float, "Value was resolved incorrectly.");
                    assert_eq!(value[2].float, 69.42, "Value was resolved incorrectly.");
                }
                Err(_) => assert!(false, "Failed to parse message."),
            }
        }

        #[test]
        fn serialize_bundle() {
            let mut buf: [c_uchar; 4096] = [0; 4096];
            let value1 = OscValue { osc_type: OscType::Float, float: 1.0, ..Default::default() };
            let value2 = OscValue { osc_type: OscType::Float, float: 0.5, ..Default::default() };
            let value3 = OscValue { osc_type: OscType::Float, float: 0.1, ..Default::default() };
            let osc_message1 = OscMessage {
                address: CString::new("/tracking/eye/CenterPitchYaw").unwrap().into_raw(),
                value_length: 2,
                value: vec![value1, value2].into_boxed_slice().as_ptr(),
            };
            let osc_message2 = OscMessage {
                address: CString::new("/tracking/eye/EyesClosedAmount").unwrap().into_raw(),
                value_length: 1,
                value: vec![value3].into_boxed_slice().as_ptr(),
            };
            let pp = [osc_message1, osc_message2];
            let mut index: i32 = 0;
            let ret_size = create_osc_bundle(buf.as_mut_ptr(), pp.as_ptr(), 2, &mut index);
            assert_ne!(ret_size, 0)
        }
    }

    #[cfg(test)]
    mod parse {
        use super::*;

        #[test]
        fn parse_bool() {
            let buf = [47, 116, 101, 115, 116, 0, 0, 0, 44, 84, 0, 0];
            let mut parse_index = 0;
            match parse(&buf, &mut parse_index) {
                Ok(message) => {
                    // Convert the address string ptr to a literal string and compare
                    let address = unsafe { CStr::from_ptr(message.address) }.to_str().unwrap();
                    assert_eq!(parse_index, 12, "Incorrect parse index returned.");
                    assert_eq!(address, "/test", "Address was resolved incorrectly.");
                    assert_eq!(message.value_length, 1, "Value length was resolved incorrectly.");
                    let value = unsafe { slice::from_raw_parts(message.value, message.value_length as usize) };
                    assert_eq!(value[0].osc_type, OscType::Bool, "Value type was resolved incorrectly.");
                    assert_eq!(value[0].bool, true, "Value was resolved incorrectly.");
                }
                Err(e) => {
                    panic!("Error: {:?}", e);
                }
            }
        }

        #[test]
        fn parse_int() {
            let buf = [47, 116, 101, 115, 116, 0, 0, 0, 44, 105, 0, 0, 0, 0, 0, 9];
            let mut parse_index = 0;
            match parse(&buf, &mut parse_index) {
                Ok(message) => {
                    // Convert the address string ptr to a literal string and compare
                    let address = unsafe { CStr::from_ptr(message.address) }.to_str().unwrap();
                    assert_eq!(parse_index, 16, "Incorrect parse index returned.");
                    assert_eq!(address, "/test", "Address was resolved incorrectly.");
                    assert_eq!(message.value_length, 1, "Value length was resolved incorrectly.");
                    let value = unsafe { slice::from_raw_parts(message.value, message.value_length as usize) };
                    assert_eq!(value[0].osc_type, OscType::Int, "Value type was resolved incorrectly.");
                    assert_eq!(value[0].int, 9, "Value was resolved incorrectly.");
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

            let mut parse_index = 0;
            match parse(&recv_bytes, &mut parse_index) {
                Ok(message) => {
                    // Convert the address string ptr to a literal string and compare
                    let address = unsafe { CStr::from_ptr(message.address) }.to_str().unwrap();
                    assert_eq!(parse_index, 16, "Incorrect parse index returned.");
                    assert_eq!(address, "/test", "Address was resolved incorrectly.");
                    assert_eq!(message.value_length, 1, "Value length was resolved incorrectly.");
                    let value = unsafe { slice::from_raw_parts(message.value, message.value_length as usize) };
                    assert_eq!(value[0].osc_type, OscType::Float, "Value type was resolved incorrectly.");
                    assert_eq!(value[0].float, 69.42, "Value was resolved incorrectly.");
                }
                Err(e) => {
                    panic!("Error: {:?}", e);
                }
            }
        }

        #[test]
        fn parse_string() {
            let buf = [47, 116, 101, 115, 116, 0, 0, 0, 44, 115, 0, 0, 104, 101, 108, 108, 111, 0, 0, 0];
            let mut parse_index = 0;
            match parse(&buf, &mut parse_index) {
                Ok(message) => {
                    // Convert the address string ptr to a literal string and compare
                    let address = unsafe { CStr::from_ptr(message.address) }.to_str().unwrap();
                    assert_eq!(parse_index, 20, "Incorrect parse index returned.");
                    assert_eq!(address, "/test", "Address was resolved incorrectly.");
                    assert_eq!(message.value_length, 1, "Value length was resolved incorrectly.");
                    let value = unsafe { slice::from_raw_parts(message.value, message.value_length as usize) };
                    assert_eq!(value[0].osc_type, OscType::String, "Value type was resolved incorrectly.");
                    // Convert the string ptr to a literal string and compare
                    let string = unsafe { CStr::from_ptr(value[0].string) }.to_str().unwrap();
                    assert_eq!(string, "hello", "Value was resolved incorrectly.");
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

            let mut parse_index = 0;
            match parse(&recv_bytes, &mut parse_index) {
                Ok(message) => {
                    // Convert the address string ptr to a literal string and compare
                    let address = unsafe { CStr::from_ptr(message.address) }.to_str().unwrap();
                    assert_eq!(parse_index, 40, "Incorrect parse index returned.");
                    assert_eq!(address, "/test", "Address was resolved incorrectly.");
                    assert_eq!(message.value_length, 6, "Value length was resolved incorrectly.");
                    let value = unsafe { slice::from_raw_parts(message.value, message.value_length as usize) };
                    // Check all the values to ensure they're all floats and equal to the expected values
                    for i in 0..6 {
                        assert_eq!(value[i].osc_type, OscType::Float, "Value type was resolved incorrectly.");
                        assert_eq!(value[i].float, i as f32 + 1.0, "Value was resolved incorrectly.");
                    }
                }
                Err(e) => {
                    panic!("Error: {:?}", e);
                }
            }
        }
    }
}
