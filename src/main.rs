use pelite::pe64::{Pe, PeFile};
use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::process;

const DEFAULT_FILE_ALIGNMENT: u32 = 0x200;

fn align(offset: u32, alignment: u32) -> u32 {
    if offset % alignment == 0 {
        offset
    } else {
        offset + (alignment - (offset % alignment))
    }
}

fn realign_pe(buf: &[u8]) -> Vec<u8> {
    let file = PeFile::from_bytes(buf).expect("Failed to parse PE file");

    let header_size = file.optional_header().SizeOfHeaders;
    let aligned_header_size = align(header_size, DEFAULT_FILE_ALIGNMENT);

    let mut dst_offset = aligned_header_size;
    let mut output = Vec::with_capacity(buf.len());

    // Copy and align headers
    output.extend_from_slice(&buf[0..header_size as usize]);
    output.resize(aligned_header_size as usize, 0);

    for section in file.section_headers() {
        let raw_offset = section.PointerToRawData;
        let raw_size = section.SizeOfRawData;
        let aligned_size = align(raw_size, DEFAULT_FILE_ALIGNMENT);

        let start = raw_offset as usize;
        let end = (raw_offset + raw_size) as usize;

        if start >= buf.len() || end > buf.len() {
            panic!("Section out of bounds");
        }

        output.resize(dst_offset as usize, 0);
        output.extend_from_slice(&buf[start..end]);
        output.resize((dst_offset + aligned_size) as usize, 0);

        dst_offset += aligned_size;
    }

    output
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <input> <output>", args[0]);
        process::exit(1);
    }

    let input_path = &args[1];
    let output_path = &args[2];

    let mut input_file = File::open(input_path).expect("Failed to open input file");
    let mut buffer = Vec::new();
    input_file.read_to_end(&mut buffer).expect("Failed to read input file");

    let realigned = realign_pe(&buffer);

    let mut output_file = File::create(output_path).expect("Failed to create output file");
    output_file.write_all(&realigned).expect("Failed to write output file");

    println!("Successfully realigned and saved to {}", output_path);
}

