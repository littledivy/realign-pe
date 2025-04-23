use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::env;
use std::fs::File;
use std::io::{Read, Write, Cursor};
use std::process;

const FILE_ALIGNMENT: u32 = 0x200;
const SECTION_HEADER_SIZE: usize = 0x28;
const SIZEOF_FILE_HEADER: usize = 0x18;

fn align(offset: u32, alignment: u32) -> u32 {
    if offset % alignment == 0 {
        offset
    } else {
        offset + (alignment - (offset % alignment))
    }
}

fn realign_pe(buf: &[u8]) -> Vec<u8> {
    let mut rdr = Cursor::new(buf);

    // Read e_lfanew
    rdr.set_position(0x3C);
    let pe_offset = rdr.read_u32::<LittleEndian>().unwrap();

    // Read NumberOfSections and SizeOfOptionalHeader
    rdr.set_position(pe_offset as u64 + 6);
    let num_sections = rdr.read_u16::<LittleEndian>().unwrap();
    let opt_header_size = rdr.read_u16::<LittleEndian>().unwrap();

    let section_table_offset = pe_offset + 4 + SIZEOF_FILE_HEADER as u32 + opt_header_size as u32;
    let header_size = section_table_offset + (num_sections as u32 * SECTION_HEADER_SIZE as u32);
    let aligned_header_size = align(header_size, FILE_ALIGNMENT);

    // Patch FileAlignment
    let file_alignment_offset = pe_offset + 4 + SIZEOF_FILE_HEADER as u32 + 0x20;
    let mut mod_buf = buf.to_vec();
    {
        let mut patch = Cursor::new(&mut mod_buf[file_alignment_offset as usize..]);
        patch.write_u32::<LittleEndian>(FILE_ALIGNMENT).unwrap();
    }

    // Parse and update section headers
    let mut dst_offset = aligned_header_size;
    let mut sections = Vec::new();

    for i in 0..num_sections {
        let sec_off = section_table_offset + i as u32 * SECTION_HEADER_SIZE as u32;
        let name = &buf[sec_off as usize..sec_off as usize + 8];
        let ptr_raw = (&buf[sec_off as usize + 0x14..]).read_u32::<LittleEndian>().unwrap();
        let size_raw = (&buf[sec_off as usize + 0x10..]).read_u32::<LittleEndian>().unwrap();
        let src_buf = &buf[ptr_raw as usize..(ptr_raw + size_raw) as usize];

        let dst_size = align(size_raw, FILE_ALIGNMENT);
        let padding = vec![0u8; (dst_size - size_raw) as usize];

        // Patch PointerToRawData and SizeOfRawData
        {
            let off = sec_off as usize + 0x14;
            let mut cursor = Cursor::new(&mut mod_buf[off..off + 4]);
            cursor.write_u32::<LittleEndian>(dst_offset).unwrap();
        }
        {
            let off = sec_off as usize + 0x10;
            let mut cursor = Cursor::new(&mut mod_buf[off..off + 4]);
            cursor.write_u32::<LittleEndian>(dst_size).unwrap();
        }

        sections.push((dst_offset, src_buf.to_vec(), padding));
        dst_offset += dst_size;
    }

    // Assemble the final buffer
    let mut ret = Vec::new();
    ret.extend_from_slice(&mod_buf[..header_size as usize]);
    ret.extend_from_slice(&vec![0u8; (aligned_header_size - header_size) as usize]);

    for (off, sec_data, padding) in sections {
        ret.extend_from_slice(&sec_data);
        ret.extend_from_slice(&padding);
    }

    ret
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <input> <output>", args[0]);
        process::exit(1);
    }

    let input_path = &args[1];
    let output_path = &args[2];

    let mut f = File::open(input_path).expect("Failed to open input file");
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).expect("Failed to read input");

    let new_pe = realign_pe(&buffer);

    let mut out = File::create(output_path).expect("Failed to create output");
    out.write_all(&new_pe).expect("Failed to write output");

    println!("Written realigned PE to {}", output_path);
}

