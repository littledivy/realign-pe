use std::env;
use std::fs;
use std::io::{Read, Write};
use std::process;
use exe::{Buffer, PE};

const DEFAULT_FILE_ALIGNMENT: u32 = 0x200;
const DEFAULT_SECTION_ALIGNMENT: u32 = 0x1000;

struct RealignedSection {
    name: Vec<u8>,
    src_offset: u32,
    src_size: u32,
    src_buf: Vec<u8>,
    dst_offset: u32,
    dst_size: u32,
    dst_padding: Vec<u8>,
}

fn align(offset: u32, alignment: u32) -> u32 {
    if offset % alignment == 0 {
        return offset;
    }
    offset + (alignment - (offset % alignment))
}

fn realign_pe(buf: &[u8]) -> Vec<u8> {
    let mut pe = exe::pe::VecPE::from_disk_data(buf);
    
    // Get PE headers
    let dos_header = pe.get_dos_header().expect("Failed to get DOS header");
    let e_lfanew = dos_header.e_lfanew.0 as usize;
    
    // Get NT headers
    let nt_headers_offset = e_lfanew;
    let file_header_offset = nt_headers_offset + 4;
    
    // Get file header fields we need
    let size_of_optional_header;
    let number_of_sections;
    {
        let file_header = pe.get_ref::<exe::headers::ImageFileHeader>(file_header_offset)
            .expect("Failed to get file header");
        size_of_optional_header = file_header.size_of_optional_header;
        number_of_sections = file_header.number_of_sections;
    }
    
    // Calculate header size
    let SIZEOF_FILE_HEADER: u32 = 0x18;
    let header_size = e_lfanew as u32 + 
                     SIZEOF_FILE_HEADER + 
                     size_of_optional_header as u32 + 
                     (number_of_sections as u32 * 0x28);
    let aligned_header_size = align(header_size, 0x200);
    
    // Get the optional header based on architecture
    let optional_header_offset = file_header_offset + 20;
    let optional_header_magic;
    {
        let magic = pe.get_ref::<u16>(optional_header_offset).expect("Failed to get optional header magic");
        optional_header_magic = *magic;
    }
    
    // Update file alignment based on architecture (32-bit or 64-bit)
    if optional_header_magic == 0x10B { // 32-bit
        let optional_header = pe.get_mut_ref::<exe::headers::ImageOptionalHeader32>(optional_header_offset)
            .expect("Failed to get 32-bit optional header");
        print!("adjusting file alignment: 0x{:x} -> 0x{:x}\n", 
               optional_header.file_alignment, 
               DEFAULT_FILE_ALIGNMENT);
        optional_header.file_alignment = DEFAULT_FILE_ALIGNMENT;
    } else if optional_header_magic == 0x20B { // 64-bit
        let optional_header = pe.get_mut_ref::<exe::headers::ImageOptionalHeader64>(optional_header_offset)
            .expect("Failed to get 64-bit optional header");
        print!("adjusting file alignment: 0x{:x} -> 0x{:x}\n", 
               optional_header.file_alignment, 
               DEFAULT_FILE_ALIGNMENT);
        optional_header.file_alignment = DEFAULT_FILE_ALIGNMENT;
    } else {
        panic!("Unsupported PE format");
    }
    
    // Get the section table
    let section_table_offset = optional_header_offset + size_of_optional_header as usize;
    let num_sections = number_of_sections as usize;
    
    // Collect section information and sort by pointer_to_raw_data
    let mut sections = Vec::new();
    for i in 0..num_sections {
        let section_offset = section_table_offset + (i * 40); // Each section header is 40 bytes
        let section = pe.get_mut_ref::<exe::headers::ImageSectionHeader>(section_offset)
            .expect("Failed to get section header");
        sections.push((section_offset, section.pointer_to_raw_data.0));
    }
    sections.sort_by_key(|&(_, pointer_to_raw_data)| pointer_to_raw_data);
    
    let mut dst_offset = aligned_header_size;  // the offset at which the current section should begin
    let mut dst_secs = Vec::new();  // list of RealignedSection instances
    
    // Process each section
    for (section_offset, _) in sections {
        let section = pe.get_mut_ref::<exe::headers::ImageSectionHeader>(section_offset)
            .expect("Failed to get section header");
        
        let pointer_to_raw_data = section.pointer_to_raw_data.0;
        let size_of_raw_data = section.size_of_raw_data;
        let dst_size = align(size_of_raw_data, 0x200);
        let padding = vec![0; (dst_size - size_of_raw_data) as usize];

        // Collect section data
        let src_offset = pointer_to_raw_data as usize;
        let src_size = size_of_raw_data as usize;
        let src_buf = if src_size > 0 && src_offset + src_size <= buf.len() {
            buf[src_offset..src_offset + src_size].to_vec()
        } else {
            Vec::new()
        };

        // Convert the section name (array of CChar) to a vector of bytes
        let name_bytes: Vec<u8> = section.name.iter().map(|c| c.0).collect();
        
        print!("  resizing {:?}\toffset: 0x{:x}\traw size: 0x{:x}  \t--> offset: 0x{:x}\traw size: 0x{:x}\n",
                String::from_utf8_lossy(&name_bytes),
                pointer_to_raw_data,
                size_of_raw_data,
                dst_offset,
                dst_size);

        let sec = RealignedSection {
            name: name_bytes,
            src_offset: pointer_to_raw_data,
            src_size: size_of_raw_data,
            src_buf,
            dst_offset,
            dst_size,
            dst_padding: padding,
        };

        dst_secs.push(sec);

        // Fix section pointers
        section.pointer_to_raw_data = exe::types::Offset(dst_offset);
        section.size_of_raw_data = dst_size;
        dst_offset += dst_size;
    }
    
    // Write the modified PE file to a buffer
    let modified_pe_data = pe.as_slice().to_vec();
    
    // Create the final buffer with realigned sections
    let mut result = Vec::new();
    result.extend_from_slice(&modified_pe_data[..header_size as usize]);
    result.extend(vec![0; (aligned_header_size - header_size) as usize]);

    for sec in dst_secs {
        result.extend_from_slice(&sec.src_buf);
        result.extend_from_slice(&sec.dst_padding);
    }

    result
}

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() != 3 {
        eprintln!("Usage: {} <input_file> <output_file>", args[0]);
        process::exit(1);
    }

    let input_path = &args[1];
    let output_path = &args[2];

    let mut input_file = fs::File::open(input_path).expect("Failed to open input file");
    let mut buf = Vec::new();
    input_file.read_to_end(&mut buf).expect("Failed to read input file");

    let result = realign_pe(&buf);

    let mut output_file = fs::File::create(output_path).expect("Failed to create output file");
    output_file.write_all(&result).expect("Failed to write output file");
}