use std::{
    fs,
    io,
    mem,
    slice
};

use winapi::um::winnt::*;

fn main() -> io::Result<()> {
    let mut args = std::env::args();
    args.next();
    let orig = args.next().unwrap();
    let mut dumped_name = args.next().unwrap();
    // let base = args.next().unwrap();
    //
    // let base = match base.as_bytes() {
    //     [b'0', b'x', rest@..] => u64::from_str_radix(unsafe { std::str::from_utf8_unchecked(rest) }, 16).unwrap(),
    //     _ => u64::from_str_radix(base.as_str(), 10).unwrap(),
    // };

    let orig = fs::read(orig)?;
    let mut dumped = fs::read(&dumped_name)?;

    let orig_dos = unsafe { &*(orig.as_ptr() as *const IMAGE_DOS_HEADER )};
    let orig_nt = unsafe { &*(orig.as_ptr().add(orig_dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64 )};
    let dumped_nt = unsafe { &mut *( dumped.as_mut_ptr().add(orig_dos.e_lfanew as usize) as *mut IMAGE_NT_HEADERS64 )};

    let orig_file = &orig_nt.FileHeader;
    let dumped_file = &mut dumped_nt.FileHeader;

    dumped_file.Machine = orig_file.Machine;
    dumped_file.NumberOfSections = orig_file.NumberOfSections;
    dumped_file.TimeDateStamp = orig_file.TimeDateStamp;
    dumped_file.PointerToSymbolTable = orig_file.PointerToSymbolTable;
    dumped_file.NumberOfSymbols = orig_file.NumberOfSymbols;
    dumped_file.SizeOfOptionalHeader = orig_file.SizeOfOptionalHeader;
    dumped_file.Characteristics = orig_file.Characteristics;

    let orig_opt = &orig_nt.OptionalHeader;
    let dumped_opt = &mut dumped_nt.OptionalHeader;

    dumped_opt.MajorLinkerVersion = orig_opt.MajorLinkerVersion;
    dumped_opt.MinorLinkerVersion = orig_opt.MinorLinkerVersion;
    dumped_opt.SizeOfCode = orig_opt.SizeOfCode;
    dumped_opt.SizeOfInitializedData = orig_opt.SizeOfInitializedData;
    dumped_opt.SizeOfUninitializedData = orig_opt.SizeOfUninitializedData;
    dumped_opt.AddressOfEntryPoint = orig_opt.AddressOfEntryPoint;
    dumped_opt.BaseOfCode = orig_opt.BaseOfCode;
    // dumped_opt.ImageBase = orig_opt.ImageBase;
    // dumped_opt.SectionAlignment = 0;
    // dumped_opt.FileAlignment = 0;
    dumped_opt.SectionAlignment = orig_opt.SectionAlignment;
    dumped_opt.FileAlignment = orig_opt.FileAlignment;
    dumped_opt.MajorOperatingSystemVersion = orig_opt.MajorOperatingSystemVersion;
    dumped_opt.MinorOperatingSystemVersion = orig_opt.MinorOperatingSystemVersion;
    dumped_opt.MajorImageVersion = orig_opt.MajorImageVersion;
    dumped_opt.MinorImageVersion = orig_opt.MinorImageVersion;
    dumped_opt.MajorSubsystemVersion = orig_opt.MajorSubsystemVersion;
    dumped_opt.MinorSubsystemVersion = orig_opt.MinorSubsystemVersion;
    dumped_opt.Win32VersionValue = orig_opt.Win32VersionValue;
    dumped_opt.SizeOfImage = dumped.len() as u32;
    dumped_opt.SizeOfHeaders = orig_opt.SizeOfHeaders;
    dumped_opt.CheckSum = 0;
    dumped_opt.Subsystem = orig_opt.Subsystem;
    dumped_opt.DllCharacteristics = orig_opt.DllCharacteristics;
    dumped_opt.SizeOfStackReserve = orig_opt.SizeOfStackReserve;
    dumped_opt.SizeOfStackCommit = orig_opt.SizeOfStackCommit;
    dumped_opt.SizeOfHeapReserve = orig_opt.SizeOfHeapReserve;
    dumped_opt.SizeOfHeapCommit = orig_opt.SizeOfHeapCommit;
    dumped_opt.LoaderFlags = orig_opt.LoaderFlags;
    dumped_opt.NumberOfRvaAndSizes = orig_opt.NumberOfRvaAndSizes;

    for i in 0..dumped_opt.NumberOfRvaAndSizes {
        let i = i as usize;
        dumped_opt.DataDirectory[i].VirtualAddress = orig_opt.DataDirectory[i].VirtualAddress;
        dumped_opt.DataDirectory[i].Size = orig_opt.DataDirectory[i].Size;
    }

    println!("{:#018X}", orig_dos.e_lfanew);
    println!("{:#018X}", mem::size_of::<IMAGE_NT_HEADERS64>());
    println!("{:#018X}", orig_dos.e_lfanew as usize + mem::size_of::<IMAGE_NT_HEADERS64>());
    let orig_sec = unsafe { slice::from_raw_parts(orig.as_ptr().add(orig_dos.e_lfanew as usize + mem::size_of::<IMAGE_NT_HEADERS64>() ) as *const IMAGE_SECTION_HEADER, orig_file.NumberOfSections as usize)};
    let dumped_sec = unsafe { slice::from_raw_parts_mut(dumped.as_mut_ptr().add(orig_dos.e_lfanew as usize + mem::size_of::<IMAGE_NT_HEADERS64>() ) as *mut IMAGE_SECTION_HEADER, orig_file.NumberOfSections as usize)};

    for (o, d) in orig_sec.iter().zip(dumped_sec.iter_mut()) {
        d.Name = o.Name;
        println!("{:?}", d.Name);
        d.Misc = o.Misc;
        d.VirtualAddress = o.VirtualAddress;
        d.SizeOfRawData = unsafe { *o.Misc.VirtualSize() };
        d.PointerToRawData = d.VirtualAddress;
        d.PointerToRelocations = 0;
        d.PointerToLinenumbers = 0;
        d.NumberOfRelocations = 0;
        d.NumberOfLinenumbers = 0;
        d.Characteristics = o.Characteristics;
    }

    dumped_name.push_str(".patched.exe");
    fs::write(dumped_name, dumped)?;

    println!("Done!");

    Ok(())
}
