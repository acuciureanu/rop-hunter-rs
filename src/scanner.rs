use capstone::arch::x86::ArchMode;
use capstone::prelude::*;
use goblin::elf::Elf;
use goblin::pe::PE;
use goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE;
use colored::*;

use crate::models::ScanResult;
use crate::formatters::ResultFormatter;
use crate::arch::x86_64;

pub struct Scanner<'a> {
    data: &'a [u8],
    filter: Option<&'a String>,
    disassembler: Capstone,
}

impl<'a> Scanner<'a> {
    pub fn new(data: &'a [u8], filter: Option<&'a String>) -> Self {
        let disassembler = Capstone::new()
            .x86()
            .mode(ArchMode::Mode64)
            .build()
            .expect("Failed to init Capstone");
            
        Self {
            data,
            filter,
            disassembler,
        }
    }
    
    pub fn scan_elf(&self, elf: &Elf) {
        let mut results = Vec::new();
        
        for ph in elf.program_headers.iter().filter(|ph| ph.is_executable()) {
            let offset = ph.p_offset as usize;
            let size = ph.p_filesz as usize;
            
            let mut result = ScanResult::new(ph.p_vaddr, size, None);
            ResultFormatter::print_section_info(&result);
            
            if offset + size <= self.data.len() {
                let code = &self.data[offset..offset + size];
                let gadgets = x86_64::find_gadgets(code, ph.p_vaddr, &self.disassembler, self.filter);
                
                for (addr, gadget) in gadgets {
                    result.add_gadget(addr, gadget);
                }
                
                results.push(result);
            } else {
                println!("{}", format!("Invalid section at 0x{:x}", ph.p_vaddr).yellow());
            }
        }
        
        ResultFormatter::print_results(results);
    }
    
    pub fn scan_pe(&self, pe: &PE) {
        let mut results = Vec::new();
        
        for section in pe.sections.iter().filter(|s| (s.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) {
            let offset = section.pointer_to_raw_data as usize;
            let size = section.size_of_raw_data as usize;
            let base_addr = pe.image_base + section.virtual_address as usize;
            
            let section_name = section.name().ok().map(|s| s.to_string());
            let mut result = ScanResult::new(base_addr as u64, size, section_name);
            ResultFormatter::print_section_info(&result);
            
            if offset + size <= self.data.len() {
                let code = &self.data[offset..offset + size];
                let gadgets = x86_64::find_gadgets(code, base_addr as u64, &self.disassembler, self.filter);
                
                for (addr, gadget) in gadgets {
                    result.add_gadget(addr, gadget);
                }
                
                results.push(result);
            } else {
                println!("{}", format!("Invalid section at 0x{:x}", base_addr).yellow());
            }
        }
        
        ResultFormatter::print_results(results);
    }
} 