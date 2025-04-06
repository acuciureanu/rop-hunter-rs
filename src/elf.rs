use goblin::elf::Elf;
use capstone::prelude::*;
use colored::*;
use prettytable::{Table, Row, Cell};
use crate::arch::x86_64;
use prettytable::row;

pub fn process_elf(data: &[u8], elf: &Elf, cs: &Capstone, filter: Option<&String>) {
    let mut table = Table::new();
    table.add_row(row!["Address", "Gadget"]);

    let mut gadget_count = 0;

    for ph in elf.program_headers.iter().filter(|ph| ph.is_executable()) {
        let offset = ph.p_offset as usize;
        let size = ph.p_filesz as usize;
        println!("{}", format!("Section at 0x{:x}, size: {}", ph.p_vaddr, size).cyan());

        if offset + size <= data.len() {
            let code = &data[offset..offset + size];
            let gadgets = x86_64::find_gadgets(code, ph.p_vaddr, cs, filter);
            for (addr, gadget) in gadgets {
                table.add_row(Row::new(vec![
                    Cell::new(&format!("0x{:016x}", addr)).style_spec("Fg"), // Green address
                    Cell::new(&gadget),
                ]));
                gadget_count += 1;
            }
        } else {
            println!("{}", format!("Invalid section at 0x{:x}", ph.p_vaddr).yellow());
        }
    }

    if gadget_count > 0 {
        println!("{}", "Gadgets found:".green().bold());
        table.printstd();
        println!("{}", format!("Total gadgets: {}", gadget_count).green());
    } else {
        println!("{}", "No gadgets found".yellow());
    }
}