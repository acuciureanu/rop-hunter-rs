use crate::arch::x86_64;
use capstone::prelude::*;
use colored::*;
use goblin::pe::PE;
use goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE;
use prettytable::row;
use prettytable::{Cell, Row, Table};

pub fn process_pe(data: &[u8], pe: &PE, cs: &Capstone, filter: Option<&String>) {
    let mut table = Table::new();
    table.add_row(row!["Address", "Gadget"]);

    let mut gadget_count = 0;

    for section in pe
        .sections
        .iter()
        .filter(|s| (s.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
    {
        let offset = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;
        let base_addr = pe.image_base + section.virtual_address as usize;
        println!(
            "{}",
            format!(
                "Section {} at 0x{:x}, size: {}",
                section.name().unwrap_or("Unnamed"),
                base_addr,
                size
            )
            .cyan()
        );

        if offset + size <= data.len() {
            let code = &data[offset..offset + size];
            let gadgets = x86_64::find_gadgets(code, base_addr as u64, cs, filter);
            for (addr, gadget) in gadgets {
                table.add_row(Row::new(vec![
                    Cell::new(&format!("0x{:016x}", addr)).style_spec("Fg"), // Green address
                    Cell::new(&gadget),
                ]));
                gadget_count += 1;
            }
        } else {
            println!(
                "{}",
                format!("Invalid section at 0x{:x}", base_addr).yellow()
            );
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
