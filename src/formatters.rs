use colored::*;
use prettytable::{Table, Row, Cell, row};
use crate::models::ScanResult;

pub struct ResultFormatter;

impl ResultFormatter {
    pub fn format_results(results: Vec<ScanResult>) -> Table {
        let mut table = Table::new();
        table.add_row(row!["Address", "Gadget"]);
        
        for result in results {
            for gadget in result.gadgets {
                table.add_row(Row::new(vec![
                    Cell::new(&format!("0x{:016x}", gadget.address)).style_spec("Fg"),
                    Cell::new(&gadget.instructions),
                ]));
            }
        }
        
        table
    }
    
    pub fn print_section_info(result: &ScanResult) {
        let section_name = result.section_name.as_deref().unwrap_or("Unnamed");
        println!(
            "{}",
            format!(
                "Section {} at 0x{:x}, size: {}",
                section_name,
                result.section_address,
                result.section_size
            )
            .cyan()
        );
    }
    
    pub fn print_results(results: Vec<ScanResult>) {
        let total_gadgets: usize = results.iter().map(|r| r.len()).sum();
        
        if total_gadgets > 0 {
            println!("{}", "Gadgets found:".green().bold());
            let table = Self::format_results(results);
            table.printstd();
            println!("{}", format!("Total gadgets: {}", total_gadgets).green());
        } else {
            println!("{}", "No gadgets found".yellow());
        }
    }
} 