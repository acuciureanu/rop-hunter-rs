use std::env;
use std::fs;
use colored::*;
use goblin::Object;

mod arch;
mod models;
mod scanner;
mod formatters;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("{}", "Usage: rop-hunter <binary_path> [--filter <pattern>]".bold().red());
        println!("  --filter: e.g., 'pop', 'mov', 'ret' (comma-separated)");
        return;
    }

    let binary_path = &args[1];
    let filter = args.get(2).and_then(|arg| if arg == "--filter" { args.get(3) } else { None });

    println!("{}", format!("Scanning: {}", binary_path).cyan().bold());

    let data = match fs::read(binary_path) {
        Ok(data) => {
            println!("{}", format!("Read {} bytes", data.len()).green());
            data
        }
        Err(e) => {
            println!("{}", format!("Error reading file: {}", e).red());
            return;
        }
    };

    let scanner = scanner::Scanner::new(&data, filter);
    
    match Object::parse(&data) {
        Ok(Object::Elf(elf)) => {
            println!("{}", "Detected ELF file".blue().bold());
            scanner.scan_elf(&elf);
        }
        Ok(Object::PE(pe)) => {
            println!("{}", "Detected PE file".blue().bold());
            scanner.scan_pe(&pe);
        }
        Ok(_) => println!("{}", "Unsupported file type".yellow()),
        Err(e) => println!("{}", format!("Parse error: {}", e).red()),
    }
}