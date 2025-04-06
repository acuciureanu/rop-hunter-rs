use capstone::prelude::*;
use memchr::memchr;

const RET_OPCODE: u8 = 0xC3;
const MAX_GADGET_SIZE: usize = 8;

pub fn find_gadgets(
    code: &[u8],
    base_addr: u64,
    cs: &Capstone,
    filter: Option<&String>,
) -> Vec<(u64, String)> {
    let mut gadgets = Vec::new();
    let mut pos = 0;

    while let Some(ret_index) = find_next_ret_instruction(&code[pos..]) {
        let absolute_index = pos + ret_index;
        let start_index = absolute_index.saturating_sub(MAX_GADGET_SIZE);
        let gadget_addr = base_addr + start_index as u64;
        let gadget_range = start_index..=absolute_index;

        if let Some(gadget) = disassemble_gadget(code, gadget_range, base_addr, cs) {
            if should_include_gadget(&gadget, filter) {
                gadgets.push((gadget_addr, gadget));
            }
        }

        pos = absolute_index + 1;
    }

    gadgets
}

fn find_next_ret_instruction(code: &[u8]) -> Option<usize> {
    memchr(RET_OPCODE, code)
}

fn disassemble_gadget(
    code: &[u8],
    range: std::ops::RangeInclusive<usize>,
    base_addr: u64,
    cs: &Capstone,
) -> Option<String> {
    let start = *range.start();
    let slice = &code[range];
    
    cs.disasm_all(slice, base_addr + start as u64).ok().and_then(|insns| {
        if insns.is_empty() || !is_valid_ret_gadget(&insns) {
            return None;
        }
        
        Some(format_instructions(&insns))
    })
}

fn is_valid_ret_gadget(insns: &capstone::Instructions) -> bool {
    insns.iter().last()
        .map(|i| i.mnemonic() == Some("ret"))
        .unwrap_or(false)
}

fn format_instructions(insns: &capstone::Instructions) -> String {
    insns.iter().map(|insn| {
        let mnemonic = insn.mnemonic().unwrap_or("");
        let op_str = insn.op_str().map(|s| format!(" {}", s)).unwrap_or_default();
        format!("{}{}", mnemonic, op_str)
    }).collect::<Vec<_>>().join("; ")
}

fn should_include_gadget(gadget: &str, filter: Option<&String>) -> bool {
    filter.is_none_or(|f| {
        f.split(',')
            .any(|pat| gadget.to_lowercase().contains(pat.trim()))
    })
}
