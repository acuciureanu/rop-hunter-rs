use capstone::prelude::*;
use memchr::memchr;

pub fn find_gadgets(
    code: &[u8],
    base_addr: u64,
    cs: &Capstone,
    filter: Option<&String>,
) -> Vec<(u64, String)> {
    let mut gadgets = Vec::new();
    let mut pos = 0;

    while let Some(i) = memchr(0xC3, &code[pos..]) {
        let i = pos + i;
        let start = i.saturating_sub(8);
        let slice = &code[start..=i];
        if let Ok(insns) = cs.disasm_all(slice, base_addr + start as u64) {
            let mut gadget = String::new();
            for insn in insns.iter() {
                if !gadget.is_empty() {
                    gadget.push_str("; ");
                }
                gadget.push_str(insn.mnemonic().unwrap_or(""));
                if let Some(op_str) = insn.op_str() {
                    gadget.push(' ');
                    gadget.push_str(op_str);
                }
            }
            if insns
                .iter()
                .last()
                .map(|i| i.mnemonic() == Some("ret"))
                .unwrap_or(false)
            {
                let addr = base_addr + start as u64;
                let include = filter.is_none_or(|f| {
                    f.split(',')
                        .any(|pat| gadget.to_lowercase().contains(pat.trim()))
                });
                if include {
                    gadgets.push((addr, gadget));
                }
            }
        }
        pos = i + 1;
    }

    gadgets
}
