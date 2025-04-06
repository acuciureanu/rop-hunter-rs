use goblin::pe::PE;
use goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE;

pub trait PEAnalyzer {
    fn get_executable_sections(&self) -> Vec<(&goblin::pe::section_table::SectionTable, usize)>;
}

impl PEAnalyzer for PE<'_> {
    fn get_executable_sections(&self) -> Vec<(&goblin::pe::section_table::SectionTable, usize)> {
        self.sections
            .iter()
            .filter(|s| (s.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
            .map(|section| {
                let base_addr = self.image_base + section.virtual_address as usize;
                (section, base_addr)
            })
            .collect()
    }
}
