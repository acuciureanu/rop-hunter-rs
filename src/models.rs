pub struct Gadget {
    pub address: u64,
    pub instructions: String,
}

pub struct ScanResult {
    pub gadgets: Vec<Gadget>,
    pub section_name: Option<String>,
    pub section_address: u64,
    pub section_size: usize,
}

impl ScanResult {
    pub fn new(section_address: u64, section_size: usize, section_name: Option<String>) -> Self {
        Self {
            gadgets: Vec::new(),
            section_name,
            section_address,
            section_size,
        }
    }

    pub fn add_gadget(&mut self, address: u64, instructions: String) {
        self.gadgets.push(Gadget { address, instructions });
    }

    pub fn len(&self) -> usize {
        self.gadgets.len()
    }
} 