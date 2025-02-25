//! # Advanced Encryption Standard (AES)
//!
//! The AES is a hardware module that accelerates decryption (and encryption)

pub struct Aes {
    aes: crate::pac::Aes,
}

impl Aes {
    /// Create a new AES peripheral instance.
    pub fn new(aes: crate::pac::Aes, reg: &mut crate::gcr::GcrRegisters) -> Self {
        use crate::gcr::ClockForPeripheral;
        unsafe {
            aes.enable_clock(&mut reg.gcr);
        }
        Self { aes }
    }
}