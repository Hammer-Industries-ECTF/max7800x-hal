//! # Advanced Encryption Standard (AES)
//!
//! The AES is a hardware module that accelerates decryption (and encryption)

use crate::pac::aes::ctrl::{KeySize, Type};

/// Address of the AES key registers in memory.
pub const AES_KEY_REGISTER_ADDR: usize = 0x4000_7800;

#[derive(Debug, Clone)]
pub enum AesError {
    NotEmpty,
    Misconfigured,
}

pub type AesSubBlock = u32;
pub type AesBlock = [AesSubBlock; 4];
pub type AesKey = [u32; 8];

pub struct Aes {
    aes: crate::pac::Aes,
}

impl Aes {
    /// Create a new AES peripheral instance.
    pub fn new(aes: crate::pac::Aes, reg: &mut crate::gcr::GcrRegisters) -> Self {
        use crate::gcr::ResetForPeripheral;
        use crate::gcr::ClockForPeripheral;
        
        unsafe {
            aes.reset(&mut reg.gcr);
            aes.enable_clock(&mut reg.gcr);
        }

        aes.ctrl().write(|w| {
            w.type_().variant(Type::DecExt);
            w.key_size().aes256();
            w.input_flush().set_bit();
            w.output_flush().set_bit();
            w.dma_rx_en().clear_bit();
            w.dma_tx_en().clear_bit();
            w.en().set_bit();

            return w;
        });

        Self { aes }
    }

    #[inline(always)]
    pub fn decrypt_block(&self, in_block: AesBlock) -> Result<AesBlock, AesError> {
        let mut out_block: AesBlock = [0, 0, 0, 0];

        self.aes.ctrl().write(|w| w.type_().variant(Type::DecExt));
        if self._get_mode() != Type::DecExt {
            return Err(AesError::Misconfigured)
        }

        if self._get_key_size() != KeySize::Aes256 {
            return Err(AesError::Misconfigured)
        }

        if !self._in_fifo_empty() {
            return Err(AesError::NotEmpty)
        }

        for subblock in in_block {
            self._set_in_fifo(subblock);
        }

        self._wait();

        for bidx in 0..out_block.len() {
            out_block[bidx] = self._get_out_fifo();
        }

        Ok(out_block)
    }

    #[inline(always)]
    pub fn encrypt_block(&self, in_block: AesBlock) -> Result<AesBlock, AesError> {
        let mut out_block: AesBlock = [0, 0, 0, 0];

        self.aes.ctrl().write(|w| w.type_().variant(Type::EncExt));
        if self._get_mode() != Type::EncExt {
            return Err(AesError::Misconfigured)
        }

        if self._get_key_size() != KeySize::Aes256 {
            return Err(AesError::Misconfigured)
        }

        if !self._in_fifo_empty() {
            return Err(AesError::NotEmpty)
        }

        for subblock in in_block {
            self._set_in_fifo(subblock);
        }

        self._wait();

        for bidx in 0..out_block.len() {
            out_block[bidx] = self._get_out_fifo();
        }

        Ok(out_block)
    }

    #[inline(always)]
    pub fn set_key(&self, key: &AesKey) {
        for i in 0..key.len() {
            let k: u32 = key[i];
            let d: usize = AES_KEY_REGISTER_ADDR + (i * 4);
            unsafe {
                core::ptr::write_volatile::<u32>((d) as *mut u32, k);
            }
        }
    }

    #[doc(hidden)]
    #[inline(always)]
    fn _set_in_fifo(&self, subblock: AesSubBlock) {
        self.aes.fifo().write(|w| unsafe { w.bits(subblock) });
    }

    #[doc(hidden)]
    #[inline(always)]
    fn _get_out_fifo(&self) -> AesSubBlock {
        self.aes.fifo().read().bits()
    }

    #[doc(hidden)]
    #[inline(always)]
    fn _wait(&self) {
        while self._is_busy() {}
    }

    #[doc(hidden)]
    #[inline(always)]
    fn _is_busy(&self) -> bool {
        self.aes.status().read().busy().bit_is_set()
    }

    #[doc(hidden)]
    #[inline(always)]
    fn _in_fifo_empty(&self) -> bool {
        self.aes.status().read().input_em().bit_is_set()
    }

    #[doc(hidden)]
    #[inline(always)]
    fn _out_fifo_full(&self) -> bool {
        self.aes.status().read().output_full().bit_is_set()
    }

    #[doc(hidden)]
    #[inline(always)]
    fn _get_key_size(&self) -> KeySize {
        self.aes.ctrl().read().key_size().variant().unwrap()
    }

    #[doc(hidden)]
    #[inline(always)]
    fn _get_mode(&self) -> Type {
        self.aes.ctrl().read().type_().variant().unwrap()
    }

}
