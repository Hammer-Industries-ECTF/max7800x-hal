//! # Advanced Encryption Standard (AES)
//!
//! The AES is a hardware module that accelerates decryption (and encryption)
//! AntiAES configured

use crate::pac::aes::ctrl::{KeySize, Type};

/// Address of the AES key registers in memory.
pub const AES_KEY_REGISTER_ADDR: usize = 0x4000_7800;

#[derive(Debug, Clone, Copy)]
pub enum AesError {
    NotEmpty,
    Misconfigured,
}

pub type AesSubBlock = u8;
pub type AesBlock = [AesSubBlock; 16];
pub type AesKey = [u8; 32];

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

        Self { aes }
    }

    /// Decrypts block with AES256
    #[inline(always)]
    pub fn decrypt_block(&self, in_block: AesBlock) -> Result<AesBlock, AesError> {
        let in_block_32: [u32; 4] = convert_u8_to_u32_array(in_block);
        let mut out_block_32: [u32; 4] = [0u32; 4];

        if self._get_mode() != Type::EncExt {
            return Err(AesError::Misconfigured)
        }

        if self._get_key_size() != KeySize::Aes256 {
            return Err(AesError::Misconfigured)
        }

        if !self._in_fifo_empty() {
            return Err(AesError::NotEmpty)
        }

        for subblock in in_block_32 {
            self._set_in_fifo(subblock);
        }

        self._wait();

        for bidx in 0..out_block_32.len() {
            out_block_32[bidx] = self._get_out_fifo();
        }

        let out_block: [u8; 16] = convert_u32_to_u8_array(out_block_32);
        Ok(out_block)
    }

    /// Encrypts block with AES256
    #[inline(always)]
    pub fn encrypt_block(&self, in_block: AesBlock) -> Result<AesBlock, AesError> {
        let in_block_32: [u32; 4] = convert_u8_to_u32_array(in_block);
        let mut out_block_32: [u32; 4] = [0u32; 4];

        if self._get_mode() != Type::DecExt {
            return Err(AesError::Misconfigured)
        }

        if self._get_key_size() != KeySize::Aes256 {
            return Err(AesError::Misconfigured)
        }

        if !self._in_fifo_empty() {
            return Err(AesError::NotEmpty)
        }

        for subblock in in_block_32 {
            self._set_in_fifo(subblock);
        }

        self._wait();

        for bidx in 0..out_block_32.len() {
            out_block_32[bidx] = self._get_out_fifo();
        }

        let out_block: [u8; 16] = convert_u32_to_u8_array(out_block_32);
        Ok(out_block)
    }

    /// Sets key for AES256
    #[inline(always)]
    pub fn set_key(&self, key: &AesKey) {
        unsafe {
            for i in 0..256 {
                core::ptr::write_volatile::<u32>((AES_KEY_REGISTER_ADDR + (i * 4)) as *mut u32, 0u32);
            }
            core::ptr::copy_nonoverlapping::<u8>(key.as_ptr(), AES_KEY_REGISTER_ADDR as *mut u8, key.len());    
        }

        self.aes.ctrl().modify(|_, w| w.en().clear_bit());
        self._flush();

        self.aes.ctrl().modify(|_, w| {
            w.key_size().aes256();
            w.type_().variant(Type::EncExt);
            return w;
        });

        self.aes.ctrl().modify(|_, w| w.en().set_bit());
    }

    /// Sets mode for AES256
    #[inline(always)]
    pub fn set_mode(&self, mode: Type) {
        self.aes.ctrl().modify(|_, w| w.en().clear_bit());
        self._wait();
        self.aes.ctrl().modify(|_, w| {
            w.type_().variant(mode);
            w.key_size().aes256();
            w.input_flush().set_bit();
            w.output_flush().set_bit();
            w.dma_rx_en().clear_bit();
            w.dma_tx_en().clear_bit();
            w.en().set_bit();

            return w;
        });
        self._wait();
    }

    #[doc(hidden)]
    #[inline(always)]
    fn _set_in_fifo(&self, subblock: u32) {
        self.aes.fifo().modify(|_, w| unsafe { w.bits(subblock) });
    }

    #[doc(hidden)]
    #[inline(always)]
    fn _get_out_fifo(&self) -> u32 {
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
    fn _out_fifo_empty(&self) -> bool {
        self.aes.status().read().output_em().bit_is_set()
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

    #[doc(hidden)]
    #[inline(always)]
    fn _flush(&self) {
        if !self._in_fifo_empty() {
            self.aes.ctrl().modify(|_, w| w.input_flush().set_bit());
        }
        if !self._out_fifo_empty() {
            self.aes.ctrl().modify(|_, w| w.output_flush().set_bit());
        }
        self._wait();
    }
}

fn convert_u8_to_u32_array(bytes: [u8; 16]) -> [u32; 4] {
    use core::mem::transmute;
    unsafe { transmute(bytes) }
}

fn convert_u32_to_u8_array(bytes: [u32; 4]) -> [u8; 16] {
    use core::mem::transmute;
    unsafe { transmute(bytes) }
}
