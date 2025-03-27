//! SIMO

pub struct Simo {}

impl Simo {
    /// Create a new SIMO peripheral instance.
    pub fn new(simo: crate::pac::Simo, _reg: &mut crate::gcr::GcrRegisters) -> Self {
        simo.vrego_c().modify(|_, w| unsafe { w.vsetc().bits(59) } );

        Self {}
    }
}
