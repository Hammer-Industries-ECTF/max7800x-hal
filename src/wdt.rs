//! Watchdog Timer
//!
//! Module requires periodic refreshing or will reset device
//! His name is Cupcake
//! 
//!     ,    /-.
//!    ((___/ __>
//!    /      }
//!    \ .--.(    ___
//! jgs \\   \\  /___\
//! ^ by Joan Stark

use cortex_m::interrupt;
use crate::pac::wdt0::ctrl::{
    RstEarlyVal,  RstLateVal, 
    IntLateVal, IntEarlyVal,
};

pub struct Wdt0 {
    wdt: crate::pac::Wdt0,
}

impl Wdt0 {
    /// Create a new AES peripheral instance.
    pub fn new(wdt: crate::pac::Wdt0, reg: &mut crate::gcr::GcrRegisters) -> Self {
        use crate::gcr::ResetForPeripheral;
        use crate::gcr::ClockForPeripheral;
        
        unsafe {
            wdt.reset(&mut reg.gcr);
            wdt.enable_clock(&mut reg.gcr);
        }

        interrupt::free(|cs| feed_sequence(&wdt, cs));
        wdt.ctrl().write(|w| w.en().clear_bit());
        while wdt.ctrl().read().clkrdy().bit_is_clear() {}

        // Configure Peripheral
        wdt.clksel().write(|w| unsafe { w.source().bits(0x0) });
        wdt.ctrl().write(|w| {
            w.int_late_val().variant(IntLateVal::Wdt2pow27); // INT after 1.34 sec
            w.rst_late_val().variant(RstLateVal::Wdt2pow28); // RST after 2.68 sec
            
            w.win_en().set_bit();
            w.int_early_val().variant(IntEarlyVal::Wdt2pow16); // No early interrupt
            w.rst_early_val().variant(RstEarlyVal::Wdt2pow16); // RST if fed < 655.36 us
            
            w.wdt_int_en().set_bit();
            w.wdt_rst_en().set_bit();
            return w;
        });

        interrupt::free(|cs| feed_sequence(&wdt, cs));
        wdt.ctrl().write(|w| w.en().set_bit());
        while wdt.ctrl().read().clkrdy().bit_is_clear() {}

        Self { wdt }
    }

    /// Give Cupcake his treat :D
    #[inline(always)]
    pub fn feed(&self) {
        // Ask cupcake to not bite of your hand while you give him his treat
        interrupt::free(|cs| feed_sequence(&self.wdt, cs));
    }
}

/// Internal feed sequence that only runs when Cupkake promises he wont bite off your hand
#[inline(always)]
fn feed_sequence(wdt: &crate::pac::Wdt0, _cs: &interrupt::CriticalSection) {
    wdt.rst().write(|w| unsafe {
        w.bits(0xA5);
        w.bits(0x5A);
        return w;
    });
}
