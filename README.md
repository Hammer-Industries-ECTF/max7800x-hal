# max78000-hal
This is a Hardware Abstraction Layer (HAL) for the MAX78000 microcontroller. The HAL is built on top of a Peripheral Access Crate (PAC), [`max78000-pac`](https://github.com/sigpwny/max78000-pac), which provides low-level access to the MAX78000's registers. The HAL provides a higher-level interface to the MAX78000's peripherals, making it easier to write applications.

A Board Support Package (BSP) for the MAX78000FTHR is also being developed alongside this HAL. More details will be released soon.

## Roadmap
See the [roadmap](https://github.com/sigpwny/max78000-hal/issues/1) to see current progress and future plans.

> [!NOTE]  
> This HAL is under active development. As a result, the API is volatile and subject to change. Be sure to refer to the [changelog](https://github.com/sigpwny/max78000-hal/releases) for breaking changes.

## Getting Started
Coming Soon™️

### Installing Rust
Coming Soon™️

### Flashing
Coming Soon™️, but the gist is that it's currently done via Analog Device's custom OpenOCD fork and `arm-none-eabi-gdb`. This is more relevant to the BSP, but it's worth mentioning here.

### Debugging
Coming Soon™️

## Documentation
Documentation for this HAL can be obtained by building the docs with `cargo`:

```sh
cargo doc --open
```

## License
The contents of this repository are dual-licensed under the *MIT OR Apache 2.0* License. This means you may choose either the MIT license or the Apache-2.0 license when using this code. See [`LICENSE-MIT`](./LICENSE-MIT) or [`LICENSE-APACHE`](./LICENSE-APACHE) for each of these licenses.

Unless you explicitly state otherwise, any contribution you intentionally submit
for inclusion in this repository, as defined in the Apache-2.0 license, shall be
dual-licensed as stated above without any additional terms or conditions.

Copyright (c) 2025 SIGPwny