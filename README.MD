# libmem Nim Bindings

This README provides information on how to integrate and use the Nim bindings for the `libmem` C library in your Nim or Python projects. These bindings allow Nim or Python applications to leverage the functionality of `libmem`, a C library, with ease. The bindings were primarily generated using Futhark and subsequently refined for better integration and usage in Nim.

## Quick Start

To use the `libmem` bindings in your Nim project, follow these simple steps:

Prebuild and formatted release-like version is in the "manualwrap" folder.
If you want to play around with the generators either check out the Nimble and Futhark script or just call `nimble buildall` in the root directory.

## Contributions

Contributions to the `libmem` Nim bindings are welcome. Whether it's improving the wrapper, adding more tests, or enhancing documentation, your input is valuable. Please submit pull requests or open issues on the project's repository to contribute.

## License

The `libmem` Nim bindings are licensed under the MIT License. You are free to use, modify, and distribute the bindings as you see fit. For more information, please refer to the `LICENSE`.txt file in the project's repository.

## Acknowledgements

Special thanks to the developers of Futhark for providing the tooling that facilitated the generation of these bindings, and to all contributors who have refined and tested the bindings to ensure they meet the needs of Nim developers.
And also thank you, @Rdbo, for the original C library.

https://github.com/rdbo/libmem
https://github.com/PMunch/futhark