# libmem Nim Bindings

This README provides information on how to integrate and use the Nim bindings for the `libmem` C library in your Nim or Python projects. These bindings allow Nim or Python applications to leverage the functionality of `libmem`, a C library, with ease. The bindings were primarily generated using Futhark and subsequently refined for better integration and usage in Nim.

## Quick Start

To use the `libmem` bindings in your Nim project, follow these simple steps:

Prebuild and formatted release-like version is in the "manualwrap" folder.
If you want to play around with the generators either check out the Nimble and Futhark script or just call `nimble buildall` in the root directory.

## Contributions

Contributions to the `libmem` Nim bindings are welcome. Whether it's improving the wrapper, adding more tests, or enhancing documentation, your input is valuable. Please submit pull requests or open issues on the project's repository to contribute.

## Building

# Prerequisites
Before you can build and use **python_nim_libmem**, you'll need to have Python and Nim installed on your system. Ensure that you have the following:

- Python (3.10 or newer) (soon needed)
- Nim (2.0.0 or newer)
- nimpy package (nimble install nimpy)

First, clone the **python_nim_libmem** repository to your local machine:

```bash
git clone https://github.com/Hypnootika/python_nim_libmem.git
cd python_nim_libmem
```

### 2. Run Nimble Tasks
Use Nimble, Nim's package manager, to perform the necessary build tasks:

Simply use:
```bash
nimble buildall
```

That will: 
- Download libmem if not present.
- Invoke a C-Source cleanup script that makes parsing more easy
- Invoke Futhark on the cleaned source
- Invoke a Python script that formats and arranges the generated output. Finally deleting all steps.
- Be aware that there is an up to date backup copy in the manualwrap folder, since the toolchain is not providing what i manually added.

# (Python steps soon)

## Todo
Python Integration and tests

### Contributing
Contributions to python_nim_libmem are welcome.

## License

The `libmem` Nim bindings are licensed under the MIT License. You are free to use, modify, and distribute the bindings as you see fit. For more information, please refer to the `LICENSE`.txt file in the project's repository.

## Acknowledgements

Special thanks to the developers of Futhark for providing the tooling that facilitated the generation of these bindings, and to all contributors who have refined and tested the bindings to ensure they meet the needs of Nim developers.
And also thank you, @Rdbo, for the original C library.
And Futhark(@PMunch) for the powerful generator.

https://github.com/rdbo/libmem
https://github.com/PMunch/futhark
