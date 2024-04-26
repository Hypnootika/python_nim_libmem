import os
import re
from pathlib import Path
regex_comments = re.compile(r"\/\*.*?\*\/", re.DOTALL)
regex_multi = r"#ifdef __cplusplus\n\}|#ifndef.*|#define.*|#ifdef.*|#	.*|#else.*|#endif.*|extern \"C\" {"
retypes = {
    "lm_void_t": "void",
    "lm_bool_t": "bool",
    "lm_byte_t": "uint8_t",
    "lm_address_t": "uintptr_t",
    "lm_size_t": "size_t",
    "lm_char_t": "char",
    "lm_string_t": "const char*",
    "lm_bytearray_t": "const uint8_t*",
    "lm_pid_t": "uint32_t",
    "lm_tid_t": "uint32_t",
    "lm_time_t": "uint64_t",
    "lm_prot_t": "uint32_t",
    "lm_process_t": "Process_t",
    "lm_thread_t": "Thread_t",
    "lm_module_t": "Module_t",
    "lm_segment_t": "Segment_t",
    "lm_symbol_t": "Symbol_t",
    "lm_inst_t": "Instruction_t",
    "lm_arch_t": "uint32_t",
    "lm_vmt_entry_t": "VmtEntry_t",
    "lm_vmt_t": "Vmt_t",
    "LM_INST_MAX": "16",
    "LM_PATH_MAX": "4096",

}
regex_typedefs = r"typedef enum \{.*?\;|typedef.*?;|enum {(.*\n)*?\};"
leftover = r"typedef \n"


def resup(data):
    data = re.sub(regex_comments, "", data)
    data = re.sub(regex_multi, "", data)
    for key, value in retypes.items():
        data = re.sub(key, value, data)
    data = re.sub(regex_typedefs, "", data)
    data = re.sub(leftover, "", data)
    data = re.sub(r"LM_CALL\n", "", data)
    data = re.sub(r"LM_API |LM_CALL ", "", data)
    data = re.sub(r"(\n\s)", "\n", data)
    data = re.sub(r"(\w+)\s+(\S+)", "\\g<1> \\g<2>", data)
    data = re.sub(r"(\n)+", "\n", data)
    data = re.sub(r"\s\s+", " ", data)
    data = data.replace("const", "")
    data = data.replace("uint64_t start_time; char path[4096];", "uint64_t start_time;\nchar path[4096];")
    data = data.replace("#include <stdlib.h>\n#include <stdint.h>", "")
    data = "#include <stdlib.h>\n#include <stdint.h>\ntypedef int bool;\n" + data


    return data


def main():
    current_dir = Path(__file__).resolve().parent
    gen_file = current_dir.parent.joinpath("libmem\\libmem.h")
    output_file = current_dir.parent.joinpath("libmem_cleaned.h")
    with open(gen_file, "r") as f:
        data = f.read()
        data = resup(data)
    with open(output_file, "w") as f:
        f.write(data)


if __name__ == "__main__":
    main()
