PROTNONE: int
PROTR: int
PROTW: int
PROTX: int
PROTXR: int
PROTXW: int
PROTRW: int
PROTXRW: int
ARCHARM: int
ARCHARM64: int
ARCHMIPS: int
ARCHX86: int
ARCHPPC: int
ARCHSPARC: int
ARCHSYSZ: int
ARCHEVM: int
ARCHMAX: int

def from_char_array_tostr(c_array) -> str: ...

class Process:
    def __init__(self, process) -> None: ...
    @property
    def name(self): ...
    @property
    def pid(self): ...
    @property
    def ppid(self): ...
    @property
    def bits(self): ...
    @property
    def start_time(self): ...
    @property
    def path(self): ...

class Thread:
    def __init__(self, thread) -> None: ...
    @property
    def tid(self): ...
    @property
    def pid(self): ...

class Module:
    def __init__(self, module) -> None: ...
    @property
    def base(self): ...
    @property
    def size(self): ...
    @property
    def path(self): ...
    @property
    def name(self): ...

class Symbol:
    def __init__(self, symbol) -> None: ...
    @property
    def address(self): ...
    @property
    def name(self): ...

class Segment:
    def __init__(self, segment) -> None: ...
    @property
    def base(self): ...
    @property
    def size(self): ...
    @property
    def prot(self): ...

class Instruction:
    def __init__(self, instruction) -> None: ...
    @property
    def address(self): ...
    @property
    def size(self): ...
    @property
    def mnemonic(self): ...
    @property
    def op_str(self): ...
    @property
    def bytes(self): ...

class Vmt:
    def __init__(self, vmt) -> None: ...
    @property
    def vtable(self): ...
    @property
    def hkentries(self): ...

def enum_processes() -> list[Process]: ...
def get_process() -> Process: ...
def get_processex(pid: int) -> Process: ...
def find_process(processname: str) -> Process: ...
def is_process_alive(process: Process) -> bool: ...
def get_bits() -> int: ...
def get_systembits() -> int: ...
def enum_threads() -> list[Thread]: ...
def enum_threadsex(process: Process) -> list[Thread]: ...
def get_thread() -> Thread: ...
def get_threadex(process: Process) -> Thread: ...
def get_thread_process(thread: Thread) -> Process: ...
def enum_modules() -> list[Module]: ...
def enum_modulesex(process: Process) -> list[Module]: ...
def find_module(name: str) -> Module: ...
def find_moduleex(process: Process, name: str) -> Module: ...
def load_module(path: str) -> bool: ...
def load_moduleex(process: Process, path: str) -> bool: ...
def unload_module(module: Module) -> bool: ...
def unload_moduleex(process: Process, module: Module) -> bool: ...
def enum_symbols(module: Module) -> list[Symbol]: ...
def enum_segments() -> list[Segment]: ...
def enum_segmentsex(process: Process) -> list[Segment]: ...
def find_segment(address: int) -> Segment: ...
def find_segmentex(process: Process, address: int) -> Segment: ...
def set_memory(dest: int, byte: bytes, size: int) -> int: ...
def set_memoryex(process: Process, dest: int, byte: bytes, size: int) -> int: ...
def prot_memory(address: int, size: int, prot: int) -> bool: ...
def prot_memoryex(process: Process, address: int, size: int, prot: int) -> bool: ...
def read_uint8(address: int) -> int: ...
def read_uint16(address: int) -> int: ...
def read_uint32(address: int) -> int: ...
def read_uint64(address: int) -> int: ...
def read_int8(address: int) -> int: ...
def read_int16(address: int) -> int: ...
def read_int32(address: int) -> int: ...
def read_int64(address: int) -> int: ...
def read_float32(address: int) -> int: ...
def read_float64(address: int) -> int: ...
def read_uint8ex(process: Process, address: int) -> bytes: ...
def read_uint16ex(process: Process, address: int) -> int: ...
def read_uint32ex(process: Process, address: int) -> int: ...
def read_uint64ex(process: Process, address: int) -> int: ...
def read_int8ex(process: Process, address: int) -> int: ...
def read_int16ex(process: Process, address: int) -> int: ...
def read_int32ex(process: Process, address: int) -> int: ...
def read_int64ex(process: Process, address: int) -> int: ...
def read_float32ex(process: Process, address: int) -> int: ...
def read_float64ex(process: Process, address: int) -> int: ...
def write_uint8(address: int, value: bytes) -> bool: ...
def write_uint16(address: int, value: int) -> bool: ...
def write_uint32(address: int, value: int) -> bool: ...
def write_uint64(address: int, value: int) -> bool: ...
def write_int8(address: int, value: int) -> bool: ...
def write_int16(address: int, value: int) -> bool: ...
def write_int32(address: int, value: int) -> bool: ...
def write_int64(address: int, value: int) -> bool: ...
def write_float32(address: int, value: int) -> bool: ...
def write_float64(address: int, value: int) -> bool: ...
def write_uint8ex(process: Process, address: int, value: bytes) -> bool: ...
def write_uint16ex(process: Process, address: int, value: int) -> bool: ...
def write_uint32ex(process: Process, address: int, value: int) -> bool: ...
def write_uint64ex(process: Process, address: int, value: int) -> bool: ...
def write_int8ex(process: Process, address: int, value: int) -> bool: ...
def write_int16ex(process: Process, address: int, value: int) -> bool: ...
def write_int32ex(process: Process, address: int, value: int) -> bool: ...
def write_int64ex(process: Process, address: int, value: int) -> bool: ...
def write_float32ex(process: Process, address: int, value: int) -> bool: ...
def write_float64ex(process: Process, address: int, value: int) -> bool: ...
def alloc_memory(size: int, prot: int) -> int: ...
def alloc_memoryex(process: Process, size: int, prot: int) -> int: ...
def free_memory(alloc: int, size: int) -> bool: ...
def free_memoryex(process: Process, alloc: int, size: int) -> bool: ...
def deep_pointer(base: int, offsets: list[int]) -> int: ...
def deep_pointerex(process: Process, base: int, offsets: list[int]) -> int: ...
def pointer_chain_64(process: Process, base: int, offsets: list[bytes]) -> int: ...
def data_scan(data: list[bytes], address: int, scansize: int) -> int: ...
def data_scanex(process: Process, data: list[bytes], address: int, scansize: int) -> int: ...
def pattern_scan(pattern: list[bytes], mask: str, address: int, scansize: int) -> int: ...
def pattern_scanex(process: Process, pattern: list[bytes], mask: str, address: int, scansize: int) -> int: ...
def sig_scan(signature: str, address: int, scansize: int) -> int: ...
def sig_scanex(process: Process, signature: str, address: int, scansize: int) -> int: ...
def find_symbol_address(module: Module, symbolname: str) -> int: ...
def assemble(code: str) -> Instruction: ...
def assembleex(code: str, runtimeaddress: int, arch: int = 3, bits: int = 64) -> int: ...
def free_payload(payload: list[bytes]): ...
def disassemble(machinecode: list[bytes]) -> Instruction: ...
def free_instructions(instructions: list[Instruction]): ...
def code_length(machinecode: int, minlength: int) -> int: ...
def code_lengthex(process: Process, machinecode: int, minlength: int) -> int: ...
def hook_code(fromarg: int, to: int) -> tuple[int, int]: ...
def hook_codeex(process: Process, fromarg: int, to: int) -> tuple[int, int]: ...
def unhook_code(fromarg: int, trampoline: int, size: int) -> bool: ...
def unhook_codeex(process: Process, fromarg: int, trampoline: int, size: int) -> bool: ...
