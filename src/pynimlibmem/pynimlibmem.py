import pynimlibmem as libmem

PROTNONE = 0
PROTR = 1
PROTW = 2
PROTX = 4
PROTXR = 5
PROTXW = 6
PROTRW = 3
PROTXRW = 7
ARCHARM = 0
ARCHARM64 = 1
ARCHMIPS = 2
ARCHX86 = 3
ARCHPPC = 4
ARCHSPARC = 5
ARCHSYSZ = 6
ARCHEVM = 7
ARCHMAX = 8


def from_char_array_tostr(c_array) -> str:
    try:
        end_index = c_array.index(0)
    except ValueError:
        end_index = len(c_array)
    return ''.join(chr(c) for c in c_array[:end_index] if 0 <= c <= 0x10FFFF)


class Process:
    def __init__(self, process):
        self._name = from_char_array_tostr(process["name"])
        self._path = from_char_array_tostr(process["path"])
        self._ppid = process["ppid"]
        self._pid = process["pid"]
        self._bits = process["bits"]
        self._start_time = process["starttime"]

    def __repr__(self):
        return (f"Name: {self._name}\n"
                f"ppid: {self._ppid}\n"
                f"pid: {self._pid}\n"
                f"bits: {self._bits}\n"
                f"starttime: {self._start_time}\n"
                f"path: {self._path}")

    @property
    def name(self):
        return self._name

    @property
    def pid(self):
        return self._pid

    @property
    def ppid(self):
        return self.ppid

    @property
    def bits(self):
        return self._bits

    @property
    def start_time(self):
        return self._start_time

    @property
    def path(self):
        return self._path


class Thread:
    def __init__(self, thread):
        self._tid = thread["tid"]
        self._owner_pid = thread["ownerpid"]

    def __repr__(self):
        return f"Thread: (Tid {self._tid} Pid: {self._owner_pid})"

    @property
    def tid(self):
        return self._tid

    @property
    def pid(self):
        return self._owner_pid


class Module:
    def __init__(self, module):
        self._base = module["base"]
        self._size = module["size"]
        self._path = from_char_array_tostr(module["path"])
        self._name = from_char_array_tostr(module["name"])

    def __repr__(self):
        return (f"Name: {self.name}\n"
                f"Path: {self.path}\n"
                f"Base: {self.base}\n"
                f"Size: {self.size}")

    @property
    def base(self):
        return self._base

    @property
    def size(self):
        return self._size

    @property
    def path(self):
        return self._path

    @property
    def name(self):
        return self._name


class Symbol:
    def __init__(self, symbol):
        self._address = symbol["memoryaddress"]
        self._name = symbol["name"]

    def __repr__(self):
        return f"Name: {self.name} Address: {self.address}"

    @property
    def address(self):
        return self._address

    @property
    def name(self):
        return self._name


class Segment:
    def __init__(self, segment):
        self._base = segment["base"]
        self._size = segment["size"]
        self._prot = segment["prot"]

    def __repr__(self):
        return f"Base: {self.base} Size: {self.size} Prot: {self.prot}"

    @property
    def base(self):
        return self._base

    @property
    def size(self):
        return self._size

    @property
    def prot(self):
        return self._prot


class Instruction:
    def __init__(self, instruction):
        self._address: int = instruction["address"]
        self._size: int = instruction["size"]
        self._bytes: list[bytes] = instruction["bytes"]
        self._mnemonic: list[str] = instruction["mnemonic"]
        self._op_str: list[str] = instruction["opstr"]

    def __repr__(self):
        return (f"Address: {self.address}\n"
                f"Size: {self.size}\n"
                f"Bytes: {self.bytes}\n"
                f"Mnemonic: {self.mnemonic}\n"
                f"op_str: {self.op_str}\n"
                )

    @property
    def address(self):
        return self._address

    @property
    def size(self):
        return self._size

    @property
    def mnemonic(self):
        return self._mnemonic

    @property
    def op_str(self):
        return self._op_str

    @property
    def bytes(self):
        return self._bytes


class Vmt:
    def __init__(self, vmt):
        self._vtable = vmt["vtable"]
        self._hkentries = vmt["hkentries"]

    def __repr__(self):
        return (f"Vtable: {self.vtable},\n"
                f"Hooked Entries: {self.hkentries}")

    @property
    def vtable(self):
        return self._vtable

    @property
    def hkentries(self):
        return self._hkentries


# Checked.
def enum_processes() -> list[Process]:
    return [Process(process) for process in libmem.enum_processes()]


# Checked.
def get_process() -> Process:
    return Process(libmem.get_process())


# Checked.
def get_processex(pid: int) -> Process:
    return Process(libmem.get_processex(pid))


# Checked.
def find_process(processname: str) -> Process:
    return Process(libmem.find_process(processname))


# Checked.
def is_process_alive(process: Process) -> bool:
    return libmem.is_process_alive(process)


# Checked.
def get_bits() -> int:
    return libmem.get_bits()


# Checked.
def get_systembits() -> int:
    return libmem.get_system_bits()


# Checked.
def enum_threads() -> list[Thread]:
    return [Thread(thread) for thread in libmem.enum_threads()]


# Checked. But doesn't work.
def enum_threadsex(process: Process) -> list[Thread]:
    return libmem.enum_threadsex(process)


# Checked.
def get_thread() -> Thread:
    return Thread(libmem.get_thread())


# Checked. But doesn't work. ### WORKS WITHOUT WRAPPING IT INTO A CLASS ->
# get_threadex(libmem.get_process())
def get_threadex(process: Process) -> Thread:
    return Thread(libmem.get_threadex(process))


# Checked. But doesn't work. #### WORKS WITHOUT WRAPPING IT INTO A CLASS ->
# get_thread_process(libmem.get_threadex(libmem.get_process()))
def get_thread_process(thread: Thread) -> Process:
    return Process(libmem.get_thread_process(thread))


# Checked.
def enum_modules() -> list[Module]:
    return [Module(module) for module in libmem.enum_modules()]


# Checked.
def enum_modulesex(process: Process) -> list[Module]:
    return [Module(module) for module in libmem.enum_modulesex(process)]


# Checked.
def find_module(name: str) -> Module:
    return Module(libmem.find_module(name))


# Checked.
def find_moduleex(process: Process, name: str) -> Module:
    return Module(libmem.find_moduleex(process, name))


# Checked.
def load_module(path: str) -> bool:
    return libmem.load_module(path)


# Checked. But doesn't work. ### WORKS WITHOUT WRAPPING IT INTO A CLASS ->
# load_moduleex(libmem.get_process(), "C:\\Windows\\System32\\ntdll.dll"))
def load_moduleex(process: Process, path: str) -> bool:
    return libmem.load_moduleex(process, path)


# Checked. But doesn't work. ### Still doesnt even without wrapping it into a class.
def unload_module(module: Module) -> bool:
    return libmem.unload_module(module)


# Checked. But doesn't work. ### Still doesnt even without wrapping it into a class.
def unload_moduleex(process: Process, module: Module) -> bool:
    return libmem.unload_moduleex(process, module)


# Checked. But doesn't work. ### Still doesnt even without wrapping it into a class.
def enum_symbols(module: Module) -> list[Symbol]:
    return [Symbol(symbol) for symbol in libmem.enum_symbols(module)]


# Checked.
def enum_segments() -> list[Segment]:
    return [Segment(segment) for segment in libmem.enum_segments()]


# Checked. But doesn't work. ### WORKS WITHOUT WRAPPING IT INTO A CLASS ->
# enum_segmentsex(libmem.get_process())
def enum_segmentsex(process: Process) -> list[Segment]:
    return [Segment(segment) for segment in libmem.enum_segmentsex(process)]


# Checked.
def find_segment(address: int) -> Segment:
    return Segment(libmem.find_segment(address))


# Checked. But doesn't work. ### Nope, still doesn't work.
def find_segmentex(process: Process, address: int) -> Segment:
    return Segment(libmem.find_segmentex(process, address))


# Checked. But doesn't work. Throws SIGSEGV. ### Still big nope.
def set_memory(dest: int, byte: bytes, size: int) -> int:
    return libmem.set_memory(dest, byte, size)


# Works.
# print(set_memoryex(libmem.get_process(), find_moduleex(libmem.get_process(), "ntdll.dll").base + 0x1000, 0x90, 8))
def set_memoryex(process: Process, dest: int, byte: bytes, size: int) -> int:
    return libmem.set_memoryex(process, dest, byte, size)


# Checked.
def prot_memory(address: int, size: int, prot: int) -> bool:
    return libmem.prot_memory(address, size, prot)


# Not checked.
def prot_memoryex(process: Process, address: int, size: int, prot: int) -> bool:
    return libmem.prot_memoryex(process, address, size, prot)


# Checked.
def read_uint8(address: int) -> int:
    return libmem.read_uint8(address)


# Checked.
def read_uint16(address: int) -> int:
    return libmem.read_uint16(address)


# Checked.
def read_uint32(address: int) -> int:
    return libmem.read_uint32(address)


# Checked.
def read_uint64(address: int) -> int:
    return libmem.read_uint64(address)


# Checked.
def read_int8(address: int) -> int:
    return libmem.read_int8(address)


def read_int16(address: int) -> int:
    return libmem.read_int16(address)


def read_int32(address: int) -> int:
    return libmem.read_int32(address)


# Checked.
def read_int64(address: int) -> int:
    return libmem.read_int64(address)


# Checked.
def read_float32(address: int) -> int:
    return libmem.read_float32(address)


# Checked.
def read_float64(address: int) -> int:
    return libmem.read_float64(address)


# Checked.
def read_uint8ex(process: Process, address: int) -> bytes:
    return libmem.read_uint8ex(process, address)


# Checked.
def read_uint16ex(process: Process, address: int) -> int:
    return libmem.read_uint16ex(process, address)


# Checked.
def read_uint32ex(process: Process, address: int) -> int:
    return libmem.read_uint32ex(process, address)


# Checked.
def read_uint64ex(process: Process, address: int) -> int:
    return libmem.read_uint64ex(process, address)


# Checked.
def read_int8ex(process: Process, address: int) -> int:
    return libmem.read_int8ex(process, address)


# Checked.
def read_int16ex(process: Process, address: int) -> int:
    return libmem.read_int16ex(process, address)


# Checked.
def read_int32ex(process: Process, address: int) -> int:
    return libmem.read_int32ex(process, address)


# Checked.
def read_int64ex(process: Process, address: int) -> int:
    return libmem.read_int64ex(process, address)


# Checked.
def read_float32ex(process: Process, address: int) -> int:
    return libmem.read_float32ex(process, address)


# Checked.
def read_float64ex(process: Process, address: int) -> int:
    return libmem.read_float64ex(process, address)


# Checked.
def write_uint8(address: int, value: bytes) -> bool:
    return libmem.write_uint8(address, value)


# Checked.
def write_uint16(address: int, value: int) -> bool:
    return libmem.write_uint16(address, value)


# Checked.
def write_uint32(address: int, value: int) -> bool:
    return libmem.write_uint32(address, value)


# Checked.
def write_uint64(address: int, value: int) -> bool:
    return libmem.write_uint64(address, value)


# Checked.
def write_int8(address: int, value: int) -> bool:
    return libmem.write_int8(address, value)


# Checked.
def write_int16(address: int, value: int) -> bool:
    return libmem.write_int16(address, value)


# Checked.
def write_int32(address: int, value: int) -> bool:
    return libmem.write_int32(address, value)


# Checked.
def write_int64(address: int, value: int) -> bool:
    return libmem.write_int64(address, value)


# Checked.
def write_float32(address: int, value: int) -> bool:
    return libmem.write_float32(address, value)


# Checked.
def write_float64(address: int, value: int) -> bool:
    return libmem.write_float64(address, value)


# Unsure.
# Checked.
def write_uint8ex(process: Process, address: int, value: bytes) -> bool:
    return libmem.write_uint8ex(process, address, value)


# Checked.
def write_uint16ex(process: Process, address: int, value: int) -> bool:
    return libmem.write_uint16ex(process, address, value)


# Checked.
def write_uint32ex(process: Process, address: int, value: int) -> bool:
    return libmem.write_uint32ex(process, address, value)


# Checked.
def write_uint64ex(process: Process, address: int, value: int) -> bool:
    return libmem.write_uint64ex(process, address, value)


# Checked.
def write_int8ex(process: Process, address: int, value: int) -> bool:
    return libmem.write_int8ex(process, address, value)


# Checked.
def write_int16ex(process: Process, address: int, value: int) -> bool:
    return libmem.write_int16ex(process, address, value)


# Checked.
def write_int32ex(process: Process, address: int, value: int) -> bool:
    return libmem.write_int32ex(process, address, value)


# Checked.
def write_int64ex(process: Process, address: int, value: int) -> bool:
    return libmem.write_int64ex(process, address, value)


# Checked.
def write_float32ex(process: Process, address: int, value: int) -> bool:
    return libmem.write_float32ex(process, address, value)


# Checked.
def write_float64ex(process: Process, address: int, value: int) -> bool:
    return libmem.write_float64ex(process, address, value)


# Checked.
def alloc_memory(size: int, prot: int) -> int:
    return libmem.alloc_memory(size, prot)


# Checked.
def alloc_memoryex(process: Process, size: int, prot: int) -> int:
    return libmem.alloc_memoryex(process, size, prot)


# Ignored
def free_memory(alloc: int, size: int) -> bool:
    return libmem.free_memory(alloc, size)


# Ignored
def free_memoryex(process: Process, alloc: int, size: int) -> bool:
    return libmem.free_memoryex(process, alloc, size)


# Later
def deep_pointer(base: int, offsets: list[int]) -> int:
    return libmem.deep_pointer(base, offsets)


# Later
def deep_pointerex(process: Process, base: int, offsets: list[int]) -> int:
    return libmem.deep_pointerex(process, base, offsets)


# Known to work.
def pointer_chain_64(process: Process, base: int, offsets: list[bytes]) -> int:
    return libmem.pointer_chain_64(process, base, offsets)


# later
def data_scan(data: list[bytes], address: int, scansize: int) -> int:
    return libmem.data_scan(data, address, scansize)


# later
def data_scanex(process: Process, data: list[bytes], address: int, scansize: int) -> int:
    return libmem.data_scanex(process, data, address, scansize)


# later
def pattern_scan(pattern: list[bytes], mask: str, address: int, scansize: int) -> int:
    return libmem.pattern_scan(pattern, mask, address, scansize)


# later
def pattern_scanex(process: Process, pattern: list[bytes], mask: str, address: int, scansize: int) -> int:
    return libmem.pattern_scanex(process, pattern, mask, address, scansize)


# later
def sig_scan(signature: str, address: int, scansize: int) -> int:
    return libmem.sig_scan(signature, address, scansize)


# later
def sig_scanex(process: Process, signature: str, address: int, scansize: int) -> int:
    return libmem.sig_scanex(process, signature, address, scansize)


# Checked.
# def get_architecture() -> int:
#     return libmem.get_architecture()


# always 0xffffffffffffffff ### Still always 0xffffffffffffffff
def find_symbol_address(module: Module, symbolname: str) -> int:
    return libmem.find_symbol_address(module, symbolname)


# Checked. But doesn't work.
# Works:
# print(libmem.assemble("mov eax, 0x1234"))
# print(assemble("mov eax, 0x1234"))
def assemble(code: str) -> Instruction:
    return Instruction(libmem.assemble(code))


# Checked. But doesn't work. ### Semms to work now.
def assembleex(code: str, runtimeaddress: int, arch: int = 3, bits: int = 64) -> int:
    return libmem.assembleex(code, runtimeaddress, arch, bits)


# Ignored
def free_payload(payload: list[bytes]):
    return libmem.free_payload(payload)


# later
def disassemble(machinecode: list[bytes]) -> Instruction:
    return Instruction(libmem.disassemble(machinecode))


# Ignored
def free_instructions(instructions: list[Instruction]):
    return [Instruction(instruction) for instruction in libmem.free_instructions(instructions)]


# Ignored
def code_length(machinecode: int, minlength: int) -> int:
    return libmem.code_length(machinecode, minlength)


# Ignored
def code_lengthex(process: Process, machinecode: int, minlength: int) -> int:
    return libmem.code_lengthex(process, machinecode, minlength)


# later
def hook_code(fromarg: int, to: int) -> tuple[int, int]:
    return libmem.hook_code(fromarg, to)


# later
def hook_codeex(process: Process, fromarg: int, to: int) -> tuple[int, int]:
    return libmem.hook_codeex(process, fromarg, to)


# later
def unhook_code(fromarg: int, trampoline: int, size: int) -> bool:
    return libmem.unhook_code(fromarg, trampoline, size)


# later
def unhook_codeex(process: Process, fromarg: int, trampoline: int, size: int) -> bool:
    return libmem.unhook_codeex(process, fromarg, trampoline, size)
