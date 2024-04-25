import re
import os

current_dir = os.path.dirname(os.path.abspath(__file__))
gen_file = os.path.join(current_dir, "nimlibmem.nim")

removethis = """when 0 is static:
  const
    Null* = 0                
else:
  let Null* = 0              
when 4096 is static:
  const
    Pathmax* = 4096          
else:
  let Pathmax* = 4096        
when 16 is static:
  const
    Instmax* = 16            
else:
  let Instmax* = 16  """

andthis = """type
  enumbool* {.size: sizeof(cint).} = enum
    False = 0, True = 1
type
  Apiimport* {.incompleteStruct.} = object"""

constorgi = """const
  Protnone* = cint(0)
const
  Protr* = cint(1)
const
  Protw* = cint(2)
const
  Protx* = cint(4)
const
  Protxr* = cint(5)
const
  Protxw* = cint(6)
const
  Protrw* = cint(3)
const
  Protxrw* = cint(7)
const
  Archarm* = cint(0)
const
  Archarm64* = cint(1)
const
  Archmips* = cint(2)
const
  Archx86* = cint(3)
const
  Archppc* = cint(4)
const
  Archsparc* = cint(5)
const
  Archsysz* = cint(6)
const
  Archevm* = cint(7)
const
  Archmax* = cint(8)"""

constnew = """const
  Protnone* = uint32(0)
  Protr* = uint32(1)
  Protw* = uint32(2)
  Protx* = uint32(4)
  Protxr* = uint32(5)
  Protxw* = uint32(6)
  Protrw* = uint32(3)
  Protxrw* = uint32(7)
  Archarm* = uint32(0)
  Archarm64* = uint32(1)
  Archmips* = uint32(2)
  Archx86* = uint32(3)
  Archppc* = uint32(4)
  Archsparc* = uint32(5)
  Archsysz* = uint32(6)
  Archevm* = uint32(7)
  Archmax* = uint32(8)
"""

wrapperfuncs = """
proc enumprocesses*(): seq[Process] = discard originalenumprocesses(cb, result.addr)

proc getprocess*(): Process =  discard originalgetprocess(addr result)

proc getprocessex*(pid: uint32): Process = discard originalgetprocessex(pid, addr result)

proc findprocess*(processname: string): Process = discard originalfindprocess(processname, result.addr)

proc isprocessalive*(process: Process): bool = return originalisprocessalive(process.addr)

proc getbits*(): csize_t = return originalgetbits()

proc getsystembits*(): csize_t = return originalgetsystembits()

proc enumthreads*(): seq[Thread] = discard originalenumthreads(cb, result.addr)

proc enumthreadsex*(process: Process): seq[Thread] = discard originalenumthreadsex(process.addr, cb, result.addr)

proc getthread*(): Thread= discard originalgetthread(result.addr)

proc getthreadex*(process: Process): Thread= discard originalgetthreadex(process.addr, addr result)

proc getthreadprocess*(thread: Thread): Process = discard originalgetthreadprocess(thread.addr, result.addr)

proc enummodules*(): seq[Module] = discard originalenummodules(cb, result.addr)

proc enummodulesex*(process: Process): seq[Module] = discard originalenummodulesex(process.addr, cb, result.addr)

proc findmodule*(name: cstring): Module = discard originalfindmodule(name, addr result)

proc findmoduleex*(process: Process; name: cstring): Module = discard originalfindmoduleex(process.addr, name, result.addr)

proc loadmodule*(path: cstring): Module = discard originalloadmodule(path, result.addr)

proc loadmoduleex*(process: Process; path: cstring): Module = discard originalloadmoduleex(process.addr, path, result.addr)

proc unloadmodule*(module: Module): bool  = return originalunloadmodule(module.addr)

proc unloadmoduleex*(process: Process; module: Module): bool = return originalunloadmoduleex(process.addr, module.addr)

proc enumsymbols*(module: Module): seq[Symbol] = discard originalenumsymbols(module.addr, cb, result.addr)

proc findsymboladdress*(module: Module; symbolname: cstring): memoryaddress = return originalfindsymboladdress(module.addr, symbolname)

proc enumsegments*(): seq[Segment] = discard originalenumsegments(cb, result.addr)

proc enumsegmentsex*(process: Process): seq[Segment] = discard originalenumsegmentsex(process.addr, cb, result.addr)

proc findsegment*(address: memoryaddress): Segment = discard originalfindsegment(address, result.addr)

proc findsegmentex*(process: Process; address: memoryaddress): Segment = discard originalfindsegmentex(process.addr, address, result.addr)

proc protmemory*(address: memoryaddress; size: csize_t; prot: prot = Protrw): prot = discard originalprotmemory(address, size, prot, result.addr)

proc protmemoryex*(process: Process; address: memoryaddress; size: csize_t;prot: prot = Protrw): prot = discard originalprotmemoryex(process.addr, address, size, prot, result.addr)

proc readmemory*[T](address: memoryaddress, t: typedesc[T], size: Natural=1): T  =
  when T is typeof(string):
    var st = newSeq[char](size)
    discard originalreadmemory(address, cast[ptr byte](addr st[0]), size.csize_t)
    result = cast[T](st)
  when T is typeof(seq):
    setLen(result, size)
    discard originalreadmemory(address, result[0].addr, size.csize_t)
  else:
    discard originalreadmemory(address, cast[ptr byte](addr result), sizeof(T).csize_t)

proc readmemoryex*[T](process: ptr Process; address: memoryaddress; t: typedesc[T], size: Natural=1): T =
  when T is typeof(string):
    var st = newSeq[char](size)
    discard originalreadmemoryex(process, address, cast[ptr byte](addr st[0]), size.csize_t)
    result = cast[T](st)
  when T is typeof(seq):
    setLen(result, size)
    discard originalreadmemoryex(process, address, result[0].addr, size.csize_t)
  else:
    discard originalreadmemoryex(process, address, cast[ptr byte](addr result), sizeof(T).csize_t)

proc writememory*[T](dest: memoryaddress; data: T): bool =
  if protmemory(dest, sizeof(T).csize_t, Protxrw) != Protnone:
    when T is typeof(SomeInteger):
      if originalwritememory(dest, cast[ptr byte](addr data), sizeof(T).csize_t) == sizeof(T).csize_t:
        result = true
    else:
      if originalwritememory(dest, cast[ptr byte](addr data[0]), sizeof(T).csize_t) == sizeof(T).csize_t:
        result = true
  else:
    raise newException(Defect, "Failed to set memory protection.")

proc writememoryex*[T](process: ptr Process; dest: memoryaddress; data: var T): bool {.discardable.} =
  if protmemoryex(process[], dest, sizeof(T).csize_t, Protxrw) != Protnone:
    when T is typeof(SomeInteger):
      if originalwritememoryex(process, dest, cast[ptr byte](addr data), sizeof(T).csize_t) == sizeof(T).csize_t:
        result = true
    else:
      if originalwritememoryex(process, dest, cast[ptr byte](addr data[0]), sizeof(T).csize_t) == sizeof(T).csize_t:
        result = true
  else:
    raise newException(Defect, "Failed to set memory protection.")

proc setmemory*(dest: memoryaddress; byte: byte; size: csize_t): csize_t = return originalsetmemory(dest, byte, size)

proc setmemoryex*(process: Process; dest: memoryaddress; byte: byte; size: csize_t): csize_t = return originalsetmemoryex(process.addr, dest, byte, size)

proc allocmemory*(size: csize_t; prot: prot): memoryaddress = return originalallocmemory(size, prot)

proc allocmemoryex*(process: Process, size: csize_t; prot: prot): memoryaddress = return originalallocmemoryex(process.addr, size, prot)

proc freememory*(alloc: memoryaddress; size: csize_t): bool = return originalfreememory(alloc, size)

proc freememoryex*(process: Process; alloc: memoryaddress; size: csize_t): bool = return originalfreememoryex(process.addr, alloc, size)

proc pointerchain64*(process: Process, base: memoryaddress, offsets: openArray[SomeInteger]): uint64  =
  result = readmemoryex(process.addr, base, uint64)
  for offset in offsets[0..^2]:
    result = readmemoryex(process.addr, result + offset, uint64)
  result = result + offsets[^1].uint64

proc datascan*(data: seq[byte], address: memoryaddress; scansize: csize_t): memoryaddress = return originaldatascan(data[0].addr, data.len.csize_t, address, scansize)

proc datascanex*(process: Process; data: seq[byte], address: memoryaddress; scansize: csize_t): memoryaddress = return originaldatascanex(process.addr, data[0].addr, data.len.csize_t, address, scansize)

proc patternscan*(pattern: openArray[uint8], mask: cstring, address: memoryaddress;scansize: csize_t): memoryaddress = return originalpatternscan(pattern[0].addr, mask, address, scansize)

proc patternscanex*(process: Process; pattern: openArray[uint8], mask: cstring;address: memoryaddress; scansize: csize_t): memoryaddress = return originalpatternscanex(process.addr, pattern[0].addr, mask, address, scansize)

proc sigscan*(signature: cstring; address: memoryaddress; scansize: csize_t): memoryaddress = return originalsigscan(signature, address, scansize)

proc sigscanex*(process: Process; signature: cstring; address: memoryaddress;scansize: csize_t): memoryaddress = return originalsigscanex(process.addr, signature, address, scansize)

proc getarchitecture*(): arch = return originalgetarchitecture()

proc freepayload*(payload: ptr byte): void = freepayload(payload)

proc assemble*(code: cstring): Instruction = discard originalassemble(code, result.addr)

proc assembleex*(code: cstring, arch: arch= getarchitecture(), bits: csize_t= getBits(), runtimeaddress: memoryaddress): csize_t = (var res: ptr byte; originalassembleex(code, arch, bits, runtimeaddress, addr res))

proc disassemble*(machinecode: openArray[byte]): Instruction = discard originaldisassemble(cast[memoryaddress](machinecode[0].addr), result.addr)

proc disassembleex*(machine_code: openArray[byte], address: memoryaddress, maxsize:  csize_t=16,  arch: arch= Archx86, bits: csize_t= 64.csize_t,): ptr Instruction = discard originaldisassembleex(machine_code[0], arch, bits, maxsize, 1, address, result.addr)

proc freeinstructions*(instructions: Instruction): void= originalfreeinstructions(instructions.addr)

proc codelength*(machinecode: memoryaddress; minlength: csize_t): csize_t = return originalcodelength(machinecode, minlength)

proc codelengthex*(process: Process; machinecode: memoryaddress; minlength: csize_t): csize_t = return originalcodelengthex(process.addr, machinecode, minlength)

proc hookcode*(fromaddress: memoryaddress, toaddress: memoryaddress): memoryaddress = discard originalhookcode(fromaddress, toaddress, result.addr)

proc hookcodeex*(process: Process; fromarg: memoryaddress; to: memoryaddress): memoryaddress = discard originalhookcodeex(process.addr, fromarg, to, result.addr)

proc unhookcode*(fromarg: memoryaddress; trampoline: memoryaddress; size: csize_t): bool = return originalunhookcode(fromarg, trampoline, size)

proc unhookcodeex*(process: Process; fromarg: memoryaddress;trampoline: memoryaddress; size: csize_t): bool = return originalunhookcodeex(process.addr, fromarg, trampoline, size)

proc vmtnew*(vtable: memoryaddress): Vmt = discard originalvmtnew(vtable.addr, addr result)

proc vmthook*(vmt: Vmt; fromfnindex: csize_t; to: memoryaddress): bool = originalvmthook(vmt.addr, fromfnindex, to)

proc vmtunhook*(vmt: Vmt; fnindex: csize_t): void= originalvmtunhook(vmt.addr, fnindex)

proc vmtgetoriginal*(vmt: Vmt; fnindex: csize_t): memoryaddress = originalvmtgetoriginal(vmt.addr, fnindex)

proc vmtreset*(vmt: Vmt): void= originalvmtreset(vmt.addr)

proc vmtfree*(vmt: Vmt): void= originalvmtfree(vmt.addr)
"""


def process_file():
    with open(gen_file, "r") as file:
        data = file.read()
    data = re.sub(r"##.*", "", data)
    proc_pragma_pattern = r"\{.cdecl,.*?:|\{.\n\W+cdecl,.*?:|\{.cdecl,\n.*?:"
    data = re.sub(proc_pragma_pattern, "{.cdecl, importc:", data)
    whitespace_patterns = [
        (r";\n\W+", r";"),
        (r"\{.\n\W+cdecl", r"{.cdecl"),
        (r"\{.cdecl,\n\W+", r"{.cdecl,")
    ]
    for pattern, subst in whitespace_patterns:
        data = re.sub(pattern, subst, data)
    data = re.sub(r"proc (?P<name>(\w+))\*", "proc original\\g<name>", data)
    data = data.replace("bool* = enumbool", "")
    data = data.replace("byte* = uint8", "")
    data = data.replace("cschar", "cchar")
    data = data.replace(constorgi, constnew)
    data = data.replace(removethis, "")
    data = data.replace(andthis, "")
    libname_snippet = """import typetraits
type
  cstr = distinct array[4096, char]

converter stringtToCstring(x: cstr): cstring = cast[cstring]((distinctBase(cstr)x)[0].addr)

proc cb[T](c: ptr T; arg: pointer): bool {.cdecl.} =
  cast[ptr seq[T]](arg)[].add(c[])
  result = true"""
    data = libname_snippet + "\n" + data
    data = data + "\n" + wrapperfuncs
    with open(gen_file, "w") as file:
        file.write(data)


if __name__ == "__main__":
    os.chdir(current_dir)
    process_file()
