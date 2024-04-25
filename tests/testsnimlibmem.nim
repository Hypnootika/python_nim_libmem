# TESTS ARE CURRENTLY NOT UPDATED. See main file.











#[
import unittest
import osproc
import ../src/nimlibmem
from osproc import startProcess, terminate, processID
from os import parentDir, `/`, sleep

let teststring = "Hello, World!"

test "enumprocesses" :
  check enumprocesses().len > 0

test "getprocess" :
  check getprocess().pid > 0

test "getprocessex" :
  var notepad = startProcess("notepad.exe")
  var notepadprocess = getprocessex(notepad.processID.uint32)
  check notepadprocess.pid == notepad.processID.uint32
  sleep(250)
  terminate(notepad)

test "findprocess":
  var notepad = startProcess("notepad.exe")
  var notepadprocess = findprocess("notepad.exe")
  check notepadprocess.pid == notepad.processID.uint32
  sleep(250)
  terminate(notepad)

test "isprocessalive":
  check isprocessalive(getprocess())

test "getbits":
  check getbits() == 64

test "getsystembits":
  check getsystembits() == 64

test "enumthreads":
  check enumthreads().len > 0

test "enumthreadsex":
  var notepad = startProcess("notepad.exe")
  var notepadprocess = getprocessex(notepad.processID.uint32)
  check enumthreadsex(notepadprocess).len > 0
  sleep(250)
  terminate(notepad)

test "getthread":
  check getthread().tid > 0

test "getthreadex":
  var notepad = startProcess("notepad.exe")
  var notepadprocess = getprocessex(notepad.processID.uint32)
  check getthreadex(notepadprocess).tid > 0
  sleep(250)
  terminate(notepad)

test "getthreadprocess":
  check getthreadprocess(getthread()).pid > 0

test "enummodules":
  check enummodules().len > 0

test "enummodulesex":
  var notepad = startProcess("notepad.exe")
  var notepadprocess = getprocessex(notepad.processID.uint32)
  check enummodulesex(notepadprocess).len > 0
  sleep(250)
  terminate(notepad)

test "findmodule":
  check findmodule("ntdll.dll").base > 0

test "findmoduleex":
  var notepad = startProcess("notepad.exe")
  var notepadprocess = getprocessex(notepad.processID.uint32)
  sleep(250)
  check findmoduleex(notepadprocess, "ntdll.dll").base > 0
  sleep(250)
  terminate(notepad)

test "loadmodule and unloadmodule":
  var notepad = startProcess("notepad.exe")
  var notepadprocess = getprocessex(notepad.processID.uint32)
  var HID = loadmodule("C:\\Windows\\System32\\HID.DLL")
  check unloadmodule(HID) == true
  sleep(250)
  terminate(notepad)

test "loadmoduleex and unloadmoduleex":
  var notepad = startProcess("notepad.exe")
  var notepadprocess = getprocessex(notepad.processID.uint32)
  var HID = loadmoduleex(notepadprocess, "C:\\Windows\\System32\\HID.DLL")
  check unloadmoduleex(notepadprocess, HID) == true
  sleep(250)
  terminate(notepad)

test "enumsymbols":
  var ntdll = findmodule("ntdll.dll")
  check enumsymbols(ntdll).len > 0

test "findsymboladdress":
  var ntdll = findmodule("ntdll.dll")
  check findsymboladdress(ntdll, "NtClose") > 0

test "enumsegments":
  check enumsegments().len > 0

test "enumsegmentsex":
  var notepad = startProcess("notepad.exe")
  var notepadprocess = getprocessex(notepad.processID.uint32)
  check enumsegmentsex(notepadprocess).len > 0
  sleep(250)
  terminate(notepad)

test "findsegment":
  check findsegment(findmodule(stringtToCstring(getprocess().name)).base).base > 0

test "findsegmentex":
  var notepad = startProcess("notepad.exe")
  var notepadprocess = getprocessex(notepad.processID.uint32)
  check findsegmentex(notepadprocess, findmodule(stringtToCstring(notepadprocess.name)).base).base > 0
  sleep(250)
  terminate(notepad)

test "protmemory":
  check protmemory(findmodule("ntdll.dll").base, 6, Protrw) == true

test "protmemoryex":
  var notepad = startProcess("notepad.exe")
  var notepadprocess = getprocessex(notepad.processID.uint32)
  var notepadmodule = findmoduleex(notepadprocess, "notepad.exe")
  check protmemoryex(notepadprocess, notepadmodule.base, 6, Protrw) == true
  sleep(250)
  terminate(notepad)

test "readmemory":
  check readmemory(findmodule("ntdll.dll").base, uint64) > 0

test "readmemoryex":
  var notepad = startProcess("notepad.exe")
  var notepadprocess = getprocessex(notepad.processID.uint32)
  sleep(250)
  check readmemoryex(notepadprocess.addr, findmoduleex(notepadprocess, "ntdll.dll").base, uint64) > 0
  sleep(250)
  terminate(notepad)

test "writememory":
  var notepad = startProcess("notepad.exe")
  var notepadprocess = getprocessex(notepad.processID.uint32)
  var ntdll = findmoduleex(notepadprocess, "ntdll.dll")
  var original = readmemoryex(notepadprocess.addr, ntdll.base, uint64)
  check writememory(ntdll.base, original + 1) == true
  check readmemory(ntdll.base, uint64) == original + 1
  sleep(250)
  terminate(notepad)

test "writememoryex":
  var notepad = startProcess("notepad.exe")
  var notepadprocess = getprocessex(notepad.processID.uint32)
  var ntdll = findmoduleex(notepadprocess, "ntdll.dll")
  var original = readmemoryex(notepadprocess.addr, ntdll.base, uint64)
  check writememoryex(notepadprocess.addr, ntdll.base, original + 1) == true
  check readmemoryex(notepadprocess.addr, ntdll.base, uint64) == original + 1
  sleep(250)
  terminate(notepad)

test "setmemory":
  var notepad = startProcess("notepad.exe")
  var notepadprocess = getprocessex(notepad.processID.uint32)
  var ntdll = findmoduleex(notepadprocess, "ntdll.dll")
  check setmemory(ntdll.base, 0, 8) == 8
  sleep(250)
  terminate(notepad)

test "setmemoryex":
  var notepad = startProcess("notepad.exe")
  var notepadprocess = getprocessex(notepad.processID.uint32)
  var notepadmodule = findmoduleex(notepadprocess, "notepad.exe")
  discard protmemoryex(notepadprocess, notepadmodule.base  + 0x100, 4, Protrw)
  check setmemoryex(notepadprocess, notepadmodule.base  + 0x100,0, 4) == 4
  sleep(250)
  terminate(notepad)

test "allocmemory and freememory":
  var notepad = startProcess("notepad.exe")
  var notepadprocess = getprocessex(notepad.processID.uint32)
  var alloc = allocmemory(8, Protrw)
  check alloc > 0
  check freememory(alloc, 8) == true
  sleep(250)
  terminate(notepad)

test "allocmemoryex and freememoryex":
  var notepad = startProcess("notepad.exe")
  var notepadprocess = getprocessex(notepad.processID.uint32)
  var alloc = allocmemoryex(notepadprocess, 8, Protrw)
  check alloc > 0
  check freememoryex(notepadprocess, alloc, 8) == true
  sleep(250)
  terminate(notepad)

test "Test PointerChain64" :
  var notepad = startProcess("notepad.exe")
  var notepadprocess = getprocessex(notepad.processID.uint32)
  var notepadmodule = findmoduleex(notepadprocess, "notepad.exe")
  check pointerchain64(notepadprocess, (notepadmodule.base + 0x000320D8.uint64), [0x40.uint64, 0x38.uint64, 0x30.uint64, 0x50.uint64]) > 0
  sleep(250)
  terminate(notepad)

test "Test DataScanex" :
  var notepad = startProcess("notepad.exe")
  var notepadprocess = getprocessex(processID(notepad).uint32)
  var notepadmodule = findmoduleex(notepadprocess, "notepad.exe")
  let data: seq[byte] = @[0xE8, 0xFA, 0xCA, 0xFF, 0xFF , 0x85 , 0xFF , 0x74 , 0x38 , 0x48 , 0x8B , 0x0D , 0x8F , 0x26 , 0x02 , 0x00 , 0x8B , 0x1D , 0x21 , 0x29 , 0x02 , 0x00 , 0x8B]
  check datascanex(notepadprocess, data, notepadmodule.base, notepadmodule.size) > 0
  sleep(250)
  terminate(notepad)

# Recently passed!
test "Test PatternScanEx" :
  var notepad = startProcess("notepad.exe")
  var notepadprocess = getprocessex(processID(notepad).uint32)
  var notepadmodule = findmoduleex(notepadprocess, "notepad.exe")
  let patternscantestpatter =[0x48.byte, 0xFF.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x0F.byte, 0x1F.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0xE9.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x33.byte, 0xC9]
  check patternscanex(notepadprocess, patternscantestpatter, "xx?????xx???x????xx",  notepadmodule.base, notepadmodule.size) > 0
  sleep(250)
  terminate(notepad)

# Recently passed!
test "Test SigScanEx" :
  var notepad = startProcess("notepad.exe")
  var notepadprocess = getprocessex(processID(notepad).uint32)
  var notepadmodule = findmoduleex(notepadprocess, "notepad.exe")
  let sigscantestsig: cstring="E8 ? ? ? ? 85 FF 74 ? 48 8B"
  check sigscanex(notepadprocess, sigscantestsig, notepadmodule.base, notepadmodule.size) > 0
  sleep(250)
  terminate(notepad)

test "Test GetArchitecture" :
  check getarchitecture() == Archx86

test "assemble" :
  let code: cstring = "mov eax, 0"
  check assemble(code).size == 5

test "assembleex" :
  var notepad = startProcess("notepad.exe")
  var notepadprocess = getprocessex(notepad.processID.uint32)
  var notepadmodule = findmoduleex(notepadprocess, "notepad.exe")
  let code: cstring = "mov eax, 0"
  var payload: ptr byte = cast[ptr byte](allocmemoryex(notepadprocess, 5, Protrw))
  check assembleex(code, notepadmodule.base, payload) > 0
  sleep(250)
  terminate(notepad)

test "disassemble" :
  var notepad = startProcess("notepad.exe")
  var notepadprocess = getprocessex(notepad.processID.uint32)
  var notepadmodule = findmoduleex(notepadprocess, "notepad.exe")
  let code: cstring = "mov eax, 0"
  check disassemble(assemble(code).bytes).size == 5
  sleep(250)
  terminate(notepad)
]#

#[
test "disassembleex" :
  var notepad = startProcess("notepad.exe")
  var notepadprocess = getprocessex(notepad.processID.uint32)
  var notepadmodule = findmoduleex(notepadprocess, "notepad.exe")
  let mema: memoryaddress = assembleex("mov eax, 0", Archx86, 64, notepadmodule.base)
  discard protmemoryex(notepadprocess, notepadmodule.base, 5, Protrw)
  echo disassembleex(mema, notepadmodule.base).repr
  sleep(250)
  terminate(notepad)
]#
#[
test "hookcode and unhookcode" :
  var curp = getprocess()
  var curm = findmodule(stringtToCstring(curp.name))
  var hook =  hookcode(curm.base + 0x0000A70A, curm.base + 0x0000A70B)
  check hook > 0
  check unhookcode(curm.base + 0x0000A70A, hook, 5) == true

test "hookcodeex and unhookcodeex" :
  var notepad = startProcess("notepad.exe")
  var notepadprocess = getprocessex(notepad.processID.uint32)
  var notepadmodule = findmoduleex(notepadprocess, "notepad.exe")
  var hook =  hookcodeex(notepadprocess, notepadmodule.base + 0x0000A70A, notepadmodule.base + 0x0000A70B)
  check hook > 0
  check unhookcodeex(notepadprocess, notepadmodule.base + 0x0000A70A, hook, 5) == true
  sleep(250)
  terminate(notepad)]#

#[
proc vmtnew*(vtable: memoryaddress): Vmt = discard originalvmtnew(vtable.addr, addr result)

proc vmthook*(vmt: Vmt; fromfnindex: csize_t; to: memoryaddress): bool = originalvmthook(vmt.addr, fromfnindex, to)

proc vmtunhook*(vmt: Vmt; fnindex: csize_t): void= originalvmtunhook(vmt.addr, fnindex)

proc vmtgetoriginal*(vmt: Vmt; fnindex: csize_t): memoryaddress = originalvmtgetoriginal(vmt.addr, fnindex)

proc vmtreset*(vmt: Vmt): void= originalvmtreset(vmt.addr)

proc vmtfree*(vmt: Vmt): void= originalvmtfree(vmt.addr)
]#
