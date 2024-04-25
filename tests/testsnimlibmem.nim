import unittest
import ../src/nimlibmem
from osproc import startProcess, terminate, processID
from os import parentDir, `/`, sleep

proc prepex(): tuple[notepadprocess: osproc.Process, processx: Processt, module: Modulet] =
  var notepad: osproc.Process = startProcess("notepad.exe")
  var notepadprocess = Getprocessex(notepad.processID.uint32)
  var notepadmodule = Findmoduleex(notepadprocess, "notepad.exe")
  (notepad, notepadprocess, notepadmodule)

proc prepnonex(): tuple[notepadprocess: osproc.Process, processx: Processt, module: Modulet] =
  var notepad = startProcess("notepad.exe")
  var ownprocess = Getprocess()
  var ownmodule = Findmodule($charArrayToCstring(ownprocess.name))
  (notepad, ownprocess, ownmodule)

proc cleansleep(notepad: osproc.Process) =
  sleep(250)
  terminate(notepad)

test "enumprocesses" :
  check Enumprocesses().len > 0

test "getprocess" :
  check Getprocess().pid > 0

test "getprocessex" :
  var (notepad, notepadprocess, _) = prepex()
  check notepadprocess.pid == notepad.processID.uint32
  cleansleep(notepad)

test "findprocess":
  var (notepad, notepadprocess, _) = prepex()
  check notepadprocess.pid == notepad.processID.uint32
  cleansleep(notepad)

test "isprocessalive":
  check Isprocessalive(Getprocess())

test "getbits":
  check Getbits() == 64

test "getsystembits":
  check Getsystembits() == 64

test "enumthreads":
  check Enumthreads().len > 0

test "enumthreadsex":
  var (notepad, notepadprocess, _) = prepex()
  check Enumthreadsex(notepadprocess).len > 0
  cleansleep(notepad)

test "getthread":
  check Getthread().tid > 0

test "getthreadex":
  var (notepad, notepadprocess, _) = prepex()
  check Getthreadex(notepadprocess).tid > 0
  cleansleep(notepad)

test "getthreadprocess":
  check Getthreadprocess(Getthread()).pid > 0

test "enummodules":
  check Enummodules().len > 0

test "enummodulesex":
  var (notepad, notepadprocess, _) = prepex()
  check Enummodulesex(notepadprocess).len > 0
  cleansleep(notepad)

test "findmodule":
  check Findmodule("ntdll.dll").base > 0

test "findmoduleex":
  var (notepad, notepadprocess, _) = prepex()
  check Findmoduleex(notepadprocess, "ntdll.dll").base > 0
  cleansleep(notepad)

test "loadmodule and unloadmodule":
  var (notepad, notepadprocess, _) = prepex()
  check Loadmodule("C:\\Windows\\System32\\HID.DLL") == true
  check Unloadmodule(Findmodule("HID.DLL")) == true
  cleansleep(notepad)

test "loadmoduleex and unloadmoduleex":
  var (notepad, notepadprocess, _) = prepex()
  check Loadmoduleex(notepadprocess, "C:\\Windows\\System32\\HID.DLL")
  check Unloadmoduleex(notepadprocess, Findmoduleex(notepadprocess, "HID.DLL")) == true
  cleansleep(notepad)

test "enumsymbols":
  var ntdll = Findmodule("ntdll.dll")
  check Enumsymbols(ntdll).len > 0

test "findsymboladdress":
  var ntdll = Findmodule("ntdll.dll")
  check Findsymboladdress(ntdll, "NtClose") > 0

test "enumsegments":
  check Enumsegments().len > 0

test "enumsegmentsex":
  var (notepad, notepadprocess, _) = prepex()
  check Enumsegmentsex(notepadprocess).len > 0
  cleansleep(notepad)

test "findsegment":
  check Findsegment(Findmodule($charArrayToCstring(Getprocess().name)).base).base > 0

test "findsegmentex":
  var (notepad, notepadprocess, _) = prepex()
  check Findsegmentex(notepadprocess, Findmodule($charArrayToCstring(notepadprocess.name)).base).base > 0
  cleansleep(notepad)

test "protmemory":
  check Protmemory(Findmodule("ntdll.dll").base, 6, Protrw) == true

test "protmemoryex":
  var (notepad, notepadprocess, notepadmodule) = prepex()
  check Protmemoryex(notepadprocess, notepadmodule.base + 10, 6, Protrw) == true
  cleansleep(notepad)

test "setmemory":
  var (notepad, ownproc, ownprocmod) = prepnonex()
  discard Protmemory(ownprocmod.base, 8, Protrw)
  check Setmemory(ownprocmod.base, 0, 8) == 8
  cleansleep(notepad)

test "setmemoryex":
  var (notepad, notepadprocess, notepadmodule) = prepex()
  discard Protmemoryex(notepadprocess, notepadmodule.base  + 50, 4, Protrw)
  check Setmemoryex(notepadprocess, notepadmodule.base  + 50,4, 8) == 8
  cleansleep(notepad)

test "allocmemory and freememory":
  var (notepad, _, _) = prepnonex()
  var alloc = Allocmemory(8, Protrw)
  check alloc > 0
  check Freememory(alloc, 8) == true
  cleansleep(notepad)

test "allocmemoryex and freememoryex":
  var (notepad, notepadprocess, _) = prepex()
  var alloc = Allocmemoryex(notepadprocess, 8, Protrw)
  check alloc > 0
  check Freememoryex(notepadprocess, alloc, 8) == true
  cleansleep(notepad)

test "Test DataScanex" :
  var (notepad, notepadprocess, notepadmodule) = prepex()
  let data: seq[byte] = @[0xE8, 0xFA, 0xCA, 0xFF, 0xFF , 0x85 , 0xFF , 0x74 , 0x38 , 0x48 , 0x8B , 0x0D , 0x8F , 0x26 , 0x02 , 0x00 , 0x8B , 0x1D , 0x21 , 0x29 , 0x02 , 0x00 , 0x8B]
  check Datascanex(notepadprocess, data, notepadmodule.base, notepadmodule.size) > 0
  cleansleep(notepad)

test "Test PatternScanEx" :
  var (notepad, notepadprocess, notepadmodule) = prepex()
  let patternscantestpatter = @[0x48.byte, 0xFF.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x0F.byte, 0x1F.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0xE9.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x33.byte, 0xC9]
  check Patternscanex(notepadprocess, patternscantestpatter, "xx?????xx???x????xx",  notepadmodule.base, notepadmodule.size) > 0
  cleansleep(notepad)

test "Test SigScanEx" :
  var (notepad, notepadprocess, notepadmodule) = prepex()
  let sigscantestsig: cstring="E8 ? ? ? ? 85 FF 74 ? 48 8B"
  check Sigscanex(notepadprocess,$sigscantestsig, notepadmodule.base, notepadmodule.size) > 0
  check Sigscanex(notepadprocess,$sigscantestsig, notepadmodule.base, notepadmodule.size) < high(uintptrt)
  cleansleep(notepad)

test "Test GetArchitecture" :
  check Getarchitecture() == Archx86

test "assemble" :
  let code: string = "mov eax, 0"
  check Assemble(code).size == 5
  check Assemble("mov eax, 0").bytes[0] == 0xB8

test "assembleex" :
  var (notepad, notepadprocess, notepadmodule) = prepex()
  check Assembleex("mov eax, 0", runtimeaddress = notepadmodule.base) > 0
  cleansleep(notepad)

# Recently passed!
test "Test Disassemble" :
  check charArrayToCstring(Disassemble(Assemble("mov eax, 0").bytes).mnemonic) == "mov"

# Recently passed!
test "Test DisassembleEx" :
  var (notepad, notepadprocess, notepadmodule) = prepex()
  var ins: Instructiont = Assemble("mov eax, 0")
  check charArrayToCstring(Disassembleex(ins.bytes, address = notepadmodule.base).mnemonic) == "mov"
  cleansleep(notepad)

# Recently passed!
test "Test CodeLength" :
  var ins = Assemble("mov eax, 0").bytes[0]
  check CodeLength(cast[uintptrt](ins.addr), 1) > 0

test "Test CodeLengthEx" :
  var (notepad, notepadprocess, notepadmodule) = prepex()
  var ins = Assemble("mov eax, 0")
  check CodeLengthex(notepadprocess, notepadmodule.base, 1) > 0
  cleansleep(notepad)

test "hookcode and unhookcode" :
  var (notepad, ownproc, ownprocmod) = prepnonex()
  var size: csize_t
  var tramp: uintptrt
  (tramp,size) = Hookcode(Allocmemory(500, Protrw), Findsymboladdress(ownprocmod, "LM_EnumProcesses"))
  check tramp > 0
  check Unhookcode(Findsymboladdress(ownprocmod, "LM_EnumProcesses"), tramp, size) == true
  cleansleep(notepad)

test "hookcodeex and unhookcodeex" :
  var (notepad, notepadprocess, notepadmodule) = prepex()
  var size: csize_t
  var tramp: uintptrt
  (tramp,size) = Hookcodeex(notepadprocess, notepadmodule.base + 0x0000A70A, notepadmodule.base + 0x0000A70B)
  check tramp > 0
  check Unhookcodeex(notepadprocess, notepadmodule.base + 0x0000A70A, tramp, 5) == true
  cleansleep(notepad)

test "vmtnew and vmtfree" :
  var (notepad, notepadprocess, notepadmodule) = prepex()
  var vmt = Vmtnew(notepadmodule.base)
  echo vmt.repr
  cleansleep(notepad)

test "vmthook and vmtunhook" :
  var (notepad, notepadprocess, notepadmodule) = prepex()
  var vmt = Vmtnew(notepadmodule.base)
  var original = Vmtgetoriginal(vmt, 0)
  check Vmthook(vmt, 0, original) == true.boolt
  Vmtunhook(vmt, 0)
  cleansleep(notepad)

test "vmtreset" :
  var (notepad, notepadprocess, notepadmodule) = prepex()
  var vmt = Vmtnew(notepadmodule.base)
  var original = Vmtgetoriginal(vmt, 0)
  check Vmthook(vmt, 0, original) == true.boolt
  Vmtreset(vmt)
  cleansleep(notepad)

#[test "vmtgetoriginal" :
  var (notepad, notepadprocess, notepadmodule) = prepex()
  var vmt = Vmtnew(notepadmodule.base)
  var original = Vmtgetoriginal(vmt, 0)
  check original > 0
  cleansleep(notepad)]#


## MISSING
#[
test "Test PointerChain64" :
  var (notepad, notepadprocess, notepadmodule) = prepex()
  check Pointerchain64(notepadprocess, (notepadmodule.base + 0x000320D8.uint64), @[0x40.uint64, 0x38.uint64, 0x30.uint64, 0x50.uint64]) > 0
  cleansleep(notepad)
]#

## ALSO read and write