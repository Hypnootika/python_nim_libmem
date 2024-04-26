import unittest, osproc
import ../src/nimlibmem

from os import parentDir, `/`, sleep

proc prepex(): tuple[notepadprocess: osproc.Process, processx: Processt, module: Modulet] =
  var notepad: osproc.Process = startProcess("notepad.exe")
  var notepadprocess = Getprocessex(notepad.processID.uint32)
  var notepadmodule = Findmoduleex(notepadprocess, "notepad.exe")
  (notepad, notepadprocess, notepadmodule)

proc prepnonex(): tuple[processx: Processt, module: Modulet] =
  var ownprocess = Getprocess()
  var ownmodule = Findmodule($charArrayToCstring(ownprocess.name))
  (ownprocess, ownmodule)

proc cleansleep(notepad: osproc.Process): bool =
  sleep(250)
  terminate(notepad)
  sleep(150)
  if running(notepad):
    terminate(notepad)

proc localtests() =
  echo "Running local tests"
  test "Test GetArchitecture" :
    check  Getarchitecture() == Archx86
  test "Test Getprocess" :
    check  Getprocess().pid > 0
  test "Test Isprocessalive":
    check  Isprocessalive(Getprocess())
  test "Test Getbits":
    check  Getbits() == 64
  test "Test Getsystembits":
    check  Getsystembits() == 64
  test "Test Findsymboladdress":
    var ntdll = Findmodule("ntdll.dll")
    check  Findsymboladdress(ntdll, "NtClose") > 0

proc processandthtreadtests() =
  echo "Running process and thread tests"
  var (notepad, notepadprocess, notepadmodule) = prepex()
  test "Test Findprocess":
    check  notepadprocess.pid == notepad.processID.uint32
    check  Findprocess("notepad.exe").pid == notepad.processID.uint32
  test "Test Getprocessex" :
    check  notepadprocess.pid == notepad.processID.uint32
  test "Test Getthread":
    check  Getthread().tid > 0
  test "Test Getthreadprocess":
    check  Getthreadprocess(Getthread()).pid > 0
  test "Test Getthreadex":
    check  Getthreadex(notepadprocess).tid > 0
  discard cleansleep(notepad)

proc enumerationtests() =
  echo "Running enumeration tests"
  var (notepad, notepadprocess, notepadmodule) = prepex()
  test "Test Enummodules":
    check  Enummodules().len > 0
  sleep(100)
  test "Test Enumprocesses" :
      check  Enumprocesses().len > 0
  sleep(100)
  test "Test Enumthreads":
    check  Enumthreads().len > 0
  sleep(100)
  test "Test Enumsegments":
    check  Enumsegments().len > 0
  sleep(100)
  test "Test Enumsymbols":
    var ntdll = Findmodule("ntdll.dll")
    check  Enumsymbols(ntdll).len > 0
  sleep(100)
  test "Test Enumthreadsex":
    check  Enumthreadsex(notepadprocess).len > 0
  sleep(100)
  test "Test Enummodulesex":
    check  Enummodulesex(notepadprocess).len > 0
  sleep(100)
  test "Test Enumsegmentsex":
    check  Enumsegmentsex(notepadprocess).len > 0
  discard cleansleep(notepad)

proc modulerelatedtests() =
  echo "Running module related tests"
  var (notepad, notepadprocess, notepadmodule) = prepex()
  test "Test Findmodule":
    check  Findmodule("ntdll.dll").base > 0
  sleep(100)
  test "Test Findmoduleex":
    check  Findmoduleex(notepadprocess, "ntdll.dll").base > 0
  test "Test Loadmodule and Unloadmodule":
    check  Loadmodule("C:\\Windows\\System32\\HID.DLL") == true
    check  Unloadmodule(Findmodule("HID.DLL")) == true
  sleep(100)
  test "Test Loadmoduleex and Unloadmoduleex":
    check  Loadmoduleex(notepadprocess, "C:\\Windows\\System32\\HID.DLL") == true
    check  Unloadmoduleex(notepadprocess, Findmodule("HID.DLL")) == true
  discard cleansleep(notepad)

proc segmenttests() =
  echo "Running segment tests"
  var (notepad, notepadprocess, notepadmodule) = prepex()
  test "Test Findsegment":
    check  Findsegment(Findmodule($charArrayToCstring(Getprocess().name)).base).base > 0

  test "Test Findsegmentex":

    check  Findsegmentex(notepadprocess, notepadmodule.base).base > 0
  discard cleansleep(notepad)

proc testmemops() =
  echo "Running memory operation tests"
  var (notepad, notepadprocess, notepadmodule) = prepex()
  test "Test Protmemory":
    check  Protmemory(Findmodule("ntdll.dll").base, 6, Protrw) == true
  test "Test Protmemoryex":
    check Protmemoryex(notepadprocess, notepadmodule.base + 100, 6, Protrw) == true
  test "Test Setmemory":
    discard Protmemory(currentmodulebase + 150, 4, Protrw)
    check Setmemory(currentmodulebase + 150, 4, 8) == 8
  test "Test Setmemoryex":
    discard Protmemoryex(notepadprocess, notepadmodule.base  + 300, 4, Protrw)
    check Setmemoryex(notepadprocess, notepadmodule.base  + 300,4, 8) == 8
  test "Test Allocmemory and Freememory":
    var alloc = Allocmemory(8, Protrw)
    check  alloc > 0
    check  Freememory(alloc, 8) == true
  test "Test Allocmemoryex and Freememoryex":
    var alloc = Allocmemoryex(notepadprocess, 8, Protrw)
    check  alloc > 0
    check  Freememoryex(notepadprocess, alloc, 8) == true
  discard cleansleep(notepad)

proc scantests() =
  echo "Running scan tests"
  var (notepad, notepadprocess, notepadmodule) = prepex()
  sleep(100)
  test "Test DataScanex" :
    let data: seq[byte] = @[0xE8, 0xFA, 0xCA, 0xFF, 0xFF , 0x85 , 0xFF , 0x74 , 0x38 , 0x48 , 0x8B , 0x0D , 0x8F , 0x26 , 0x02 , 0x00 , 0x8B , 0x1D , 0x21 , 0x29 , 0x02 , 0x00 , 0x8B]
    check  Datascanex(notepadprocess, data, notepadmodule.base, notepadmodule.size) > 0
  sleep(100)
  test "Test PatternScanEx" :
      let patternscantestpatter = @[0x48.byte, 0xFF.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x0F.byte, 0x1F.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0xE9.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x33.byte, 0xC9]
      check  Patternscanex(notepadprocess, patternscantestpatter, "xx?????xx???x????xx",  notepadmodule.base, notepadmodule.size) > 0
  sleep(100)
  test "Test SigScanEx" :
    let sigscantestsig: cstring="E8 ? ? ? ? 85 FF 74 ? 48 8B"
    check  Sigscanex(notepadprocess,$sigscantestsig, notepadmodule.base, notepadmodule.size) > 0
    echo  Sigscanex(notepadprocess,$sigscantestsig, notepadmodule.base, notepadmodule.size) < high(uintptrt)
  discard cleansleep(notepad)

proc asmtests() =
  var (notepad, notepadprocess, notepadmodule) = prepex()
  let code: string = "mov eax, 0"
  var ins: Instructiont = Assemble("mov eax, 0")
  test "Test Assemble" :
    check  Assemble(code).size == 5
    check  Assemble("mov eax, 0").bytes[0] == 0xB8
  test "Test Assembleex" :
    check  Assembleex("mov eax, 0", runtimeaddress = notepadmodule.base) > 0
  test "Test Disassemble" :
    check  charArrayToCstring(Disassemble(Assemble("mov eax, 0").bytes).mnemonic) == "mov"
  test "Test DisassembleEx" :
    check  charArrayToCstring(Disassembleex(ins.bytes, address = notepadmodule.base).mnemonic) == "mov"
  test "Test CodeLength" :
    var ins = Assemble("mov eax, 0").bytes[0]
    check CodeLength(cast[uintptrt](ins.addr), 1) > 0
  test "Test CodeLengthEx":
    var ins = Assemble("mov eax, 0")
    check  CodeLengthex(notepadprocess, notepadmodule.base, 1) > 0
  discard cleansleep(notepad)

proc hookandpointerhcain() =
  var (ownproc, ownprocmod) = prepnonex()
  var (notepad, notepadprocess, notepadmodule) = prepex()
  var size: csize_t
  var tramp: uintptrt
  test "Test Hookcode and Unhookcode" :
    (tramp,size) = Hookcode(Allocmemory(500, Protrw), Findsymboladdress(ownprocmod, "LM_EnumProcesses"))
    check  tramp > 0
    check  Unhookcode(Findsymboladdress(ownprocmod, "LM_EnumProcesses"), tramp, size) == true
  test "Test Hookcodeex and Unhookcodeex" :
    (tramp,size) = Hookcodeex(notepadprocess, notepadmodule.base + 0x0000A70A, notepadmodule.base + 0x0000A70B)
    check  tramp > 0
    check  Unhookcodeex(notepadprocess, notepadmodule.base + 0x0000A70A, tramp, 5) == true
  test "Test PointerChain64" :
    check  pointerchain64(notepadprocess, (notepadmodule.base + 0x000320D8.uint64), @[0x40.uint64, 0x38.uint64, 0x30.uint64, 0x50.uint64]) > 0
  discard cleansleep(notepad)

proc memoryreadstest() =
  echo "Running memory read tests"
  var (notepad, notepadprocess, notepadmodule) = prepex()
  test "Test read_uint8" :
    check  sizeof(read_uint8(currentmodulebase)) == sizeof(uint8)
  test "Test read_uint16" :
    check  sizeof(read_uint16(currentmodulebase)) == sizeof(uint16)
  test "Test read_uint32" :
    check  sizeof(read_uint32(currentmodulebase)) == sizeof(uint32)
  test "Test read_uint64" :
    check  sizeof(read_uint64(currentmodulebase)) == sizeof(uint64)
  test "Test read_int8" :
    check  sizeof(read_int8(currentmodulebase)) == sizeof(int8)
  test "Test read_int16" :
    check  sizeof(read_int16(currentmodulebase)) == sizeof(int16)
  test "Test read_int32" :
    check  sizeof(read_int32(currentmodulebase)) == sizeof(int32)
  test "Test read_int64" :
    check  sizeof(read_int64(currentmodulebase)) == sizeof(int64)
  test "Test read_float32" :
    check  sizeof(read_float32(currentmodulebase)) == sizeof(float32)
  test "Test read_float64" :
    check  sizeof(read_float64(currentmodulebase)) == sizeof(float64)
  test "Test read_uint8ex" :
    check  sizeof(read_uint8ex(notepadprocess, notepadmodule.base)) == sizeof(uint8)
  test "Test read_uint16ex" :
    check  sizeof(read_uint16ex(notepadprocess, notepadmodule.base)) == sizeof(uint16)
  test "Test read_uint32ex" :
    check  sizeof(read_uint32ex(notepadprocess, notepadmodule.base)) == sizeof(uint32)
  test "Test read_uint64ex" :
    check  sizeof(read_uint64ex(notepadprocess, notepadmodule.base)) == sizeof(uint64)
  test "Test read_int8ex" :
    check  sizeof(read_int8ex(notepadprocess, notepadmodule.base)) == sizeof(int8)
  test "Test read_int16ex" :
    check  sizeof(read_int16ex(notepadprocess, notepadmodule.base)) == sizeof(int16)
  test "Test read_int32ex" :
    check  sizeof(read_int32ex(notepadprocess, notepadmodule.base)) == sizeof(int32)
  test "Test read_int64ex" :
    check  sizeof(read_int64ex(notepadprocess, notepadmodule.base)) == sizeof(int64)
  test "Test read_float32ex" :
    check  sizeof(read_float32ex(notepadprocess, notepadmodule.base)) == sizeof(float32)
  test "Test read_float64ex" :
    check  sizeof(read_float64ex(notepadprocess, notepadmodule.base)) == sizeof(float64)
  discard cleansleep(notepad)

proc writetests() =
  echo "Running memory write tests"
  var (notepad, notepadprocess, notepadmodule) = prepex()
  let u8: uint8 = uint8(0xFF)
  let u16: uint16 = uint16(0xFFFF)
  let u32: uint32 = uint32(0xFFFFFFFF)
  let u64: uint64 = uint64(0xFFFFFFFFFFFFFF)
  let i8: int8 = int8(-1)
  let i16: int16 = int16(-1)
  let i32: int32 = int32(-1)
  let i64: int64 = int64(-1)
  let f32: float32 = float32(-1.0)
  let f64: float64 = float64(-1.0)
  test "Test write_uint8" :
    check  write_uint8(currentmodulebase, u8) == true
  test "Test write_uint16" :
    check  write_uint16(currentmodulebase, u16) == true
  test "Test write_uint32" :
    check  write_uint32(currentmodulebase, u32) == true
  test "Test write_uint64" :
    check  write_uint64(currentmodulebase, u64) == true
  test "Test write_int8" :
    check  write_int8(currentmodulebase, i8) == true
  test "Test write_int16" :
    check  write_int16(currentmodulebase, i16) == true
  test "Test write_int32" :
    check  write_int32(currentmodulebase, i32) == true
  test "Test write_int64" :
    check  write_int64(currentmodulebase, i64) == true
  test "Test write_float32" :
    check  write_float32(currentmodulebase, f32) == true
  test "Test write_float64" :
    check  write_float64(currentmodulebase, f64) == true
  test "Test write_uint8ex" :
    check  write_uint8ex(notepadprocess, notepadmodule.base, u8) == true
  test "Test write_uint16ex" :
    check  write_uint16ex(notepadprocess, notepadmodule.base, u16) == true
  test "Test write_uint32ex" :
    check  write_uint32ex(notepadprocess, notepadmodule.base, u32) == true
  test "Test write_uint64ex" :
    check  write_uint64ex(notepadprocess, notepadmodule.base, u64) == true
  test "Test write_int8ex" :
    check  write_int8ex(notepadprocess, notepadmodule.base, i8) == true
  test "Test write_int16ex" :
    check  write_int16ex(notepadprocess, notepadmodule.base, i16) == true
  test "Test write_int32ex" :
    check  write_int32ex(notepadprocess, notepadmodule.base, i32) == true
  test "Test write_int64ex" :
    check  write_int64ex(notepadprocess, notepadmodule.base, i64) == true
  test "Test write_float32ex" :
    check  write_float32ex(notepadprocess, notepadmodule.base, f32) == true
  test "Test write_float64ex" :
    check  write_float64ex(notepadprocess, notepadmodule.base, f64) == true
  discard cleansleep(notepad)


proc main() =
  localtests()
  sleep(1000)
  processandthtreadtests()
  sleep(1000)
  enumerationtests()
  sleep(1000)
  modulerelatedtests()
  sleep(1000)
  segmenttests()
  sleep(1000)
  testmemops()
  sleep(1000)
  scantests()
  sleep(1000)
  asmtests()
  sleep(1000)
  hookandpointerhcain()
  sleep(1000)
  memoryreadstest()
  sleep(1000)
  writetests()
  sleep(1000)
  echo "All tests passed"

when isMainModule:
  main()