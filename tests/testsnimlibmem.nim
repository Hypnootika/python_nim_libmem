import unittest, osproc
import ../src/nimlibmem

from os import parentDir, `/`, sleep

proc prepex(): tuple[notepadprocess: osproc.Process, processx: Processt, module: Modulet] =
  var notepad: osproc.Process = startProcess("notepad.exe")
  var notepadprocess = getProcessex(notepad.processID.uint32)
  var notepadmodule = findModuleex(notepadprocess, "notepad.exe")
  (notepad, notepadprocess, notepadmodule)

proc prepnonex(): tuple[processx: Processt, module: Modulet] =
  var ownprocess = getProcess()
  var ownmodule = findModule($charArrayToCstring(ownprocess.name))
  (ownprocess, ownmodule)

proc cleansleep(notepad: osproc.Process): bool =
  sleep(250)
  terminate(notepad)
  sleep(150)
  if running(notepad):
    terminate(notepad)

proc localtests() =
  echo "running local tests"
  test "Test: getarchitecture" :
    check  getarchitecture() == Archx86
  test "Test: getprocess" :
    check  getprocess().pid > 0
  test "Test: isprocessalive":
    check  isprocessalive(getprocess())
  test "Test: getbits":
    check  getbits() == 64
  test "Test: getsystembits":
    check  getsystembits() == 64
  test "Test: findsymboladdress":
    var ntdll = findmodule("ntdll.dll")
    check  findsymboladdress(ntdll, "ntclose") > 0

proc processandthtreadtests() =
  echo "running process and thread tests"
  var (notepad, notepadprocess, notepadmodule) = prepex()
  test "Test: findprocess":
    check  notepadprocess.pid == notepad.processid.uint32
    check  findprocess("notepad.exe").pid == notepad.processid.uint32
  test "Test: getprocessex" :
    check  notepadprocess.pid == notepad.processid.uint32
  test "Test: getthread":
    check  getthread().tid > 0
  test "Test: getthreadprocess":
    check  getthreadprocess(getthread()).pid > 0
  test "Test: getthreadex":
    check  getthreadex(notepadprocess).tid > 0
  discard cleansleep(notepad)

proc enumerationtests() =
  echo "running enumeration tests"
  var (notepad, notepadprocess, notepadmodule) = prepex()
  test "Test: enummodules":
    check  enummodules().len > 0
  sleep(100)
  test "Test: enumprocesses" :
      check  enumprocesses().len > 0
  sleep(100)
  test "Test: enumthreads":
    check  enumthreads().len > 0
  sleep(100)
  test "Test: enumsegments":
    check  enumsegments().len > 0
  sleep(100)
  test "Test: enumsymbols":
    var ntdll = findmodule("ntdll.dll")
    check  enumsymbols(ntdll).len > 0
  sleep(100)
  test "Test: enumthreadsex":
    check  enumthreadsex(notepadprocess).len > 0
  sleep(100)
  test "Test: enummodulesex":
    check  enummodulesex(notepadprocess).len > 0
  sleep(100)
  test "Test: enumsegmentsex":
    check  enumsegmentsex(notepadprocess).len > 0
  discard cleansleep(notepad)

proc modulerelatedtests() =
  echo "running module related tests"
  var (notepad, notepadprocess, notepadmodule) = prepex()
  test "Test: findmodule":
    check  findmodule("ntdll.dll").base > 0
  sleep(100)
  test "Test: findmoduleex":
    check  findmoduleex(notepadprocess, "ntdll.dll").base > 0
  test "Test: loadmodule and unloadmodule":
    check  loadmodule("c:\\windows\\system32\\hid.dll") == true
    check  unloadmodule(findmodule("hid.dll")) == true
  sleep(100)
  test "Test: loadmoduleex and unloadmoduleex":
    check  loadmoduleex(notepadprocess, "c:\\windows\\system32\\hid.dll") == true
    check  unloadmoduleex(notepadprocess, findmodule("hid.dll")) == true
  discard cleansleep(notepad)

proc segmenttests() =
  echo "running segment tests"
  var (notepad, notepadprocess, notepadmodule) = prepex()
  test "Test: findsegment":
    check findsegment(findmodule($chararraytocstring(getprocess().name)).base).base > 0

  test "Test: findsegmentex":

    check  findsegmentex(notepadprocess, notepadmodule.base).base > 0
  discard cleansleep(notepad)

proc testmemops() =
  echo "running memory operation tests"
  var (notepad, notepadprocess, notepadmodule) = prepex()
  test "Test: protmemory":
    check  protmemory(findmodule("ntdll.dll").base, 6, Protrw) == true
  test "Test: protmemoryex":
    check protmemoryex(notepadprocess, notepadmodule.base + 100, 6, Protrw) == true
  test "Test: setmemory":
    discard protmemory(currentmodulebase + 150, 4, Protrw)
    check setmemory(currentmodulebase + 150, 4, 8) == 8
  test "Test: setmemoryex":
    discard protmemoryex(notepadprocess, notepadmodule.base  + 300, 4, Protrw)
    check setmemoryex(notepadprocess, notepadmodule.base  + 300,4, 8) == 8
  test "Test: allocmemory and freememory":
    var alloc = allocmemory(8, Protrw)
    check  alloc > 0
    check  freememory(alloc, 8) == true
  test "Test: allocmemoryex and freememoryex":
    var alloc = allocmemoryex(notepadprocess, 8, Protrw)
    check  alloc > 0
    check freememoryex(notepadprocess, alloc, 8) == true
  discard cleansleep(notepad)

proc scantests() =
  echo "running scan tests"
  var (notepad, notepadprocess, notepadmodule) = prepex()
  sleep(100)
  test "Test: datascanex" :
    let data: seq[byte] = @[0xe8, 0xfa, 0xca, 0xff, 0xff , 0x85 , 0xff , 0x74 , 0x38 , 0x48 , 0x8b , 0x0d , 0x8f , 0x26 , 0x02 , 0x00 , 0x8b , 0x1d , 0x21 , 0x29 , 0x02 , 0x00 , 0x8b]
    check  datascanex(notepadprocess, data, notepadmodule.base, notepadmodule.size) > 0
  sleep(100)
  test "Test: patternscanex" :
      let patternscantestpatter = @[0x48.byte, 0xff.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x0f.byte, 0x1f.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0xe9.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x33.byte, 0xc9]
      check  patternscanex(notepadprocess, patternscantestpatter, "xx?????xx???x????xx",  notepadmodule.base, notepadmodule.size) > 0
  sleep(100)
  test "Test: sigscanex" :
    let sigscantestsig: cstring="e8 ? ? ? ? 85 ff 74 ? 48 8b"
    check  sigscanex(notepadprocess,$sigscantestsig, notepadmodule.base, notepadmodule.size) > 0
  discard cleansleep(notepad)

proc asmtests() =
  var (notepad, notepadprocess, notepadmodule) = prepex()
  let code: string = "mov eax, 0"
  var ins: Instructiont = assemble("mov eax, 0")
  test "Test: assemble" :
    check  assemble(code).size == 5
    check  assemble("mov eax, 0").bytes[0] == 0xb8
  test "Test: assembleex" :
    check  assembleex("mov eax, 0", runtimeaddress = notepadmodule.base) > 0
  test "Test: disassemble" :
    check  chararraytocstring(disassemble(assemble("mov eax, 0").bytes).mnemonic) == "mov"
  test "Test: disassembleex" :
    check  chararraytocstring(disassembleex(ins.bytes, address = notepadmodule.base).mnemonic) == "mov"
  test "Test: codelength" :
    var ins = assemble("mov eax, 0").bytes[0]
    check codelength(cast[uintptrt](ins.addr), 1) > 0
  test "Test: codelengthex":
    var ins = assemble("mov eax, 0")
    check  codelengthex(notepadprocess, notepadmodule.base, 1) > 0
  discard cleansleep(notepad)

proc hookandpointerhcain() =
  var (ownproc, ownprocmod) = prepnonex()
  var (notepad, notepadprocess, notepadmodule) = prepex()
  var size: csize_t
  var tramp: uintptrt
  test "Test: hookcode and unhookcode" :
    (tramp,size) = hookcode(allocmemory(500, Protrw), findsymboladdress(ownprocmod, "LM_EnumProcesses"))
    check  tramp > 0
    check  unhookcode(findsymboladdress(ownprocmod, "LM_EnumProcesses"), tramp, size) == true
  test "Test: hookcodeex and unhookcodeex" :
    (tramp,size) = hookcodeex(notepadprocess, notepadmodule.base + 0x0000a70a, notepadmodule.base + 0x0000a70b)
    check  tramp > 0
    check  unhookcodeex(notepadprocess, notepadmodule.base + 0x0000a70a, tramp, 5) == true
  test "Test: pointerchain64" :
    check  pointerchain64(notepadprocess, (notepadmodule.base + 0x000320d8.uint64), [0x40.byte, 0x38.byte, 0x30.byte, 0x50.byte]) > 0
  discard cleansleep(notepad)

proc memoryreadstest() =
  echo "running memory read tests"
  var (notepad, notepadprocess, notepadmodule) = prepex()
  test "Test: read_uint8" :
    check  sizeof(read_uint8(currentmodulebase)) == sizeof(uint8)
  test "Test: read_uint16" :
    check  sizeof(read_uint16(currentmodulebase)) == sizeof(uint16)
  test "Test: read_uint32" :
    check  sizeof(read_uint32(currentmodulebase)) == sizeof(uint32)
  test "Test: read_uint64" :
    check  sizeof(read_uint64(currentmodulebase)) == sizeof(uint64)
  test "Test: read_int8" :
    check  sizeof(read_int8(currentmodulebase)) == sizeof(int8)
  test "Test: read_int16" :
    check  sizeof(read_int16(currentmodulebase)) == sizeof(int16)
  test "Test: read_int32" :
    check  sizeof(read_int32(currentmodulebase)) == sizeof(int32)
  test "Test: read_int64" :
    check  sizeof(read_int64(currentmodulebase)) == sizeof(int64)
  test "Test: read_float32" :
    check  sizeof(read_float32(currentmodulebase)) == sizeof(float32)
  test "Test: read_float64" :
    check  sizeof(read_float64(currentmodulebase)) == sizeof(float64)
  test "Test: read_uint8ex" :
    check  sizeof(read_uint8ex(notepadprocess, notepadmodule.base)) == sizeof(uint8)
  test "Test: read_uint16ex" :
    check  sizeof(read_uint16ex(notepadprocess, notepadmodule.base)) == sizeof(uint16)
  test "Test: read_uint32ex" :
    check  sizeof(read_uint32ex(notepadprocess, notepadmodule.base)) == sizeof(uint32)
  test "Test: read_uint64ex" :
    check  sizeof(read_uint64ex(notepadprocess, notepadmodule.base)) == sizeof(uint64)
  test "Test: read_int8ex" :
    check  sizeof(read_int8ex(notepadprocess, notepadmodule.base)) == sizeof(int8)
  test "Test: read_int16ex" :
    check  sizeof(read_int16ex(notepadprocess, notepadmodule.base)) == sizeof(int16)
  test "Test: read_int32ex" :
    check  sizeof(read_int32ex(notepadprocess, notepadmodule.base)) == sizeof(int32)
  test "Test: read_int64ex" :
    check  sizeof(read_int64ex(notepadprocess, notepadmodule.base)) == sizeof(int64)
  test "Test: read_float32ex" :
    check  sizeof(read_float32ex(notepadprocess, notepadmodule.base)) == sizeof(float32)
  test "Test: read_float64ex" :
    check  sizeof(read_float64ex(notepadprocess, notepadmodule.base)) == sizeof(float64)
  discard cleansleep(notepad)

proc writetests() =
  echo "running memory write tests"
  var (notepad, notepadprocess, notepadmodule) = prepex()
  let u8: uint8 = uint8(0xff)
  let u16: uint16 = uint16(0xffff)
  let u32: uint32 = uint32(0xffffffff)
  let u64: uint64 = uint64(0xffffffffffffff)
  let i8: int8 = int8(-1)
  let i16: int16 = int16(-1)
  let i32: int32 = int32(-1)
  let i64: int64 = int64(-1)
  let f32: float32 = float32(-1.0)
  let f64: float64 = float64(-1.0)
  test "Test: write_uint8" :
    check  write_uint8(currentmodulebase, u8) == true
  test "Test: write_uint16" :
    check  write_uint16(currentmodulebase, u16) == true
  test "Test: write_uint32" :
    check  write_uint32(currentmodulebase, u32) == true
  test "Test: write_uint64" :
    check  write_uint64(currentmodulebase, u64) == true
  test "Test: write_int8" :
    check  write_int8(currentmodulebase, i8) == true
  test "Test: write_int16" :
    check  write_int16(currentmodulebase, i16) == true
  test "Test: write_int32" :
    check  write_int32(currentmodulebase, i32) == true
  test "Test: write_int64" :
    check  write_int64(currentmodulebase, i64) == true
  test "Test: write_float32" :
    check  write_float32(currentmodulebase, f32) == true
  test "Test: write_float64" :
    check  write_float64(currentmodulebase, f64) == true
  test "Test: write_uint8ex" :
    check  write_uint8ex(notepadprocess, notepadmodule.base, u8) == true
  test "Test: write_uint16ex" :
    check  write_uint16ex(notepadprocess, notepadmodule.base, u16) == true
  test "Test: write_uint32ex" :
    check  write_uint32ex(notepadprocess, notepadmodule.base, u32) == true
  test "Test: write_uint64ex" :
    check  write_uint64ex(notepadprocess, notepadmodule.base, u64) == true
  test "Test: write_int8ex" :
    check  write_int8ex(notepadprocess, notepadmodule.base, i8) == true
  test "Test: write_int16ex" :
    check  write_int16ex(notepadprocess, notepadmodule.base, i16) == true
  test "Test: write_int32ex" :
    check  write_int32ex(notepadprocess, notepadmodule.base, i32) == true
  test "Test: write_int64ex" :
    check  write_int64ex(notepadprocess, notepadmodule.base, i64) == true
  test "Test: write_float32ex" :
    check  write_float32ex(notepadprocess, notepadmodule.base, f32) == true
  test "Test: write_float64ex" :
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
  echo "all tests passed"

when isMainModule:
  main()