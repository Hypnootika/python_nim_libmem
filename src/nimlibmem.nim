import typetraits, os, nimpy

pyExportModule("pynimlibmem")

const
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


type
  cstr = distinct array[4096, char]
  boolt* = cint
  structprocesst* {.pure, inheritable, bycopy.} = object
    pid*: uint32
    ppid*: uint32
    bits*: csize_t
    starttime*: uint64
    path*: array[4096, char]
    name*: array[4096, char]
  Processt* = structprocesst
  structthreadt* {.pure, inheritable, bycopy.} = object
    tid*: uint32
    ownerpid*: uint32
  Threadt* = structthreadt
  structmodulet* {.pure, inheritable, bycopy.} = object
    base*: uintptrt
    endfield*: uintptrt
    size*: csize_t
    path*: array[4096, char]
    name*: array[4096, char]
  uintptrt* = culonglong
  Modulet* = structmodulet
  structsegmentt* {.pure, inheritable, bycopy.} = object
    base*: uintptrt
    endfield*: uintptrt
    size*: csize_t
    prot*: uint32
  Segmentt* = structsegmentt
  structsymbolt* {.pure, inheritable, bycopy.} = object
    name*: cstring
    address*: uintptrt
  Symbolt* = structsymbolt
  structinstructiont* {.pure, inheritable, bycopy.} = object
    address*: uintptrt
    size*: csize_t
    bytes*: array[16'i64, uint8]
    mnemonic*: array[32'i64, char]
    opstr*: array[160'i64, char]
  Instructiont* = structinstructiont
  structvmtentryt* {.pure, inheritable, bycopy.} = object
    origfunc*: uintptrt
    index*: csize_t
    next*: ptr structvmtentryt
  Vmtentryt* = structvmtentryt
  structvmtt* {.pure, inheritable, bycopy.} = object
    vtable*: ptr uint = nil
    hkentries*: ptr Vmtentryt
  Vmtt* = structvmtt

converter stringtToCstring*(x: cstr): cstring  {.used, inline.} = cast[cstring]((distinctBase(cstr)x)[0].addr)
converter charArrayToCstring*(x: array[4096, char]): cstring {.used, inline.} = cast[cstring](x[0].addr)
converter cstringToStringt*(x: cstring): cstr {.used, inline.} = cast[cstr]($x)
converter charArrayToCstring*(x: array[32, char]): cstring {.used, inline.} = cast[cstring](x[0].addr)
converter charArrayToCstring*(x: array[160, char]): cstring {.used, inline.} = cast[cstring](x[0].addr)



proc cb*[T](c: ptr T; arg: pointer): boolt {.cdecl.} =
  cast[ptr seq[T]](arg)[].add(c[])
  result = 1

proc originalEnumprocesses(callback: proc (a0: ptr Processt; a1: pointer): boolt {.cdecl.}; arg: pointer): boolt {.cdecl, importc: "LM_EnumProcesses".}
proc enumProcesses*(): seq[Processt] {.exportpy: "enum_processes".}  =
  ## # Description
  ## Enumerates processes running on the system.
  ##
  ## # Parameters
  ## The function does not have parameters
  ##
  ## # Return Value
  ## A sequence of `Processt` structures containing information about each process.
  discard originalEnumprocesses(cb, result.addr)


proc originalGetprocess(processout: ptr Processt): boolt {.cdecl, importc: "LM_GetProcess".}
proc getProcess*(): Processt {.exportpy: "get_process".}  =
  ## # Description
  ## Retrieves information about the current process, including its PID,
  ## parent PID, path, name, start time, and architecture bits.
  ##
  ## # Parameters
  ## The function does not have parameters
  ##
  ## # Return Value
  ## A `Processt` structure containing information about the current process.
  discard originalGetprocess(result.addr)


proc originalGetprocessex(pid: uint32; processout: ptr Processt): boolt {.cdecl, importc: "LM_GetProcessEx".}
proc getProcessex*(pid: uint32): Processt {.exportpy: "get_processex".}  =
  ## # Description
  ## Retrieves information about a specified process identified by its process ID.
  ##
  ## # Parameters
  ##  - `pid`: The process ID of the process for which you want to
  ## retrieve information.
  ##
  ## # Return Value
  ## A `Processt` structure containing information about the specified process.
  discard originalGetprocessex(pid, result.addr)


proc originalFindprocess(processname: cstring; processout: ptr Processt): boolt {.cdecl, importc: "LM_FindProcess".}
proc findProcess*(processname: string): Processt {.exportpy: "find_process".}  =
  ## # Description
  ## Searches for a process by name and returns it as a `Processt` structure.
  ##
  ## # Parameters
  ##  - `process_name`: The name of the process you are trying to find
  ## (e.g `game.exe`). It can also be a relative path, such as
  ## `/game/hello` for a process at `/usr/share/game/hello`.
  ##
  ## # Return Value
  ## A `Processt` structure containing information about the found process.
  discard originalFindprocess(processname, result.addr)


proc originalIsprocessalive(process: ptr Processt): boolt {.cdecl, importc: "LM_IsProcessAlive".}
proc isProcessalive*(process: Processt): bool {.exportpy: "is_process_alive".}  =
  ## # Description
  ## Checks if a process is alive.
  ##
  ## # Parameters
  ##  - `process`: The process that will be checked.
  ##
  ## # Return Value
  ## `TRUE` if the process specified by the input `Processt`
  ## is alive or `FALSE` otherwise.
  return originalIsprocessalive(process.addr).bool


proc originalgetBits(): csize_t {.cdecl, importc: "LM_GetBits".}
proc getBits*(): csize_t {.exportpy: "get_bits".}  =
  ## # Description
  ## Returns the size of a pointer in bits, which corresponds to the current
  ## process's bits (32 bits or 64 bits).
  ##
  ## # Parameters
  ## - The function does not have parameters
  ##
  ## # Return Value
  ## The size of a pointer in bits.
  return originalgetBits()


proc originalGetsystembits(): csize_t {.cdecl, importc: "LM_GetSystemBits".}
proc getSystembits*(): csize_t {.exportpy: "get_system_bits".}  =
  ## # Description
  ## Returns the system architecture bits (32 bits or 64 bits).
  ##
  ## # Parameters
  ## - The function does not have parameters
  ##
  ## # Return Value
  ## The system bits (32 or 64).
  return originalGetsystembits()


proc originalEnumthreads(callback: proc (a0: ptr Threadt; a1: pointer): boolt {.cdecl.}; arg: pointer): boolt {.cdecl, importc: "LM_EnumThreads".}
proc enumThreads*(): seq[Threadt] {.exportpy: "enum_threads".}  =
  ## # Description
  ## Enumerates threads in the current process.
  ##
  ## # Parameters
  ## - The function does not have parameters
  ##
  ## # Return Value
  ## A sequence of `Threadt` structures containing information about each thread.
  discard originalEnumthreads(cb, result.addr)


proc originalEnumthreadsex(process: ptr Processt; callback: proc (a0: ptr Threadt; a1: pointer): boolt {.cdecl.}; arg: pointer): boolt {.cdecl, importc: "LM_EnumThreadsEx".}
proc enumThreadsex*(process: Processt): seq[Threadt] {.exportpy: "enum_threadsex".}  =
  ## # Description
  ## Enumerates threads of a given process.
  ##
  ## # Parameters
  ##  - `process`: The process you want to enumerate the threads from.
  ##
  ## # Return Value
  ## A sequence of `Threadt` structures containing information about each thread.
  discard originalEnumthreadsex(process.addr, cb, result.addr)


proc originalGetthread(threadout: ptr Threadt): boolt {.cdecl, importc: "LM_GetThread".}
proc getThread*(): Threadt {.exportpy: "get_thread".}  =
  ## # Description
  ## Retrieves information about the thread it's running from.
  ##
  ## # Parameters
  ## The function does not have parameters
  ##
  ## # Return Value
  ## A `Threadt` structure containing information about the current thread.
  discard originalGetthread(result.addr)


proc originalGetthreadex(process: ptr Processt; threadout: ptr Threadt): boolt {.cdecl, importc: "LM_GetThreadEx".}
proc getThreadex*(process: Processt): Threadt {.exportpy: "get_threadex".}  =
  ## # Description
  ## Retrieves information about a thread in a process.
  ##
  ## # Parameters
  ##  - `process`: The process that the thread will be retrieved from.
  ##
  ## # Return Value
  ## A `Threadt` structure containing information about the thread in the specified process.
  discard originalGetthreadex(process.addr, result.addr)


proc originalGetthreadprocess(thread: ptr Threadt; processout: ptr Processt): boolt {. cdecl, importc: "LM_GetThreadProcess".}
proc getThreadprocess*(thread: Threadt): Processt {.exportpy: "get_thread_process".}  =
  ## # Description
  ## Retrieves the process that owns a given thread.
  ##
  ## # Parameters
  ##  - `thread`: The thread whose process will be retrieved.
  ##  - `process_out`: A pointer to the `Processt` structure where the function
  ## `GetThreadProcess` will store the process information related to
  ## the given thread.
  ##
  ## # Return Value
  ## `TRUE` if the operation was successful or `FALSE`
  ## otherwise.
  discard originalGetthreadprocess(thread.addr, result.addr)


proc originalEnummodules(callback: proc (a0: ptr Modulet; a1: pointer): boolt {.cdecl.}; arg: pointer): boolt {.cdecl, importc: "LM_EnumModules".}
proc enumModules*(): seq[Modulet] {.exportpy: "enum_modules".}  =
  ## # Description
  ## Enumerates modules in the current process and calls a callback function
  ## for each module found.
  ##
  ## # Parameters
  ##  - The function does not have parameters
  ##
  ## # Return Value
  ## A sequence of `Modulet` structures containing information about each module.
  discard originalEnummodules(cb, result.addr)


proc originalEnummodulesex(process: ptr Processt; callback: proc (a0: ptr Modulet; a1: pointer): boolt {.cdecl.}; arg: pointer): boolt {.cdecl, importc: "LM_EnumModulesEx".}
proc enumModulesex*(process: Processt): seq[Modulet] {.exportpy: "enum_modulesex".}  =
  ## # Description
  ## Enumerates modules in a specified process and calls a callback function
  ## for each module found.
  ##
  ## # Parameters
  ##  - `process`: The process that the modules will be enumerated from.
  ##
  ## # Return Value
  ## A sequence of `Modulet` structures containing information about each module.
  discard originalEnummodulesex(process.addr, cb, result.addr)


proc originalFindmodule(name: cstring; moduleout: ptr Modulet): boolt {.cdecl, importc: "LM_FindModule".}
proc findModule*(name: string): Modulet {.exportpy: "find_module".}  =
  ## # Description
  ## Finds a module by its name returns it as a `Modulet` structure.
  ##
  ## # Parameters
  ##  - `name`: The name of the module to find (e.g `game.dll`). It can also be a
  ## relative path, such as `/game/hello` for a module at `/usr/share/game/hello`.
  ##
  ## # Return Value
  ## A `Modulet` structure containing information about the found module.
  discard originalFindmodule(name, result.addr)


proc originalFindmoduleex(process: ptr Processt; name: cstring; moduleout: ptr Modulet): boolt {. cdecl, importc: "LM_FindModuleEx".}
proc findModuleex*(process: Processt; name: string): Modulet {.exportpy: "find_moduleex".}  =
  ## # Description
  ## Finds a module by its name returns it as a `Modulet` structure.
  ##
  ## # Parameters
  ##  - `process`: The process that the module will be searched in.
  ##  - `name`: The name of the module to find (e.g `game.dll`). It can also be a
  ## relative path, such as `/game/hello` for a module at `/usr/share/game/hello`.
  ##
  ## # Return Value
  ## A `Modulet` structure containing information about the found module.
  discard originalFindmoduleex(process.addr, name, result.addr)

template currentmodulebase*(): uintptrt = findmodule($charArrayToCstring(getprocess().name)).base

proc originalLoadmodule(path: cstring; moduleout: ptr Modulet): boolt {.cdecl, importc: "LM_LoadModule".}
proc loadModule*(path: string): bool {.exportpy: "load_module".}  =
  ## # Description
  ## Loads a module from a specified path into the current process.
  ##
  ## # Parameters
  ##  - `path`: The path of the module to be loaded.
  ##
  ## # Return Value
  ## Returns `TRUE` is the module was loaded successfully, or `FALSE` if it fails.
  return originalLoadmodule(path, nil).bool

proc originalLoadmoduleex(process: ptr Processt; path: cstring; moduleout: ptr Modulet): boolt {. cdecl, importc: "LM_LoadModuleEx".}
proc loadModuleex*(process: Processt; path: string): bool {.exportpy: "load_moduleex".}  =
  ## # Description
  ## Loads a module from a specified path into a specified process.
  ##
  ## # Parameters
  ##  - `process`: The process that the module will be loaded into.
  ##  - `path`: The path of the module to be loaded.
  ##
  ## # Return Value
  ## Returns `TRUE` is the module was loaded successfully, or `FALSE` if it fails.
  return originalLoadmoduleex(process.addr, path.cstring, nil).bool


proc originalUnloadmodule(module: ptr Modulet): boolt {.cdecl, importc: "LM_UnloadModule".}
proc unloadModule*(module: Modulet): bool {.exportpy: "unload_module".}  =
  ## # Description
  ## Unloads a module from the current process.
  ##
  ## # Parameters
  ##  - `module`: The module that you want to unload from the process.
  ##
  ## # Return Value
  ## Returns `TRUE` if the module was successfully unloaded, and `FALSE` if it fails.
  return originalUnloadmodule(module.addr).bool


proc originalUnloadmoduleex(process: ptr Processt; module: ptr Modulet): boolt {.cdecl, importc: "LM_UnloadModuleEx".}
proc unloadModuleex*(process: Processt; module: Modulet): bool {.exportpy: "unload_moduleex".}  =
  ## # Description
  ## Unloads a module from a specified process.
  ##
  ## # Parameters
  ##  - `process`: The process that the module will be unloaded from.
  ##  - `module`: The module that you want to unload from the process.
  ##
  ## # Return Value
  ## Returns `TRUE` if the module was successfully unloaded, and `FALSE` if it fails.
  return originalUnloadmoduleex(process.addr, module.addr).bool


proc originalEnumsymbols(module: ptr Modulet; callback: proc (a0: ptr Symbolt; a1: pointer): boolt {.cdecl.}; arg: pointer): boolt {.cdecl, importc: "LM_EnumSymbols".}
proc enumSymbols*(module: Modulet): seq[Symbolt] {.exportpy: "enum_symbols".}  =
  ## # Description
  ## Enumerates symbols in a module and calls a callback function for each symbol found.
  ##
  ## # Parameters
  ##  - `module`: The module where the symbols will be enumerated from.
  ##
  ## # Return Value
  ## A sequence of `Symbolt` structures containing information about each symbol.
  discard originalEnumsymbols(module.addr, cb, result.addr)


proc originalEnumsegments(callback: proc (a0: ptr Segmentt; a1: pointer): boolt {.cdecl.}; arg: pointer): boolt {.cdecl, importc: "LM_EnumSegments".}
proc enumSegments*(): seq[Segmentt] {.exportpy: "enum_segments".}  =
  ## # Description
  ## Enumerates the memory segments of the current process and invokes a callback function for each segment.
  ##
  ## # Parameters
  ##  - The function does not have parameters
  ##
  ## # Return Value
  ## A sequence of `Segmentt` structures containing information about each segment.
  discard originalEnumsegments(cb, result.addr)


proc originalEnumsegmentsex(process: ptr Processt; callback: proc (a0: ptr Segmentt; a1: pointer): boolt {.cdecl.}; arg: pointer): boolt {.cdecl, importc: "LM_EnumSegmentsEx".}
proc enumSegmentsex*(process: Processt): seq[Segmentt] {.exportpy: "enum_segmentsex".}  =
  ## # Description
  ## Enumerates the memory segments of a given process and invokes a callback function for each segment.
  ##
  ## # Parameters
  ##  - `process`: A pointer to a structure containing information about the process whose segments will be enumerated.
  ##
  ## # Return Value
  ## A sequence of `Segmentt` structures containing information about each segment.
  discard originalEnumsegmentsex(process.addr, cb, result.addr)


proc originalFindsegment(address: uintptrt; segmentout: ptr Segmentt): boolt {.cdecl, importc: "LM_FindSegment".}
proc findSegment*(address: uintptrt): Segmentt {.exportpy: "find_segment".}  =
  ## # Description
  ## The function `FindSegment` searches for a memory segment that a given address is within
  ##
  ## # Parameters
  ##  - `address`: The address to search for.
  ##
  ## # Return Value
  ## The function returns a `Segmentt` structure containing information about the segment that contains the specified address.
  discard originalFindsegment(address, result.addr)


proc originalFindsegmentex(process: ptr Processt; address: uintptrt; segmentout: ptr Segmentt): boolt {.cdecl, importc: "LM_FindSegmentEx".}
proc findSegmentex*(process: Processt; address: uintptrt): Segmentt {.exportpy: "find_segmentex".}  =
  ## # Description
  ## The function `FindSegment` searches for a memory segment that a given address is within.
  ##
  ## # Parameters
  ##  - `process`: A pointer to a structure containing information about the process whose memory segments will be searched.
  ##  - `address`: The address to search for.
  ##
  ## # Return Value
  ## The function returns a `Segmentt` structure containing information about the segment that contains the specified address.
  discard originalFindsegmentex(process.addr, address, result.addr)

proc originalSetmemory(dest: uintptrt; byte: uint8; size: csize_t): csize_t {.cdecl, importc: "LM_SetMemory".}
proc setMemory*(dest: uintptrt; byte: uint8; size: csize_t): csize_t {.exportpy: "set_memory".}  =
  ## # Description
  ## Sets a specified memory region to a given byte value.
  ##
  ## # Parameters
  ##  - `dest`: The destination memory address where the `byte` value will be written to, starting from this address.
  ##  - `byte`: The value of the byte that will be written to the memory locations starting from the `dest` address.
  ##  - `size`: The number of bytes to set in the memory starting from the `dest` address.
  ##
  ## # Return Value
  ## The number of bytes that were successfully set to the
  ## specified value `byte` in the memory region starting at address
  ## `dest`.
  return originalSetmemory(dest, byte, size)


proc originalSetmemoryex(process: ptr Processt; dest: uintptrt; byte: uint8; size: csize_t): csize_t {.cdecl, importc: "LM_SetMemoryEx".}
proc setMemoryex*(process: Processt; dest: uintptrt; byte: uint8; size: csize_t): csize_t {.exportpy: "set_memoryex".}  =
  ## # Description
  ## Sets a specified memory region to a given byte value in a target
  ## process.
  ##
  ## # Parameters
  ##  - `process`: A pointer to the process that the memory will be set.
  ##  - `dest`: The destination address in the target process where the `byte` value will be written to.
  ##  - `byte`: The value of the byte that will be written to the memory locations starting from the `dest` address.
  ##  - `size`: The number of bytes to set in the memory starting from the `dest` address.
  ##
  ## # Return Value
  ## The number of bytes that were successfully set to the
  ## specified value `byte` in the memory region starting at address
  ## `dest` in the target process. If there are any errors, it returns 0.
  return originalSetmemoryex(process.addr, dest, byte, size)


proc originalprotmemory(address: uintptrt; size: csize_t; prot: uint32; oldprotout: ptr uint32): boolt {.cdecl, importc: "LM_ProtMemory".}
proc protMemory*(address: uintptrt; size: csize_t; prot: uint32): bool {.exportpy: "prot_memory".}  =
  ## # Description
  ## The function sets memory protection flags for a specified memory address range.
  ##
  ## # Parameters
  ##  - `address`: The memory address to be protected.
  ##  - `size`: The size of memory to be protected. If the size is 0, the function will default to using the system's page size for the operation.
  ##  - `prot`: The new protection flags that will be applied to the memory region starting at the specified address. It is a bit mask of `PROT_X` (execute), `PROT_R` (read), `PROT_W` (write).
  ##
  ## # Return Value
  ## The function returns a boolean value, either `TRUE` or `FALSE`, based on the success of the memory protection operation.
  return originalprotmemory(address, size, prot, nil).bool


proc originalprotmemoryex(process: ptr Processt; address: uintptrt; size: csize_t; prot: uint32; oldprotout: ptr uint32): boolt {.cdecl, importc: "LM_ProtMemoryEx".}
proc protMemoryex*(process: Processt; address: uintptrt; size: csize_t; prot: uint32): bool {.exportpy: "prot_memoryex".}  =
  ## # Description
  ## The function modifies memory protection flags for a specified address range in a given process.
  ##
  ## # Parameters
  ##  - `process`: A pointer to the process that the memory flags will be modified from.
  ##  - `address`: The memory address to be protected.
  ##  - `size`: The size of memory to be protected. If the size is 0, the function will default to using the system's page size for the operation.
  ##  - `prot`: The new protection flags that will be applied to the memory region starting at the specified address. It is a bit mask of `PROT_X` (execute), `PROT_R` (read), `PROT_W` (write).
  ##
  ## # Return Value
  ## The function returns a boolean value indicating whether the memory
  ## protection operation was successful or not. It returns `TRUE` if the
  ## operation was successful and `FALSE` if it was not.
  return originalprotmemoryex(process.addr, address, size, prot, nil).bool


proc originalReadmemory(source: uintptrt; dest: ptr uint8; size: csize_t): csize_t {. cdecl, importc: "LM_ReadMemory".}
proc readmemory*[T](address: uintptrt, t: typedesc[T], size: Natural=1): T  =
  when T is typeof(string|cstring):
    var st = newSeq[char](size)
    discard originalReadmemory(address, cast[ptr byte](addr st[0]), size.csize_t)
    result = cast[T](st)
  when T is typeof(seq):
    setLen(result, size)
    discard originalReadmemory(address, result[0].addr, size.csize_t)
  else:
    discard originalReadmemory(address, cast[ptr byte](addr result), sizeof(T).csize_t)

## Due to Python incompatibility with Type T, we are exposing fixed type reads and writes:
proc read_uint8*(address: uintptrt): uint8 {.exportpy.}  =
  ## # Description
  ## Reads an unsigned 8-bit integer from a specified memory address.
  ##
  ## # Parameters
  ##  - `address`: The memory address from which the unsigned 8-bit integer will be read.
  ##
  ## # Return Value
  ## The unsigned 8-bit integer value read from the specified memory address.
  result = cast[uint8](readmemory(address, uint8))

proc read_uint16*(address: uintptrt): uint16 {.exportpy.}  =
  ## # Description
  ## Reads an unsigned 16-bit integer from a specified memory address.
  ##
  ## # Parameters
  ##  - `address`: The memory address from which the unsigned 16-bit integer will be read.
  ##
  ## # Return Value
  ## The unsigned 16-bit integer value read from the specified memory address.
  result = cast[uint16](readmemory(address, uint16))

proc read_uint32*(address: uintptrt): uint32 {.exportpy.}  =
  ## # Description
  ## Reads an unsigned 32-bit integer from a specified memory address.
  ##
  ## # Parameters
  ##  - `address`: The memory address from which the unsigned 32-bit integer will be read.
  ##
  ## # Return Value
  ## The unsigned 32-bit integer value read from the specified memory address.
  return readmemory(address, uint32)

proc read_uint64*(address: uintptrt): uint64 {.exportpy.}  =
  ## # Description
  ## Reads an unsigned 64-bit integer from a specified memory address.
  ##
  ## # Parameters
  ##  - `address`: The memory address from which the unsigned 64-bit integer will be read.
  ##
  ## # Return Value
  ## The unsigned 64-bit integer value read from the specified memory address.
  return readmemory(address, uint64)

proc read_int8*(address: uintptrt): int8 {.exportpy.}  =
  ## # Description
  ## Reads a signed 8-bit integer from a specified memory address.
  ##
  ## # Parameters
  ##  - `address`: The memory address from which the signed 8-bit integer will be read.
  ##
  ## # Return Value
  ## The signed 8-bit integer value read from the specified memory address.
  return readmemory(address, int8)

proc read_int16*(address: uintptrt): int16 {.exportpy.}  =
  ## # Description
  ## Reads a signed 16-bit integer from a specified memory address.
  ##
  ## # Parameters
  ##  - `address`: The memory address from which the signed 16-bit integer will be read.
  ##
  ## # Return Value
  ## The signed 16-bit integer value read from the specified memory address.
  return readmemory(address, int16)

proc read_int32*(address: uintptrt): int32 {.exportpy.}  =
  ## # Description
  ## Reads a signed 32-bit integer from a specified memory address.
  ##
  ## # Parameters
  ##  - `address`: The memory address from which the signed 32-bit integer will be read.
  ##
  ## # Return Value
  ## The signed 32-bit integer value read from the specified memory address.
  return readmemory(address, int32)

proc read_int64*(address: uintptrt): int64 {.exportpy.}  =
  ## # Description
  ## Reads a signed 64-bit integer from a specified memory address.
  ##
  ## # Parameters
  ##  - `address`: The memory address from which the signed 64-bit integer will be read.
  ##
  ## # Return Value
  ## The signed 64-bit integer value read from the specified memory address.
  return readmemory(address, int64)

proc read_float32*(address: uintptrt): float32 {.exportpy.}  =
  ## # Description
  ## Reads a 32-bit floating-point number from a specified memory address.
  ##
  ## # Parameters
  ##  - `address`: The memory address from which the 32-bit floating-point number will be read.
  ##
  ## # Return Value
  ## The 32-bit floating-point number value read from the specified memory address.
  return readmemory(address, float32)

proc read_float64*(address: uintptrt): float64 {.exportpy.}  =
  ## # Description
  ## Reads a 64-bit floating-point number from a specified memory address.
  ##
  ## # Parameters
  ##  - `address`: The memory address from which the 64-bit floating-point number will be read.
  ##
  ## # Return Value
  ## The 64-bit floating-point number value read from the specified memory address.
  return readmemory(address, float64)

proc originalReadmemoryex(process: ptr Processt; source: uintptrt; dest: ptr uint8; size: csize_t): csize_t {.cdecl, importc: "LM_ReadMemoryEx".}
proc readMemoryex*[T](process: ptr Processt; address: uintptrt; t: typedesc[T], size: Natural=1): T =
  when T is typeof(string|cstring):
    var st = newSeq[char](size)
    discard originalReadmemoryex(process, address, cast[ptr byte](addr st[0]), size.csize_t)
    result = cast[T](st)
  when T is typeof(seq):
    setLen(result, size)
    discard originalReadmemoryex(process, address, result[0].addr, size.csize_t)
  else:
    discard originalReadmemoryex(process, address, cast[ptr byte](addr result), sizeof(T).csize_t)

proc read_uint8ex*(process: Processt; address: uintptrt): uint8 {.exportpy.}  =
  ## # Description
  ## Reads an unsigned 8-bit integer from a specified memory address in a target process.
  ##
  ## # Parameters
  ##  - `process`: A pointer to the process that the unsigned 8-bit integer will be read from.
  ##  - `address`: The memory address from which the unsigned 8-bit integer will be read.
  ##
  ## # Return Value
  ## The unsigned 8-bit integer value read from the specified memory address in the target process.
  return readmemoryex(process.addr, address, uint8)

proc read_uint16ex*(process:  Processt; address: uintptrt): uint16 {.exportpy.}  =
  ## # Description
  ## Reads an unsigned 16-bit integer from a specified memory address in a target process.
  ##
  ## # Parameters
  ##  - `process`: A pointer to the process that the unsigned 16-bit integer will be read from.
  ##  - `address`: The memory address from which the unsigned 16-bit integer will be read.
  ##
  ## # Return Value
  ## The unsigned 16-bit integer value read from the specified memory address in the target process.
  return readmemoryex(process.addr, address, uint16)

proc read_uint32ex*(process:  Processt; address: uintptrt): uint32 {.exportpy.}  =
  ## # Description
  ## Reads an unsigned 32-bit integer from a specified memory address in a target process.
  ##
  ## # Parameters
  ##  - `process`: A pointer to the process that the unsigned 32-bit integer will be read from.
  ##  - `address`: The memory address from which the unsigned 32-bit integer will be read.
  ##
  ## # Return Value
  ## The unsigned 32-bit integer value read from the specified memory address in the target process.
  return readmemoryex(process.addr, address, uint32)

proc read_uint64ex*(process:  Processt; address: uintptrt): uint64 {.exportpy.}  =
  ## # Description
  ## Reads an unsigned 64-bit integer from a specified memory address in a target process.
  ##
  ## # Parameters
  ##  - `process`: A pointer to the process that the unsigned 64-bit integer will be read from.
  ##  - `address`: The memory address from which the unsigned 64-bit integer will be read.
  ##
  ## # Return Value
  ## The unsigned 64-bit integer value read from the specified memory address in the target process.
  return readmemoryex(process.addr, address, uint64)

proc read_int8ex*(process:  Processt; address: uintptrt): int8 {.exportpy.}  =
  ## # Description
  ## Reads a signed 8-bit integer from a specified memory address in a target process.
  ##
  ## # Parameters
  ##  - `process`: A pointer to the process that the signed 8-bit integer will be read from.
  ##  - `address`: The memory address from which the signed 8-bit integer will be read.
  ##
  ## # Return Value
  ## The signed 8-bit integer value read from the specified memory address in the target process.
  return readmemoryex(process.addr, address, int8)

proc read_int16ex*(process:  Processt; address: uintptrt): int16 {.exportpy.}  =
  ## # Description
  ## Reads a signed 16-bit integer from a specified memory address in a target process.
  ##
  ## # Parameters
  ##  - `process`: A pointer to the process that the signed 16-bit integer will be read from.
  ##  - `address`: The memory address from which the signed 16-bit integer will be read.
  ##
  ## # Return Value
  ## The signed 16-bit integer value read from the specified memory address in the target process.
  return readmemoryex(process.addr, address, int16)

proc read_int32ex*(process:  Processt; address: uintptrt): int32 {.exportpy.}  =
  ## # Description
  ## Reads a signed 32-bit integer from a specified memory address in a target process.
  ##
  ## # Parameters
  ##  - `process`: A pointer to the process that the signed 32-bit integer will be read from.
  ##  - `address`: The memory address from which the signed 32-bit integer will be read.
  ##
  ## # Return Value
  ## The signed 32-bit integer value read from the specified memory address in the target process.
  return readmemoryex(process.addr, address, int32)

proc read_int64ex*(process:  Processt; address: uintptrt): int64 {.exportpy.}  =
  ## # Description
  ## Reads a signed 64-bit integer from a specified memory address in a target process.
  ##
  ## # Parameters
  ##  - `process`: A pointer to the process that the signed 64-bit integer will be read from.
  ##  - `address`: The memory address from which the signed 64-bit integer will be read.
  ##
  ## # Return Value
  ## The signed 64-bit integer value read from the specified memory address in the target process.
  return readmemoryex(process.addr, address, int64)

proc read_float_32ex*(process:  Processt; address: uintptrt): float32 {.exportpy.}  =
  ## # Description
  ## Reads a 32-bit floating-point number from a specified memory address in a target process.
  ##
  ## # Parameters
  ##  - `process`: A pointer to the process that the 32-bit floating-point number will be read from.
  ##  - `address`: The memory address from which the 32-bit floating-point number will be read.
  ##
  ## # Return Value
  ## The 32-bit floating-point number value read from the specified memory address in the target process.
  return readmemoryex(process.addr, address, float32)

proc read_float64ex*(process:  Processt; address: uintptrt): float64 {.exportpy.}  =
  ## # Description
  ## Reads a 64-bit floating-point number from a specified memory address in a target process.
  ##
  ## # Parameters
  ##  - `process`: A pointer to the process that the 64-bit floating-point number will be read from.
  ##  - `address`: The memory address from which the 64-bit floating-point number will be read.
  ##
  ## # Return Value
  ## The 64-bit floating-point number value read from the specified memory address in the target process.
  return readmemoryex(process.addr, address, float64)

proc originalwritememory(dest: uintptrt; source: ptr byte; size: csize_t): csize_t {.cdecl, importc: "LM_WriteMemory".}
proc writeMemory*[T](address: uintptrt, value: T, size: Natural=1) : bool =
  if protmemory(address, size.csize_t, Protxrw):
    try:
       when T is typeof string or cstring:
          if originalwritememory(address, cast[ptr byte](addr value[0]), size.csize_t) == size:
            result = true
          else:
            result = false
       when T is typeof seq:
          if originalwritememory(address, value[0].addr, size.csize_t) == size:
            result = true
          else:
            result = false
       else:
          if originalwritememory(address, cast[ptr byte](addr value), sizeof(T).csize_t) == sizeof(T).csize_t:
            result = true
          else:
            result = false
    except:
      if protmemory(address, size.csize_t, Protxrw):
        if writememory(address, value, size) == false:
          discard protmemory(address, size.csize_t, Protr)
      else:
        raise newException(ValueError, "Memory protection error")
    finally:
      discard protmemory(address, size.csize_t, Protr)

proc write_uint8*(address: uintptrt; value: uint8) : bool {.exportpy.}  =
  ## # Description
  ## Writes an unsigned 8-bit integer to a specified memory address.
  ##
  ## # Parameters
  ##  - `address`: The memory address where the unsigned 8-bit integer will be written.
  ##  - `value`: The unsigned 8-bit integer value that will be written to the memory address.
  writememory(address, value)

proc write_uint16*(address: uintptrt; value: uint16)  : bool {.exportpy.}  =
  ## # Description
  ## Writes an unsigned 16-bit integer to a specified memory address.
  ##
  ## # Parameters
  ##  - `address`: The memory address where the unsigned 16-bit integer will be written.
  ##  - `value`: The unsigned 16-bit integer value that will be written to the memory address.
  writememory(address, value)

proc write_uint32*(address: uintptrt; value: uint32)  : bool {.exportpy.}  =
  ## # Description
  ## Writes an unsigned 32-bit integer to a specified memory address.
  ##
  ## # Parameters
  ##  - `address`: The memory address where the unsigned 32-bit integer will be written.
  ##  - `value`: The unsigned 32-bit integer value that will be written to the memory address.
  writememory(address, value)

proc write_uint64*(address: uintptrt; value: uint64)  : bool {.exportpy.}  =
  ## # Description
  ## Writes an unsigned 64-bit integer to a specified memory address.
  ##
  ## # Parameters
  ##  - `address`: The memory address where the unsigned 64-bit integer will be written.
  ##  - `value`: The unsigned 64-bit integer value that will be written to the memory address.
  writememory(address, value)

proc write_int8*(address: uintptrt; value: int8)  : bool {.exportpy.}  =
  ## # Description
  ## Writes a signed 8-bit integer to a specified memory address.
  ##
  ## # Parameters
  ##  - `address`: The memory address where the signed 8-bit integer will be written.
  ##  - `value`: The signed 8-bit integer value that will be written to the memory address.
  writememory(address, value)

proc write_int16*(address: uintptrt; value: int16)  : bool {.exportpy.}  =
  ## # Description
  ## Writes a signed 16-bit integer to a specified memory address.
  ##
  ## # Parameters
  ##  - `address`: The memory address where the signed 16-bit integer will be written.
  ##  - `value`: The signed 16-bit integer value that will be written to the memory address.
  writememory(address, value)

proc write_int32*(address: uintptrt; value: int32)  : bool {.exportpy.}  =
  ## # Description
  ## Writes a signed 32-bit integer to a specified memory address.
  ##
  ## # Parameters
  ##  - `address`: The memory address where the signed 32-bit integer will be written.
  ##  - `value`: The signed 32-bit integer value that will be written to the memory address.
  writememory(address, value)

proc write_int64*(address: uintptrt; value: int64) : bool  {.exportpy.}  =
  ## # Description
  ## Writes a signed 64-bit integer to a specified memory address.
  ##
  ## # Parameters
  ##  - `address`: The memory address where the signed 64-bit integer will be written.
  ##  - `value`: The signed 64-bit integer value that will be written to the memory address.
  writememory(address, value)

proc write_float32*(address: uintptrt; value: float32) : bool {.exportpy.}  =
  ## # Description
  ## Writes a 32-bit floating-point number to a specified memory address.
  ##
  ## # Parameters
  ##  - `address`: The memory address where the 32-bit floating-point number will be written.
  ##  - `value`: The 32-bit floating-point number value that will be written to the memory address.
  writememory(address, value)

proc write_float64*(address: uintptrt; value: float64)  : bool {.exportpy.}  =
  ## # Description
  ## Writes a 64-bit floating-point number to a specified memory address.
  ##
  ## # Parameters
  ##  - `address`: The memory address where the 64-bit floating-point number will be written.
  ##  - `value`: The 64-bit floating-point number value that will be written to the memory address.
  writememory(address, value)

proc originalwritememoryex(process: ptr Processt; dest: uintptrt ;source: ptr byte; size: csize_t): csize_t {.cdecl, importc: "LM_WriteMemoryEx".}
proc writeMemoryex*[T](process: Processt; address: uintptrt; value: T, size: Natural=1) : bool =
  if protmemoryex(process, address, size.csize_t, Protxrw):
    try:
       when T is typeof string or cstring:
          if originalwritememoryex(process.addr, address, cast[ptr byte](addr value[0]), size.csize_t) == size:
            result = true
          else:
            result = false
       when T is typeof seq:
          if originalwritememoryex(process.addr, address, value[0].addr, size.csize_t) == size:
            result = true
          else:
            result = false
       else:
          if originalwritememoryex(process.addr, address, cast[ptr byte](addr value), sizeof(T).csize_t) == sizeof(T).csize_t:
            result = true
          else:
            result = false
    except:
      if protmemoryex(process, address, size.csize_t, Protxrw):
        if writememoryex(process, address, value, size) == false:
          discard protmemoryex(process, address, size.csize_t, Protr)
      else:
        raise newException(ValueError, "Memory protection error")
    finally:
      if protmemoryex(process, address, size.csize_t, Protr) == false:
        raise newException(ValueError, "Memory protection error")

proc write_uint8ex*(process: Processt; address: uintptrt; value: uint8):bool {.exportpy.}  =
  ## # Description
  ## Writes an unsigned 8-bit integer to a specified memory address in a target process.
  ##
  ## # Parameters
  ##  - `process`: A pointer to the process that the unsigned 8-bit integer will be written to.
  ##  - `address`: The memory address where the unsigned 8-bit integer will be written.
  ##  - `value`: The unsigned 8-bit integer value that will be written to the memory address.
  writememoryex(process, address, value)

proc write_uint16ex*(process: Processt; address: uintptrt; value: uint16):bool  {.exportpy.}  =
  ## # Description
  ## Writes an unsigned 16-bit integer to a specified memory address in a target process.
  ##
  ## # Parameters
  ##  - `process`: A pointer to the process that the unsigned 16-bit integer will be written to.
  ##  - `address`: The memory address where the unsigned 16-bit integer will be written.
  ##  - `value`: The unsigned 16-bit integer value that will be written to the memory address.
  writememoryex(process, address, value)

proc write_uint32ex*(process: Processt; address: uintptrt; value: uint32):bool  {.exportpy.}  =
  ## # Description
  ## Writes an unsigned 32-bit integer to a specified memory address in a target process.
  ##
  ## # Parameters
  ##  - `process`: A pointer to the process that the unsigned 32-bit integer will be written to.
  ##  - `address`: The memory address where the unsigned 32-bit integer will be written.
  ##  - `value`: The unsigned 32-bit integer value that will be written to the memory address.
  writememoryex(process, address, value)

proc write_uint64ex*(process: Processt; address: uintptrt; value: uint64):bool  {.exportpy.}  =
  ## # Description
  ## Writes an unsigned 64-bit integer to a specified memory address in a target process.
  ##
  ## # Parameters
  ##  - `process`: A pointer to the process that the unsigned 64-bit integer will be written to.
  ##  - `address`: The memory address where the unsigned 64-bit integer will be written.
  ##  - `value`: The unsigned 64-bit integer value that will be written to the memory address.
  writememoryex(process, address, value)

proc write_int8ex*(process: Processt; address: uintptrt; value: int8):bool  {.exportpy.}  =
  ## # Description
  ## Writes a signed 8-bit integer to a specified memory address in a target process.
  ##
  ## # Parameters
  ##  - `process`: A pointer to the process that the signed 8-bit integer will be written to.
  ##  - `address`: The memory address where the signed 8-bit integer will be written.
  ##  - `value`: The signed 8-bit integer value that will be written to the memory address.
  writememoryex(process, address, value)

proc write_int16ex*(process: Processt; address: uintptrt; value: int16):bool  {.exportpy.}  =
  ## # Description
  ## Writes a signed 16-bit integer to a specified memory address in a target process.
  ##
  ## # Parameters
  ##  - `process`: A pointer to the process that the signed 16-bit integer will be written to.
  ##  - `address`: The memory address where the signed 16-bit integer will be written.
  ##  - `value`: The signed 16-bit integer value that will be written to the memory address.
  writememoryex(process, address, value)

proc write_int32ex*(process: Processt; address: uintptrt; value: int32):bool  {.exportpy.}  =
  ## # Description
  ## Writes a signed 32-bit integer to a specified memory address in a target process.
  ##
  ## # Parameters
  ##  - `process`: A pointer to the process that the signed 32-bit integer will be written to.
  ##  - `address`: The memory address where the signed 32-bit integer will be written.
  ##  - `value`: The signed 32-bit integer value that will be written to the memory address.
  writememoryex(process, address, value)

proc write_int64ex*(process: Processt; address: uintptrt; value: int64):bool  {.exportpy.}  =
  ## # Description
  ## Writes a signed 64-bit integer to a specified memory address in a target process.
  ##
  ## # Parameters
  ##  - `process`: A pointer to the process that the signed 64-bit integer will be written to.
  ##  - `address`: The memory address where the signed 64-bit integer will be written.
  ##  - `value`: The signed 64-bit integer value that will be written to the memory address.
  writememoryex(process, address, value)

proc write_float32ex*(process: Processt; address: uintptrt; value: float32):bool  {.exportpy.}  =
  ## # Description
  ## Writes a 32-bit floating-point number to a specified memory address in a target process.
  ##
  ## # Parameters
  ##  - `process`: A pointer to the process that the 32-bit floating-point number will be written to.
  ##  - `address`: The memory address where the 32-bit floating-point number will be written.
  ##  - `value`: The 32-bit floating-point number value that will be written to the memory address.
  writememoryex(process, address, value)

proc write_float64ex*(process: Processt; address: uintptrt; value: float64):bool  {.exportpy.}  =
  ## # Description
  ## Writes a 64-bit floating-point number to a specified memory address in a target process.
  ##
  ## # Parameters
  ##  - `process`: A pointer to the process that the 64-bit floating-point number will be written to.
  ##  - `address`: The memory address where the 64-bit floating-point number will be written.
  ##  - `value`: The 64-bit floating-point number value that will be written to the memory address.
  writememoryex(process, address, value)

proc originalAllocmemory(size: csize_t; prot: uint32): uintptrt {.cdecl, importc: "LM_AllocMemory".}
proc allocMemory*(size: csize_t; prot: uint32): uintptrt {.exportpy: "alloc_memory".}  =
  ## # Description
  ## The function allocates memory with a specified size and protection flags,
  ## returning the allocated memory address.
  ##
  ## # Parameters
  ##  - `size`: The size of memory to be allocated. If the size is 0, the function will allocate a full page of memory. If a specific size is provided, that amount of memory will be allocated, aligned to the next page size.
  ##  - `prot`: The memory protection flags for the allocated memory region. It is a bit mask of `PROT_X` (execute), `PROT_R` (read), `PROT_W` (write).
  ##
  ## # Return Value
  ## The function returns the memory address of the allocated memory with
  ## the specified allocation options, or `(uintptrt(-1))` if it fails.
  return originalAllocmemory(size, prot)


proc originalAllocmemoryex(process: ptr Processt; size: csize_t; prot: uint32): uintptrt {. cdecl, importc: "LM_AllocMemoryEx".}
proc allocMemoryex*(process: Processt; size: csize_t; prot: uint32): uintptrt {.exportpy: "alloc_memory_ex".}  =
  ## # Description
  ## The function allocates memory in a specified process with the given size
  ## and memory protection flags.
  ##
  ## # Parameters
  ##  - `process`: A pointer to the process that the memory will be allocated to.
  ##  - `size`: The size of memory to be allocated. If the size is 0, the function will allocate a full page of memory. If a specific size is provided, that amount of memory will be allocated, aligned to the next page size.
  ##  - `prot`: The memory protection flags for the allocated memory region. It is a bit mask of `PROT_X` (execute), `PROT_R` (read), `PROT_W` (write).
  ##
  ## # Return Value
  ## The function returns a memory address of type `address_t` if the
  ## memory allocation is successful. If there are any issues, it returns
  ## `(uintptrt(-1))`.
  return originalAllocmemoryex(process.addr, size, prot)


proc originalFreememory(alloc: uintptrt; size: csize_t): boolt {.cdecl, importc: "LM_FreeMemory".}
proc freeMemory*(alloc: uintptrt; size: csize_t): bool {.exportpy: "free_memory".}  =
  ## # Description
  ## The function deallocates memory that was previously allocated with
  ## `AllocMemory`.
  ##
  ## # Parameters
  ##  - `alloc`: The address of the memory block that was previously allocated.
  ##  - `size`: The size of the memory block that was previously allocated. If the size is 0, the function will use the system's page size for unmapping the memory.
  ##
  ## # Return Value
  ## The function returns `TRUE` if the memory deallocation operation
  ## is successful, and `FALSE` if the operation fails.
  return originalFreememory(alloc, size).bool


proc originalFreememoryex(process: ptr Processt; alloc: uintptrt; size: csize_t): boolt {. cdecl, importc: "LM_FreeMemoryEx".}
proc freeMemoryex*(process: Processt; alloc: uintptrt; size: csize_t): bool {.exportpy: "free_memory_ex".}  =
  ## # Description
  ## The function deallocates memory that was previously allocated with
  ## `AllocMemoryEx` on a given process.
  ##
  ## # Parameters
  ##  - `process`: A pointer to the process that the memory will be deallocated from.
  ##  - `alloc`: The address of the memory block that was previously allocated and needs to be freed.
  ##  - `size`: The size of the memory block that was previously allocated and now needs to be freed. If the size is 0, the function will use the system's page size as the default size for freeing the memory.
  ##
  ## # Return Value
  ## The function returns a boolean value (`TRUE` or `FALSE`)
  ## indicating whether the memory deallocation operation was successful or not.
  return originalFreememoryex(process.addr, alloc, size).bool


proc originalDeeppointer(base: uintptrt; offsets: ptr uintptrt; noffsets: csize_t): uintptrt {. cdecl, importc: "LM_DeepPointer".}
proc deepPointer*(base: uintptrt; offsets: seq[uintptrt]): uintptrt {.exportpy: "deep_pointer".}  =
  ## # Description
  ## The function calculates a deep pointer address by applying a series of
  ## offsets to a base address and dereferencing intermediate pointers.
  ##
  ## # Parameters
  ##  - `base`: The starting address from which to calculate the deep pointer.
  ##  - `offsets`: An array of offsets used to navigate through the memory addresses.
  ##
  ## # Return Value
  ## The function returns a deep pointer calculated based on the provided
  ## base address, offsets, and number of offsets. The function iterates through
  ## the offsets, adjusting the base address and dereferencing accordingly.
  return originalDeeppointer(base, cast[ptr uintptrt](addr offsets[0]), offsets.len.csize_t)


proc originalDeeppointerex(process: ptr Processt; base: uintptrt; offsets: ptr uintptrt; noffsets: csize_t): uintptrt {.cdecl, importc: "LM_DeepPointerEx".}
proc deepPointerex*(process: Processt; base: uintptrt; offsets: seq[uintptrt]): uintptrt {.exportpy: "deep_pointer_ex".}  =
  ## # Description
  ## The function `DeepPointerEx` calculates a deep pointer address by applying a series of offsets to a
  ## base address and dereferencing intermediate pointers in a given process's memory space.
  ##
  ## # Parameters
  ##  - `process`: The `process` parameter is a pointer to a structure representing a process in the system. It's the process that the deep pointer will be calculated from.
  ##  - `base`: The `base` parameter in the `DeepPointerEx` function represents the starting address from which to calculate the deep pointer.
  ##  - `offsets`: The `offsets` parameter is a pointer to an array of address_t values. These values are used as offsets to navigate through memory addresses in the `DeepPointerEx` function.
  ##
  ## # Return Value
  ## The function `DeepPointerEx` returns a deep pointer calculated based on the provided base
  ## address, offsets, and number of offsets. The function iterates through the offsets, adjusting the
  ## base address and dereferencing accordingly.
  return originalDeeppointerex(process.addr, base, cast[ptr uintptrt](addr offsets[0]), offsets.len.csize_t)

proc pointerChain64*(process: Processt, base: uintptrt, offsets: openArray[byte]): uint64 {.exportpy.}  =
  ## # Description
  ## This is a pure Nim integration of the DeepPointerEx function. I just like it more this way.
  ##
  ## # Parameters
  ##  - `process`: The process that the deep pointer will be calculated from.
  ##  - `base`: The starting address from which to calculate the deep pointer.
  ##  - `offsets`: A sequence[array like] of offsets used to navigate through the memory addresses.
  ##
  ## # Return Value
  ## The function returns a deep pointer calculated based on the provided
  ## base address, offsets, and number of offsets. The function iterates through
  ## the offsets, adjusting the base address and dereferencing accordingly.
  ##
  ## Example: Pointerchain64(notepadprocess, (notepadmodule.base + 0x000320D8.uint64), @[0x40.uint64, 0x38.uint64, 0x30.uint64, 0x50.uint64])
  result = readmemoryex(process.addr, base, uint64)
  for offset in offsets[0..^2]:
    result = readmemoryex(process.addr, result + offset, uint64)
  result = result + offsets[^1].uint64

proc originalDatascan(data: ptr uint8; datasize: csize_t; address: uintptrt; scansize: csize_t): uintptrt {.cdecl, importc: "LM_DataScan".}
proc dataScan*(data: seq[byte]; address: uintptrt, scansize: csize_t): uintptrt {.exportpy: "data_scan".}  =
  ## # Description
  ## The function scans a specified memory address range for a specific data
  ## pattern and returns the address where the data is found.
  ##
  ## # Parameters
  ##  - `data`: The data to be scanned for in memory.
  ##  - `address`: The starting memory address where the scanning operation will begin. The function will scan a range of memory starting from this address to find the data.
  ##  - `scansize`: The size of the memory region to scan starting from the specified `address`. It determines the range within which the function will search for a match with the provided `data` array.
  ##
  ## # Return Value
  ## The function returns the memory address where a match for the
  ## provided data was found. If no match is found, it returns
  ## `(uintptrt(-1))`.
  return originalDatascan(cast[ptr uint8](addr data[0]), data.len.csize_t, address, scansize)


proc originalDatascanex(process: ptr Processt; data: ptr uint8; datasize: csize_t; address: uintptrt; scansize: csize_t): uintptrt {.cdecl, importc: "LM_DataScanEx".}
proc dataScanex*(process: Processt; data: seq[byte]; address: uintptrt, scansize: csize_t): uintptrt {.exportpy: "data_scan_ex".}  =
  ## # Description
  ## The function scans a specified memory address range for a specific data
  ## pattern in a given process and returns the address where the data is
  ## found.
  ##
  ## # Parameters
  ##  - `process`: The process whose memory will be scanned.
  ##  - `data`: The data to be scanned for in memory.
  ##  - `address`: The starting memory address where the scanning operation will begin. The function will scan a range of memory starting from this address to find the data.
  ##  - `scansize`: The size of the memory region to scan starting from the specified `address`. It determines the range within which the function will search for a match with the provided `data` array.
  ##
  ## # Return Value
  ## The function returns the memory address where a match for the
  ## provided data was found. If no match is found, it returns
  ## `(uintptrt(-1))`.
  originalDatascanex(process.addr, cast[ptr uint8](addr data[0]), data.len.csize_t, address, scansize)


proc originalPatternscan(pattern: ptr uint8; mask: cstring; address: uintptrt; scansize: csize_t): uintptrt {.cdecl, importc: "LM_PatternScan".}
proc patternScan*(pattern: seq[byte]; mask: string; address: uintptrt, scansize: csize_t): uintptrt {.exportpy: "pattern_scan".}  =
  ## # Description
  ## The function searches for a specific pattern in memory based on a given
  ## mask.
  ##
  ## # Parameters
  ##  - `pattern`: The pattern to be searched for in memory. Ex:[0x48.byte, 0xFF.byte, 0x00.byte]
  ##  - `mask`: The pattern mask used for scanning memory. It is used to specify which bytes in the pattern should be matched against the memory content. The mask can contain characters such as '?' which act as wildcards, allowing any byte to be matched. You can also use 'x' to have an exact match. Ex: "x?x"
  ##  - `address`: The starting memory address where the scanning operation will begin. The function will scan the memory starting from this address to find the pattern match.
  ##  - `scansize`: The size of the memory region to scan starting from the specified `address`. It determines the range within which the function will search for the specified pattern based on the provided `pattern` and `mask`.
  ##
  ## # Return Value
  ## The function returns the memory address where a match for the
  ## given pattern and mask is found within the specified scan size starting
  ## from the provided address. If no match is found or if an error occurs,
  ## the function returns `(uintptrt(-1))`.
  return originalPatternscan(cast[ptr uint8](addr pattern[0]), mask, address, scansize)


proc originalPatternscanex(process: ptr Processt; pattern: ptr uint8; mask: cstring; address: uintptrt; scansize: csize_t): uintptrt {.cdecl, importc: "LM_PatternScanEx".}
proc patternScanex*(process: Processt; pattern: seq[byte]; mask: string; address: uintptrt, scansize: csize_t): uintptrt {.exportpy: "pattern_scan_ex".}  =
  ## # Description
  ## The function searches for a specific pattern in memory in a given process based on a mask.
  ##
  ## # Parameters
  ##  - `process`: The process whose memory will be scanned.
  ##  - `pattern`: The pattern to be searched for in memory. Ex:[0x48.byte, 0xFF.byte, 0x00.byte]
  ##  - `mask`: The pattern mask used for scanning memory. It is used to specify which bytes in the pattern should be matched against the memory content. The mask can contain characters such as'?' which act as wildcards, allowing any byte to be matched. You can also use 'x' to have an exact match. Ex: "x?x"
  ##  - `address`: The starting memory address where the scanning operation will begin. The function will scan the memory starting from this address to find the pattern match.
  ##  - `scansize`: The size of the memory region to scan starting from the specified `address`. It determines the range within which the function will search for the specified pattern based on the provided `pattern` and `mask`.
  ##
  ## # Return Value
  ## The function returns the memory address where a match for the given pattern and mask is
  ## found within the specified scan size starting from the provided address. If no match is found or
  ## if an error occurs, the function returns `(uintptrt(-1))`.
  return originalPatternscanex(process.addr, cast[ptr uint8](addr pattern[0]), mask, address, scansize)


proc originalSigscan(signature: cstring; address: uintptrt; scansize: csize_t): uintptrt {. cdecl, importc: "LM_SigScan".}
proc sigScan*(signature: string; address: uintptrt, scansize: csize_t): uintptrt {.exportpy: "sig_scan".}  =
  ## # Description
  ## The function searches for a specific signature pattern in memory starting from a given address
  ## within a specified scan size.
  ##
  ## # Parameters
  ##  - `signature`: The signature to be scanned for in memory. It is used to identify a specific pattern of bytes in memory. You can use `??` to match against any byte, or the byte's hexadecimal value. Example: `"DE AD BE EF ?? ?? 13 37"`.
  ##  - `address`: The starting memory address where the signature scanning will begin. The function will scan the memory starting from this address to find the pattern match.
  ##  - `scansize`: The size of the memory region to scan starting from the `address` parameter. It specifies the number of bytes to search for the signature pattern within the memory region.
  ##
  ## # Return Value
  ## The function retuns either the address of the pattern match found in the specified memory range
  ## or (uintptrt(-1))` if no match is found (or an error occurs).
  return originalSigscan(signature, address, scansize)


proc originalSigscanex(process: ptr Processt; signature: cstring; address: uintptrt; scansize: csize_t): uintptrt {.cdecl, importc: "LM_SigScanEx".}
proc sigScanex*(process: Processt; signature: string; address: uintptrt, scansize: csize_t): uintptrt {.exportpy: "sig_scan_ex".}  =
  ## # Description
  ## The function searches for a specific signature pattern in memory from a given process starting
  ## from a specific address within a specified scan size.
  ##
  ## # Parameters
  ##  - `process`: The process whose memory will be scanned.
  ##  - `signature`: The signature to be scanned for in memory. It is used to identify a specific pattern of bytes in memory. You can use `??` to match against any byte, or the byte's hexadecimal value. Example: `"DE AD BE EF ?? ?? 13 37"`.
  ##  - `address`: The starting memory address where the signature scanning will begin. The function will scan the memory starting from this address to find the pattern match.
  ##  - `scansize`: The size of the memory region to scan starting from the `address` parameter. It specifies the number of bytes to search for the signature pattern within the memory region.
  ##
  ## # Return Value
  ## The function retuns either the address of the pattern match found in the specified memory range
  ## or `(uintptrt(-1))` if no match is found (or an error occurs).
  return originalSigscanex(process.addr, signature, address, scansize)


proc originalgetarchitecture(): uint32 {.cdecl, importc: "LM_GetArchitecture".}
proc getArchitecture*(): uint32 {.exportpy: "get_architecture".}  =
  ## # Description
  ## The function returns the current architecture.
  ##
  ## # Parameters
  ## The function does not have parameters
  ##
  ## # Return Value
  ## The function returns the architecture of the system. It can be one of:
  ## - `ARCH_X86` for 32-bit x86.
  ## - `ARCH_AMD64` for 64-bit x86.
  ## - Check constants for more.
  return originalgetarchitecture()


proc originalFindsymboladdress(module: ptr Modulet; symbolname: cstring): uintptrt {.cdecl, importc: "LM_FindSymbolAddress".}
proc findSymboladdress*(module: Modulet; symbolname: string): uintptrt {.exportpy: "find_symbol_address".}  =
  ## # Description
  ## Finds the address of a symbol within a module.
  ##
  ## # Parameters
  ##  - `module`: The module where the symbol will be looked up from.
  ##  - `symbol_name`: The name of the symbol to look up.
  ##
  ## # Return Value
  ## Returns the address of the symbol, or `(uintptrt(-1))` if it fails.
  return originalFindsymboladdress(module.addr, symbolname)


proc originalAssemble(code: cstring; instructionout: ptr Instructiont): boolt {.cdecl, importc: "LM_Assemble".}
proc assemble*(code: string): Instructiont {.exportpy.}  = 
  ## # Description
  ## The function assembles a single instruction into machine code.
  ##
  ## # Parameters
  ##  - `code`: The instruction to be assembled. Example: `"mov eax, ebx"`.
  ##
  ## # Return Value
  ## The function returns a `Instructiont` structure containing the assembled instruction.
  discard originalAssemble(code, result.addr)


proc originalAssembleex(code: cstring; arch: uint32; bits: csize_t; runtimeaddress: uintptrt; payloadout: ptr ptr uint8): csize_t {. cdecl, importc: "LM_AssembleEx".}
proc assembleex*(code: string, runtimeaddress: uintptrt, arch: uint32 = getarchitecture(), bits: csize_t= getBits()): csize_t {.exportpy.}  =
  ## # Description
  ## The function assembles instructions into machine code.
  ##
  ## # Parameters
  ##  - `code`: The instructions to be assembled. Example: `"mov eax, ebx ; jmp eax"`.
  ##  - `arch`: The architecture to be assembled = defaullt(getarchitecture())
  ##  - `bits`: The bitness of the architecture to be assembled = default(getBits()). It can be `32` or `64`.
  ##  - `runtime_address`: The runtime address to resolve the addressing (for example, relative jumps will be resolved using this address).
  ##  - `payload_out`: A pointer to the buffer that will receive the assembled instructions. The buffer should be freed with `FreePayload` after use.
  ##
  ## # Return Value
  ## On success, it returns a sequence of bytes containing the assembled instructions. On failure, it returns an empty sequence.
  result = (var res: ptr byte; originalAssembleex(code.cstring, arch, bits, runtimeaddress, addr res))


proc originalFreepayload(payload: ptr uint8): void {.cdecl, importc: "LM_FreePayload".}
proc freePayload*(payload: seq[byte]): void {.exportpy: "free_payload".}  =
  ## # Description
  ## The function deallocates memory allocated by `AssembleEx`.
  ##
  ## # Parameters
  ##  - `payload`: The memory to be freed that was allocated by `AssembleEx`
  ##
  ## # Return Value
  ## The function does not return a value
  originalFreepayload(payload[0].addr)


proc originalDisassemble(machinecode: uintptrt; instructionout: ptr Instructiont): boolt {. cdecl, importc: "LM_Disassemble".}
proc disassemble*(machinecode: openArray[byte]): Instructiont {.exportpy.}  =
  ## # Description
  ## The function disassembles one instruction into an `Instructiont` struct.
  ##
  ## # Parameters
  ##  - `machine_code`: The address of the instruction to be disassembled.
  ##
  ## # Return Value
  ## The function returns an `Instructiont` structure containing the disassembled instruction.
  discard originalDisassemble(cast[uintptrt](machinecode[0].addr), result.addr)


proc originalDisassembleex(machinecode: uintptrt; arch: uint32; bits: csize_t; maxsize: csize_t; instructioncount: csize_t; runtimeaddress: uintptrt; instructionsout: ptr ptr Instructiont): csize_t {.cdecl, importc: "LM_DisassembleEx".}
proc disassembleex*(machine_code: openArray[byte], address: uintptrt, maxsize:  csize_t=16,  arch: uint32 = Archx86, bits: csize_t= 64.csize_t,): ptr Instructiont =
  ## # Description
  ## The function disassembles instructions into an array of `Instructiont` structs.
  ##
  ## # Parameters
  ##  - `machine_code`: The address of the instructions to be disassembled.
  ##  - `runtime_address`: The runtime address to resolve the addressing (for example, relative jumps will be resolved using this address).
  ##  - `instruction_count`: The amount of instructions to disassemble (0 for as many as possible, limited by `max_size`) = default(0).
  ##  - `max_size`: The maximum number of bytes to disassemble (0 for as many as possible, limited by `instruction_count`) = default(0).
  ##  - `arch`: The architecture to be disassembled = default(getarchitecture())
  ##  - `bits`: The bitness of the architecture to be disassembled = default(getBits()). It can be `32` or `64`.
  ##
  ## # Return Value
  ## On success, it returns an array of `Instructiont` structures containing the disassembled instructions. On failure, it returns an empty sequence.
  discard originalDisassembleex(cast[uintptrt](machine_code[0].addr), arch, bits, maxsize, 1, address, result.addr)


proc originalFreeinstructions(instructions: ptr Instructiont): void {.cdecl, importc: "LM_FreeInstructions".}
proc freeInstructions*(instructions: seq[Instructiont]): void {.exportpy: "free_instructions".}  =
  ## # Description
  ## The function deallocates the memory allocated by `DisassembleEx` for the disassembled instructions.
  ##
  ## # Parameters
  ##  - `instructions`: The disassembled instructions allocated by `DisassembleEx`
  ##
  ## # Return Value
  ## The function does not return a value
  originalFreeinstructions(instructions[0].addr)


proc originalCodelength(machinecode: uintptrt; minlength: csize_t): csize_t {.cdecl, importc: "LM_CodeLength".}
proc codeLength*(machinecode: uintptrt; minlength: csize_t): csize_t {.exportpy: "code_length".}  =
  ## # Description
  ## The function calculates the size aligned to the instruction length, based on a minimum size.
  ##
  ## # Parameters
  ##  - `machine_code`: The address of the instructions.
  ##  - `min_length`: The minimum size to be aligned to instruction length.
  ##
  ## # Return Value
  ## On success, it returns the aligned size to the next instruction's length. On failure, it returns `0`.
  return originalCodelength(machinecode, minlength)


proc originalCodelengthex(process: ptr Processt; machinecode: uintptrt; minlength: csize_t): csize_t {.cdecl, importc: "LM_CodeLengthEx".}
proc codeLengthex*(process: Processt; machinecode: uintptrt; minlength: csize_t): csize_t {.exportpy: "code_length_ex".}  =
  ## # Description
  ## The function calculates the size aligned to the instruction length, based on a minimum size, in a remote process.
  ##
  ## # Parameters
  ##  - `process`: The remote process to get the aligned length from.
  ##  - `machine_code`: The address of the instructions in the remote process.
  ##  - `min_length`: The minimum size to be aligned to instruction length.
  ##
  ## # Return Value
  ## On success, it returns the aligned size to the next instruction's length. On failure, it returns `0`.
  return originalCodelengthex(process.addr, machinecode, minlength)


proc originalHookcode(fromarg: uintptrt; to: uintptrt; trampolineout: ptr uintptrt): csize_t {. cdecl, importc: "LM_HookCode".}
proc hookCode*(fromarg: uintptrt; to: uintptrt): tuple[trampout: uintptrt, size: csize_t] {.exportpy: "hook_code".}  =
  ## # Description
  ## The function places a hook/detour onto the address `from`, redirecting it to the address `to`. Optionally, it generates a trampoline in `trampoline_out` to call the original function.
  ##
  ## # Parameters
  ##  - `from`: The address where the hook will be placed.
  ##  - `to`: The address where the hook will jump to.
  ##  - `trampoline_out`: Optional pointer to an `address_t` variable that will receive a trampoline/gateway to call the original function.
  ##
  ## # Return Value
  ## The amount of bytes occupied by the hook (aligned to the nearest instruction).
  var t: uintptrt
  result.size = originalHookcode(fromarg, to, t.addr)
  result.trampout = t


proc originalHookcodeex(process: ptr Processt; fromarg: uintptrt; to: uintptrt; trampolineout: ptr uintptrt): csize_t {.cdecl, importc: "LM_HookCodeEx".}
proc hookCodeex*(process: Processt; fromarg: uintptrt; to: uintptrt): tuple[trampout: uintptrt, size: csize_t] {.exportpy: "hook_code_ex".}  =
  ## # Description
  ## The function places a hook/detour onto the address `from` in a remote process, redirecting it to the address `to`.
  ## Optionally, it generates a trampoline in `trampoline_out` to call the original function in the remote process.
  ##
  ## # Parameters
  ##  - `process`: The remote process to place the hook in.
  ##  - `from`: The address where the hook will be placed in the remote process.
  ##  - `to`: The address where the hook will jump to in the remote process.
  ##  - `trampoline_out`: Optional pointer to an `uintptrt` variable that will receive a trampoline/gateway to call the original function in the remote process.
  ##
  ## # Return Value
  ## The amount of bytes occupied by the hook (aligned to the nearest instruction) in the remote process.
  var trampout: uintptrt
  result.size = originalHookcodeex(process.addr, fromarg, to, trampout.addr)
  result.trampout = trampout


proc originalUnhookcode(fromarg: uintptrt; trampoline: uintptrt; size: csize_t): boolt {. cdecl, importc: "LM_UnhookCode".}
proc unhookCode*(fromarg: uintptrt; trampoline: uintptrt; size: csize_t): bool {.exportpy: "unhook_code".}  =
  ## # Description
  ## The function removes a hook/detour placed on the address `from`, restoring it to its original state.
  ## The function also frees the trampoline allocated by `HookCode`.
  ##
  ## # Parameters
  ##  - `from`: The address where the hook was placed.
  ##  - `trampoline`: The address of the trampoline generated by `HookCode`.
  ##  - `size`: The amount of bytes occupied by the hook (aligned to the nearest instruction).
  ##
  ## # Return Value
  ## `TRUE` on success, `FALSE` on failure.
  return originalUnhookcode(fromarg, trampoline, size).bool


proc originalUnhookcodeex(process: ptr Processt; fromarg: uintptrt; trampoline: uintptrt; size: csize_t): boolt {.cdecl, importc: "LM_UnhookCodeEx".}
proc unhookCodeex*(process: Processt; fromarg: uintptrt; trampoline: uintptrt; size: csize_t): bool {.exportpy: "unhook_code_ex".}  =
  ## # Description
  ## The function removes a hook/detour placed on the address `from` in a remote process, restoring it to its original state.
  ## The function also frees the trampoline allocated by `HookCodeEx`.
  ##
  ## # Parameters
  ##  - `process`: The remote process where the hook was placed.
  ##  - `from`: The address where the hook was placed in the remote process.
  ##  - `trampoline`: The address of the trampoline generated by `HookCodeEx`.
  ##  - `size`: The amount of bytes occupied by the hook (aligned to the nearest instruction) in the remote process.
  ##
  ## # Return Value
  ## `TRUE` on success, `FALSE` on failure.
  return  originalUnhookcodeex(process.addr, fromarg, trampoline, size).bool


proc originalVmtnew(vtable: ptr uintptrt; vmtout: ptr Vmtt): boolt {.cdecl, importc: "LM_VmtNew".}
proc vmtnew*(vtable:  uintptrt): Vmtt  =
  ### Note: Currently not accessible from Python
  ## # Description
  ## The function creates a new VMT manager from a given VMT table.
  ##
  ## # Parameters
  ##  - `vtable`: The address of a VMT.
  ##
  ## # Return Value
  ## The function returns a `Vmtt` structure representing the VMT manager.
  discard originalVmtnew(vtable.addr, result.addr)


proc originalVmthook(vmt: ptr Vmtt; fromfnindex: csize_t; to: uintptrt): boolt {.cdecl, importc: "LM_VmtHook".}
proc vmtHook*(vmt: Vmtt; fromfnindex: csize_t; to: uintptrt): boolt  =
  ### Note: Currently not accessible from Python
  ## # Description
  ## The function hooks the VMT function at index `from_fn_index` in the VMT managed by `vmt`,
  ## changing it to `to`.
  ##
  ## # Parameters
  ##  - `vmt`: The VMT manager.
  ##  - `from_fn_index`: The index of the VMT function to hook.
  ##  - `to`: The function that will replace the original VMT function.
  ##
  ## # Return Value
  ## On success, it returns `TRUE`. On failure, it returns `FALSE`.
  return originalVmthook(vmt.addr, fromfnindex, to)


proc originalVmtunhook(vmt: ptr Vmtt; fnindex: csize_t): void {.cdecl, importc: "LM_VmtUnhook".}
proc vmtUnhook*(vmt:  Vmtt; fnindex: csize_t): void =
  ### Note: Currently not accessible from Python
  ## # Description
  ## The function unhooks the VMT function at index `fn_index` in the VMT managed by `vmt`,
  ## restoring the original function.
  ##
  ## # Parameters
  ##  - `vmt`: The VMT manager.
  ##  - `fn_index`: The index of the VMT function to unhook
  ##
  ## # Return Value
  ## The function does not return a value
  originalVmtunhook(vmt.addr, fnindex)


proc vmtgetoriginaloriginal(vmt: ptr Vmtt; fnindex: csize_t): uintptrt {.discardable, cdecl, importc: "LM_VmtGetOriginal".}
proc vmtgetoriginal*(vmt: Vmtt; fnindex: csize_t): uintptrt =
  ## # Description
  ## The function retrieves the original function pointer from the VMT manager at index `fn_index`.
  ##
  ## # Parameters
  ##  - `vmt`: The VMT manager.
  ##  - `fn_index`: The index of the VMT function to retrieve.
  ##
  ## # Return Value
  ## The function returns the original function pointer from the VMT manager.
  return vmtgetoriginaloriginal(vmt.addr, fnindex)


proc vmtresetoriginal(vmt: ptr Vmtt): void {.discardable, cdecl, importc: "LM_VmtReset".}
proc vmtReset*(vmt: Vmtt): void   =
  ## # Description
  ## The function resets the VMT manager, restoring all original functions.
  ##
  ## # Parameters
  ##  - `vmt`: The VMT manager to reset.
  ##
  ## # Return Value
  ## The function does not return a value
  vmtresetoriginal(vmt.addr)


proc vmtFreeoriginal(vmt: ptr Vmtt): void {.discardable, cdecl, importc: "LM_VmtFree".}
proc vmtFree*(vmt: Vmtt): void   =
  ## # Description
  ## The function frees the VMT manager.
  ##
  ## # Parameters
  ##  - `vmt`: The VMT manager to free.
  ##
  ## # Return Value
  ## The function does not return a value
  vmtfreeoriginal(vmt.addr)

