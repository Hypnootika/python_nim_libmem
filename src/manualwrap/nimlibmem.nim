import typetraits, strutils, os, nimpy
type
  cstr = distinct array[4096, char]
  
pyExportModule("libmem")

converter stringtToCstring(x: cstr): cstring  {.used, inline.}= cast[cstring]((distinctBase(cstr)x)[0].addr)
converter charArrayToCstring(x: array[4096, char]): cstring {.used, inline.} = cast[cstring]((distinctBase(array[4096, char])x)[0].addr)
converter cstringToStringt(x: cstring): cstr {.used, inline.} = cast[cstr]($x)


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
    vtable*: ptr uintptrt
    hkentries*: ptr Vmtentryt
  Vmtt* = structvmtt


proc cb[T](c: ptr T; arg: pointer): boolt {.cdecl.} =
  cast[ptr seq[T]](arg)[].add(c[])
  result = 1

proc originalEnumprocesses(callback: proc (a0: ptr Processt; a1: pointer): boolt {.cdecl.}; arg: pointer): boolt {.cdecl, importc: "LM_EnumProcesses".}
proc Enumprocesses*(): seq[Processt]  = 
  # EnumProcesses
  ## 
  ## ```c
  ##  bool_t 
  ## EnumProcesses(bool_t ( *callback)(process_t *process,
  ## 					       void_t    *arg),
  ## 		 void_t          *arg);
  ## ```
  ## 
  ## # Description
  ## Enumerates processes on a system and calls a callback function for each process found.
  ## 
  ## # Parameters
  ##  - `callback`: The callback function that will receive the current
  ## process in the enumeration and an extra argument. This function
  ## should return `TRUE` to continue the enumeration, or `FALSE`
  ## to stop it.
  ##  - `arg`: The user-defined data structure that will be passed to the
  ## callback function along with the `process_t` structure.
  ## 
  ## # Return Value
  ## `TRUE` on success, or `FALSE` on failure.
  ## 
  discard originalEnumprocesses(cb, result.addr)




proc originalGetprocess(processout: ptr Processt): boolt {.cdecl, importc: "LM_GetProcess".}
proc Getprocess*(): Processt {.exportpy.}  = 
  # GetProcess
  ## 
  ## ```c
  ##  bool_t 
  ## GetProcess(process_t *process_out);
  ## ```
  ## 
  ## # Description
  ## Retrieves information about the current process, including its PID,
  ## parent PID, path, name, start time, and architecture bits.
  ## 
  ## # Parameters
  ##  - `process_out`: A pointer to the `process_t` structure that will be populated
  ## with information about the current process.
  ## 
  ## # Return Value
  ## `TRUE` if the process information was successfully
  ## retrieved or `FALSE` if there was an error.
  ## 
  discard originalGetprocess(result.addr)



proc originalGetprocessex(pid: uint32; processout: ptr Processt): boolt {.cdecl, importc: "LM_GetProcessEx".}
proc Getprocessex*(pid: uint32): Processt {.exportpy.}  = 
  # GetProcessEx
  ## 
  ## ```c
  ##  bool_t 
  ## GetProcessEx(pid_t      pid,
  ## 		process_t *process_out);
  ## ```
  ## 
  ## # Description
  ## Retrieves information about a specified process identified by its process ID.
  ## 
  ## # Parameters
  ##  - `pid`: The process ID of the process for which you want to
  ## retrieve information.
  ##  - `process_out`: A pointer to the `process_t` structure that will be
  ## populated with information about the specified process.
  ## 
  ## # Return Value
  ## `TRUE` if the process information was successfully
  ## retrieved or `FALSE` if there was an issue during the
  ## retrieval process.
  ## 
  discard originalGetprocessex(pid, result.addr)



proc originalFindprocess(processname: cstring; processout: ptr Processt): boolt {.cdecl, importc: "LM_FindProcess".}
proc Findprocess*(processname: string): Processt {.exportpy.}  = 
  # FindProcess
  ## 
  ## ```c
  ##  bool_t 
  ## FindProcess(string_t   process_name,
  ## 	       process_t *process_out);
  ## ```
  ## 
  ## # Description
  ## Searches for a process by name and returns whether the process was
  ## found or not.
  ## 
  ## # Parameters
  ##  - `process_name`: The name of the process you are trying to find
  ## (e.g `game.exe`). It can also be a relative path, such as
  ## `/game/hello` for a process at `/usr/share/game/hello`.
  ##  - `process_out`: A pointer to the `process_t` structure that will be
  ## populated with information about the found process.
  ## 
  ## # Return Value
  ## `TRUE` if the process with the specified name was found
  ## successfully or `FALSE` otherwise.
  ## 
  discard originalFindprocess(processname, result.addr)



proc originalIsprocessalive(process: ptr Processt): boolt {.cdecl, importc: "LM_IsProcessAlive".}
proc Isprocessalive*(process: Processt): bool {.exportpy.}  = 
  # IsProcessAlive
  ## 
  ## ```c
  ##  bool_t 
  ## IsProcessAlive(const process_t *process);
  ## ```
  ## 
  ## # Description
  ## Checks if a given process is alive based on its PID and start time.
  ## 
  ## # Parameters
  ##  - `process`: The process that will be checked.
  ## 
  ## # Return Value
  ## `TRUE` if the process specified by the input `process_t`
  ## is alive or `FALSE` otherwise.
  ## 
  originalIsprocessalive(process.addr).bool



proc originalGetbits(): csize_t {.cdecl, importc: "LM_GetBits".}
proc Getbits*(): csize_t {.exportpy.}  = 
  # GetBits
  ## 
  ## ```c
  ##  size_t 
  ## GetBits();
  ## ```
  ## 
  ## # Description
  ## Returns the size of a pointer in bits, which corresponds to the current
  ## process's bits (32 bits or 64 bits).
  ## 
  ## # Parameters
  ## The function does not have parameters
  ## 
  ## # Return Value
  ## The size of a pointer in bits.
  ## 
  originalGetbits()



proc originalGetsystembits(): csize_t {.cdecl, importc: "LM_GetSystemBits".}
proc Getsystembits*(): csize_t {.exportpy.}  = 
  # GetSystemBits
  ## 
  ## ```c
  ##  size_t 
  ## GetSystemBits();
  ## ```
  ## 
  ## # Description
  ## Returns the system architecture bits (32 bits or 64 bits).
  ## 
  ## # Parameters
  ## The function does not have parameters
  ## 
  ## # Return Value
  ## The system bits (32 or 64).
  ## 
  originalGetsystembits()



proc originalEnumthreads(callback: proc (a0: ptr Threadt; a1: pointer): boolt {.cdecl.}; arg: pointer): boolt {.cdecl, importc: "LM_EnumThreads".}
proc Enumthreads*(): seq[Threadt] {.exportpy.}  = 
  # EnumThreads
  ## 
  ## ```c
  ##  bool_t 
  ## EnumThreads(bool_t ( *callback)(thread_t *thread,
  ## 					     void_t   *arg),
  ## 	       void_t          *arg);
  ## ```
  ## 
  ## # Description
  ## Enumerates threads in the current process and calls a callback
  ## function for each thread found.
  ## 
  ## # Parameters
  ##  - `callback`: The callback function that will receive the current
  ## thread in the enumeration and an extra argument. This function
  ## should return `TRUE` to continue the enumeration, or `FALSE`
  ## to stop it.
  ##  - `arg`: The user-defined data structure that will be passed to
  ## the callback function `callback` during thread enumeration. This
  ## allows you to pass additional information or context to the
  ## callback function if needed.
  ## 
  ## # Return Value
  ## The function `EnumThreads` returns a boolean value of
  ## type `bool_t`, containing `TRUE` if it succeeds, or
  ## `FALSE` if it fails.
  ## 
  discard originalEnumthreads(cb, result.addr)



proc originalEnumthreadsex(process: ptr Processt; callback: proc (a0: ptr Threadt; a1: pointer): boolt {.cdecl.}; arg: pointer): boolt {.cdecl, importc: "LM_EnumThreadsEx".}
proc Enumthreadsex*(process: Processt): seq[Threadt] {.exportpy.}  = 
  # EnumThreadsEx
  ## 
  ## ```c
  ##  bool_t 
  ## EnumThreadsEx(const process_t *process,
  ## 		 bool_t ( *callback)(thread_t *thread,
  ## 					       void_t   *arg),
  ## 		 void_t          *arg);
  ## ```
  ## 
  ## # Description
  ## Enumerates threads of a given process and invokes a callback
  ## function for each thread.
  ## 
  ## # Parameters
  ##  - `process`: The process you want to enumerate the threads from.
  ##  - `callback`: The callback function that will receive the current
  ## thread in the enumeration and an extra argument. This function
  ## should return `TRUE` to continue the enumeration, or `FALSE`
  ## to stop it.
  ##  - `arg`: The user-defined data that can be passed to the callback
  ## function. It allows you to provide additional information or
  ## context to the callback function when iterating over threads in a
  ## process.
  ## 
  ## # Return Value
  ## The function `EnumThreadsEx` returns a boolean value,
  ## either `TRUE` or `FALSE`, depending on the success of the
  ## operation.
  ## 
  discard originalEnumthreadsex(process.addr, cb, result.addr)



proc originalGetthread(threadout: ptr Threadt): boolt {.cdecl, importc: "LM_GetThread".}
proc Getthread*(): Threadt {.exportpy.}  = 
  # GetThread
  ## 
  ## ```c
  ##  bool_t 
  ## GetThread(thread_t *thread_out);
  ## ```
  ## 
  ## # Description
  ## Retrieves information about the thread it's running from.
  ## 
  ## # Parameters
  ##  - `thread_out`: A pointer to the `thread_t` structure that will be populated
  ## with information about the current thread, specifically the thread ID (`tid`) and
  ## the process ID (`owner_pid`).
  ## 
  ## # Return Value
  ## `TRUE` if the thread information was successfully
  ## retrieved and stored in the provided `thread_t` structure.
  ## Otherwise, the function returns `FALSE`.
  ## 
  discard originalGetthread(result.addr)



proc originalGetthreadex(process: ptr Processt; threadout: ptr Threadt): boolt {.cdecl, importc: "LM_GetThreadEx".}
proc Getthreadex*(process: Processt): Threadt {.exportpy.}  = 
  # GetThreadEx
  ## 
  ## ```c
  ##  bool_t 
  ## GetThreadEx(const process_t *process,
  ## 	       thread_t        *thread_out);
  ## ```
  ## 
  ## # Description
  ## Retrieves information about a thread in a process.
  ## 
  ## # Parameters
  ##  - `process`: The process that the thread will be retrieved from.
  ##  - `thread_out`: A pointer to the `thread_t` variable where the function will
  ## store the thread information retrieved from the process.
  ## 
  ## # Return Value
  ## `TRUE` if the thread was retrieved successfully, or
  ## `FALSE` if it fails.
  ## 
  discard originalGetthreadex(process.addr, result.addr)



proc originalGetthreadprocess(thread: ptr Threadt; processout: ptr Processt): boolt {. cdecl, importc: "LM_GetThreadProcess".}
proc Getthreadprocess*(thread: Threadt): Processt {.exportpy.}  = 
  # GetThreadProcess
  ## 
  ## ```c
  ##  bool_t 
  ## GetThreadProcess(const thread_t *thread,
  ## 		    process_t      *process_out);
  ## ```
  ## 
  ## # Description
  ## Retrieves the process that owns a given thread.
  ## 
  ## # Parameters
  ##  - `thread`: The thread whose process will be retrieved.
  ##  - `process_out`: A pointer to the `process_t` structure where the function
  ## `GetThreadProcess` will store the process information related to
  ## the given thread.
  ## 
  ## # Return Value
  ## `TRUE` if the operation was successful or `FALSE`
  ## otherwise.
  ## 
  discard originalGetthreadprocess(thread.addr, result.addr)



proc originalEnummodules(callback: proc (a0: ptr Modulet; a1: pointer): boolt {.cdecl.}; arg: pointer): boolt {.cdecl, importc: "LM_EnumModules".}
proc Enummodules*(): seq[Modulet] {.exportpy.}  = 
  # EnumModules
  ## 
  ## ```c
  ##  bool_t 
  ## EnumModules(bool_t ( *callback)(module_t *module,
  ## 					     void_t   *arg),
  ## 	       void_t          *arg);
  ## ```
  ## 
  ## # Description
  ## Enumerates modules in the current process and calls a callback function
  ## for each module found.
  ## 
  ## # Parameters
  ##  - `callback`: The callback function that will receive the current module in
  ## the enumeration and an extra argument. This function should return `TRUE`
  ## to continue the enumeration, or `FALSE` to stop it.
  ##  - `arg`: An extra argument that is passed to the callback function. This allows
  ## you to provide additional information or context to the callback function when
  ## it is invoked during the enumeration of modules.
  ## 
  ## # Return Value
  ## Returns `TRUE` if the enumeration succeeds, or `FALSE` if it fails.
  ## 
  discard originalEnummodules(cb, result.addr)



proc originalEnummodulesex(process: ptr Processt; callback: proc (a0: ptr Modulet; a1: pointer): boolt {.cdecl.}; arg: pointer): boolt {.cdecl, importc: "LM_EnumModulesEx".}
proc Enummodulesex*(process: Processt): seq[Modulet] {.exportpy.}  = 
  # EnumModulesEx
  ## 
  ## ```c
  ##  bool_t 
  ## EnumModulesEx(const process_t *process,
  ## 		 bool_t ( *callback)(module_t *module,
  ## 					       void_t   *arg),
  ## 		 void_t          *arg);
  ## ```
  ## 
  ## # Description
  ## Enumerates modules in a specified process and calls a callback function
  ## for each module found.
  ## 
  ## # Parameters
  ##  - `process`: The process that the modules will be enumerated from.
  ##  - `callback`: The callback function that will receive the current module in
  ## the enumeration and an extra argument. This function should return `TRUE`
  ## to continue the enumeration, or `FALSE` to stop it.
  ##  - `arg`: An extra argument that is passed to the callback function. This allows
  ## you to provide additional information or context to the callback function when
  ## it is invoked during the enumeration of modules.
  ## 
  ## # Return Value
  ## Returns `TRUE` if the enumeration succeeds, or `FALSE` if it fails.
  ## 
  discard originalEnummodulesex(process.addr, cb, result.addr)



proc originalFindmodule(name: cstring; moduleout: ptr Modulet): boolt {.cdecl, importc: "LM_FindModule".}
proc Findmodule*(name: string): Modulet {.exportpy.}  = 
  # FindModule
  ## 
  ## ```c
  ##  bool_t 
  ## FindModule(string_t  name,
  ## 	      module_t *module_out);
  ## ```
  ## 
  ## # Description
  ## Finds a module by name and populates the `module_out` parameter with the found module information.
  ## 
  ## # Parameters
  ##  - `name`: The name of the module to find (e.g `game.dll`). It can also be a
  ## relative path, such as `/game/hello` for a module at `/usr/share/game/hello`.
  ##  - `module_out`: A pointer to a `module_t` structure. This function populates
  ## this structure with information about the found module, containing information
  ## such as base, end, size, path and name.
  ## 
  ## # Return Value
  ## Returns `TRUE` if the module is found successfully, otherwise it
  ## returns `FALSE`.
  ## 
  discard originalFindmodule(name, result.addr)



proc originalFindmoduleex(process: ptr Processt; name: cstring; moduleout: ptr Modulet): boolt {. cdecl, importc: "LM_FindModuleEx".}
proc Findmoduleex*(process: Processt; name: string): Modulet {.exportpy.}  = 
  # FindModuleEx
  ## 
  ## ```c
  ##  bool_t 
  ## FindModuleEx(const process_t *process,
  ## 		string_t         name,
  ## 		module_t        *module_out);
  ## ```
  ## 
  ## # Description
  ## Finds a module by name in a specified process and populates the `module_out` parameter with the found module information.
  ## 
  ## # Parameters
  ##  - `process`: The process that the module will be searched in.
  ##  - `name`: The name of the module to find (e.g `game.dll`). It can also be a
  ## relative path, such as `/game/hello` for a module at `/usr/share/game/hello`.
  ##  - `module_out`: A pointer to a `module_t` structure. This function populates
  ## this structure with information about the found module, containing information
  ## such as base, end, size, path and name.
  ## 
  ## # Return Value
  ## Returns `TRUE` if the module is found successfully, otherwise it
  ## returns `FALSE`.
  ## 
  discard originalFindmoduleex(process.addr, name, result.addr)



proc originalLoadmodule(path: cstring; moduleout: ptr Modulet): boolt {.cdecl, importc: "LM_LoadModule".}
proc Loadmodule*(path: string): Modulet {.exportpy.}  = 
  # LoadModule
  ## 
  ## ```c
  ##  bool_t 
  ## LoadModule(string_t  path,
  ## 	      module_t *module_out);
  ## ```
  ## 
  ## # Description
  ## Loads a module from a specified path into the current process.
  ## 
  ## # Parameters
  ##  - `path`: The path of the module to be loaded.
  ##  - `module_out`: A pointer to a `module_t` type, which is used to store information
  ## about the loaded module (optional).
  ## 
  ## # Return Value
  ## Returns `TRUE` is the module was loaded successfully, or `FALSE` if it fails.
  ## 
  discard originalLoadmodule(path, result.addr)



proc originalLoadmoduleex(process: ptr Processt; path: cstring; moduleout: ptr Modulet): boolt {. cdecl, importc: "LM_LoadModuleEx".}
proc Loadmoduleex*(process: Processt; path: string; m: Modulet): bool {.exportpy.}  = 
  # LoadModuleEx
  ## 
  ## ```c
  ##  bool_t 
  ## LoadModuleEx(const process_t *process,
  ## 		string_t         path,
  ## 		module_t        *module_out);
  ## ```
  ## 
  ## # Description
  ## Loads a module from a specified path into a specified process.
  ## 
  ## # Parameters
  ##  - `process`: The process that the module will be loaded into.
  ##  - `path`: The path of the module to be loaded.
  ##  - `module_out`: A pointer to a `module_t` type, which is used to store information
  ## about the loaded module (optional).
  ## 
  ## # Return Value
  ## Returns `TRUE` is the module was loaded successfully, or `FALSE` if it fails.
  ## 
  discard originalLoadmoduleex(process.addr, path, m.addr).bool



proc originalUnloadmodule(module: ptr Modulet): boolt {.cdecl, importc: "LM_UnloadModule".}
proc Unloadmodule*(module: Modulet): bool {.exportpy.}  = 
  # UnloadModule
  ## 
  ## ```c
  ##  bool_t 
  ## UnloadModule(const module_t *module);
  ## ```
  ## 
  ## # Description
  ## Unloads a module from the current process.
  ## 
  ## # Parameters
  ##  - `module`: The module that you want to unload from the process.
  ## 
  ## # Return Value
  ## Returns `TRUE` if the module was successfully unloaded, and `FALSE` if it fails.
  ## 
  originalUnloadmodule(module.addr).bool



proc originalUnloadmoduleex(process: ptr Processt; module: ptr Modulet): boolt {.cdecl, importc: "LM_UnloadModuleEx".}
proc Unloadmoduleex*(process: Processt; module: Modulet): bool {.exportpy.}  = 
  # UnloadModuleEx
  ## 
  ## ```c
  ##  bool_t 
  ## UnloadModuleEx(const process_t *process,
  ## 		  const module_t  *module);
  ## ```
  ## 
  ## # Description
  ## Unloads a module from a specified process.
  ## 
  ## # Parameters
  ##  - `process`: The process that the module will be unloaded from.
  ##  - `module`: The module that you want to unload from the process.
  ## 
  ## # Return Value
  ## Returns `TRUE` if the module was successfully unloaded, and `FALSE` if it fails.
  ## 
  originalUnloadmoduleex(process.addr, module.addr).bool



proc originalEnumsymbols(module: ptr Modulet; callback: proc (a0: ptr Symbolt; a1: pointer): boolt {.cdecl.}; arg: pointer): boolt {.cdecl, importc: "LM_EnumSymbols".}
proc Enumsymbols*(module: Modulet): seq[Symbolt] {.exportpy.}  = 
  # EnumSymbols
  ## 
  ## ```c
  ##  bool_t 
  ## EnumSymbols(const module_t  *module,
  ## 	       bool_t ( *callback)(symbol_t *symbol,
  ## 					     void_t   *arg),
  ## 	       void_t          *arg);
  ## ```
  ## 
  ## # Description
  ## Enumerates symbols in a module and calls a callback function for each symbol found.
  ## 
  ## # Parameters
  ##  - `module`: The module where the symbols will be enumerated from.
  ##  - `callback`: A function pointer that will receive each symbol in the enumeration and an extra argument.
  ## The callback function should return `TRUE` to continue the enumeration or `FALSE` to stop it.
  ##  - `arg`: A pointer to user-defined data that can be passed to the callback function.
  ## It allows you to provide additional information or context.
  ## 
  ## # Return Value
  ## Returns `TRUE` if the enumeration succeeds, `FALSE` otherwise.
  ## 
  discard originalEnumsymbols(module.addr, cb, result.addr)



proc originalEnumsegments(callback: proc (a0: ptr Segmentt; a1: pointer): boolt {.cdecl.}; arg: pointer): boolt {.cdecl, importc: "LM_EnumSegments".}
proc Enumsegments*(): seq[Segmentt] {.exportpy.}  = 
  # EnumSegments
  ## 
  ## ```c
  ##  bool_t 
  ## EnumSegments(bool_t ( *callback)(segment_t *segment,
  ##                 			      void_t    *arg),
  ## 		void_t          *arg);
  ## ```
  ## 
  ## # Description
  ## Enumerates the memory segments of the current process and invokes a callback function for each segment.
  ## 
  ## # Parameters
  ##  - `callback`: A function pointer that will receive each segment in the enumeration and an extra argument.
  ## The callback function should return `TRUE` to continue the enumeration or `FALSE` to stop it.
  ##  - `arg`: A pointer to user-defined data that can be passed to the callback function.
  ## It allows you to provide additional information or context to the callback function when iterating over segments.
  ## 
  ## # Return Value
  ## The function returns `TRUE` if the enumeration was successful, or `FALSE` otherwise.
  ## 
  discard originalEnumsegments(cb, result.addr)



proc originalEnumsegmentsex(process: ptr Processt; callback: proc (a0: ptr Segmentt; a1: pointer): boolt {.cdecl.}; arg: pointer): boolt {.cdecl, importc: "LM_EnumSegmentsEx".}
proc Enumsegmentsex*(process: Processt): seq[Segmentt] {.exportpy.}  = 
  # EnumSegmentsEx
  ## 
  ## ```c
  ##  bool_t 
  ## EnumSegmentsEx(const process_t *process,
  ##                   bool_t ( *callback)(segment_t *segment,
  ## 						void_t    *arg),
  ## 		  void_t          *arg);
  ## ```
  ## 
  ## # Description
  ## Enumerates the memory segments of a given process and invokes a callback function for each segment.
  ## 
  ## # Parameters
  ##  - `process`: A pointer to a structure containing information about the process whose segments
  ## will be enumerated.
  ##  - `callback`: A function pointer that will receive each segment in the enumeration and an extra argument.
  ## The callback function should return `TRUE` to continue the enumeration or `FALSE` to stop it.
  ##  - `arg`: A pointer to user-defined data that can be passed to the callback function.
  ## It allows you to provide additional information or context to the callback function when iterating over segments.
  ## 
  ## # Return Value
  ## The function returns `TRUE` if the enumeration was successful, or `FALSE` otherwise.
  ## 
  discard originalEnumsegmentsex(process.addr, cb, result.addr)



proc originalFindsegment(address: uintptrt; segmentout: ptr Segmentt): boolt {.cdecl, importc: "LM_FindSegment".}
proc Findsegment*(address: uintptrt): Segmentt {.exportpy.}  = 
  # FindSegment
  ## 
  ## ```c
  ##  bool_t 
  ## FindSegment(address_t  address,
  ## 	       segment_t *segment_out);
  ## ```
  ## 
  ## # Description
  ## The function `FindSegment` searches for a memory segment that a given address is within and populates the
  ## `segment_out` parameter with the result.
  ## 
  ## # Parameters
  ##  - `address`: The address to search for.
  ##  - `segment_out`: A pointer to an `segment_t` structure to populate with information about the
  ## segment that contains the specified address.
  ## 
  ## # Return Value
  ## The function returns `TRUE` if the specified address is found within a segment, or `FALSE` otherwise.
  ## 
  discard originalFindsegment(address, result.addr)



proc originalFindsegmentex(process: ptr Processt; address: uintptrt; segmentout: ptr Segmentt): boolt {.cdecl, importc: "LM_FindSegmentEx".}
proc Findsegmentex*(process: Processt; address: uintptrt): Segmentt {.exportpy.}  = 
  # FindSegmentEx
  ## 
  ## ```c
  ##  bool_t 
  ## FindSegmentEx(const process_t *process,
  ## 		 address_t        address,
  ## 		 segment_t       *segment_out);
  ## ```
  ## 
  ## # Description
  ## The function `FindSegment` searches for a memory segment that a given address is within and populates the
  ## `segment_out` parameter with the result.
  ## 
  ## # Parameters
  ##  - `process`: A pointer to a structure containing information about the process whose memory
  ## segments will be searched.
  ##  - `address`: The address to search for.
  ##  - `segment_out`: A pointer to an `segment_t` structure to populate with information about the
  ## segment that contains the specified address.
  ## 
  ## # Return Value
  ## The function returns `TRUE` if the specified address is found within a segment, or `FALSE` otherwise.
  ## 
  discard originalFindsegmentex(process.addr, address, result.addr)



proc originalReadmemory(source: uintptrt; dest: ptr uint8; size: csize_t): csize_t {. cdecl, importc: "LM_ReadMemory".}
proc originalReadmemoryex(process: ptr Processt; source: uintptrt; dest: ptr uint8; size: csize_t): csize_t {.cdecl, importc: "LM_ReadMemoryEx".}

proc originalSetmemory(dest: uintptrt; byte: uint8; size: csize_t): csize_t {.cdecl, importc: "LM_SetMemory".}
proc Setmemory*(dest: uintptrt; byte: uint8; size: csize_t): csize_t {.exportpy.}  = 
  # SetMemory
  ## 
  ## ```c
  ##  size_t 
  ## SetMemory(address_t dest,
  ## 	     byte_t    byte,
  ## 	     size_t    size);
  ## ```
  ## 
  ## # Description
  ## Sets a specified memory region to a given byte value.
  ## 
  ## # Parameters
  ##  - `dest`: The destination memory address where the `byte` value will
  ## be written to, starting from this address.
  ##  - `byte`: The value of the byte that will be written to the memory
  ## locations starting from the `dest` address.
  ##  - `size`: The number of bytes to set in the memory starting from
  ## the `dest` address.
  ## 
  ## # Return Value
  ## The number of bytes that were successfully set to the
  ## specified value `byte` in the memory region starting at address
  ## `dest`.
  ## 
  originalSetmemory(dest, byte, size)



proc originalSetmemoryex(process: ptr Processt; dest: uintptrt; byte: uint8; size: csize_t): csize_t {.cdecl, importc: "LM_SetMemoryEx".}
proc Setmemoryex*(process: Processt; dest: uintptrt; byte: uint8; size: csize_t): csize_t {.exportpy.}  = 
  # SetMemoryEx
  ## 
  ## ```c
  ##  size_t 
  ## SetMemoryEx(const process_t *process,
  ## 	       address_t        dest,
  ## 	       byte_t           byte,
  ## 	       size_t           size);
  ## ```
  ## 
  ## # Description
  ## Sets a specified memory region to a given byte value in a target
  ## process.
  ## 
  ## # Parameters
  ##  - `process`: A pointer to the process that the memory will be set.
  ##  - `dest`: The destination address in the target process where the
  ## `byte` value will be written to.
  ##  - `byte`: The value of the byte that will be written to the memory
  ## locations starting from the `dest` address.
  ##  - `size`: The number of bytes to set in the memory starting from
  ## the `dest` address.
  ## 
  ## # Return Value
  ## The number of bytes that were successfully set to the
  ## specified value `byte` in the memory region starting at address
  ## `dest` in the target process. If there are any errors, it returns 0.
  ## 
  originalSetmemoryex(process.addr, dest, byte, size)



proc originalProtmemory(address: uintptrt; size: csize_t; prot: uint32; oldprotout: ptr uint32): boolt {.cdecl, importc: "LM_ProtMemory".}
proc Protmemory*(address: uintptrt; size: csize_t; prot: uint32): bool {.exportpy.}  = 
  # ProtMemory
  ## 
  ## ```c
  ##  bool_t 
  ## ProtMemory(address_t address,
  ## 	      size_t    size,
  ## 	      prot_t    prot,
  ## 	      prot_t   *oldprot_out);
  ## ```
  ## 
  ## # Description
  ## The function sets memory protection flags for a specified memory address range.
  ## 
  ## # Parameters
  ##  - `address`: The memory address to be protected.
  ##  - `size`: The size of memory to be protected. If the size is 0,
  ## the function will default to using the system's page size for the operation.
  ##  - `prot`: The new protection flags that will be applied to the memory region
  ## starting at the specified address. It is a bit mask of `PROT_X`
  ## (execute), `PROT_R` (read), `PROT_W` (write).
  ##  - `oldprot_out`: A pointer to a `prot_t` type variable that will be used to
  ## store the old protection flags of a memory segment before they are updated with
  ## the new protection settings specified by the `prot` parameter.
  ## 
  ## # Return Value
  ## The function returns a boolean value, either `TRUE` or `FALSE`, based on the
  ## success of the memory protection operation.
  ## 
  originalProtmemory(address, size, prot, nil).bool



proc originalProtmemoryex(process: ptr Processt; address: uintptrt; size: csize_t; prot: uint32; oldprotout: ptr uint32): boolt {.cdecl, importc: "LM_ProtMemoryEx".}
proc Protmemoryex*(process: Processt; address: uintptrt; size: csize_t; prot: uint32): bool {.exportpy.}  = 
  # ProtMemoryEx
  ## 
  ## ```c
  ##  bool_t 
  ## ProtMemoryEx(const process_t *process,
  ## 		address_t        address,
  ## 		size_t           size,
  ## 		prot_t           prot,
  ## 		prot_t          *oldprot_out);
  ## ```
  ## 
  ## # Description
  ## The function modifies memory protection flags for a specified address range in a given
  ## process.
  ## 
  ## # Parameters
  ##  - `process`: A pointer to the process that the memory flags will be modified from.
  ##  - `address`: The memory address to be protected.
  ##  - `size`: The size of memory to be protected. If the size is 0,
  ## the function will default to using the system's page size for the operation.
  ##  - `prot`: The new protection flags that will be applied to the memory region
  ## starting at the specified address. It is a bit mask of `PROT_X`
  ## (execute), `PROT_R` (read), `PROT_W` (write).
  ##  - `oldprot_out`: A pointer to a `prot_t` type variable that will be used to
  ## store the old protection flags of a memory segment before they are updated with
  ## the new protection settings specified by the `prot` parameter.
  ## 
  ## # Return Value
  ## The function returns a boolean value indicating whether the memory
  ## protection operation was successful or not. It returns `TRUE` if the
  ## operation was successful and `FALSE` if it was not.
  ## 
  originalProtmemoryex(process.addr, address, size, prot, nil).bool



proc originalAllocmemory(size: csize_t; prot: uint32): uintptrt {.cdecl, importc: "LM_AllocMemory".}
proc Allocmemory*(size: csize_t; prot: uint32): uintptrt {.exportpy.}  = 
  # AllocMemory
  ## 
  ## ```c
  ##  address_t 
  ## AllocMemory(size_t size,
  ## 	       prot_t prot);
  ## ```
  ## 
  ## # Description
  ## The function allocates memory with a specified size and protection flags,
  ## returning the allocated memory address.
  ## 
  ## # Parameters
  ##  - `size`: The size of memory to be allocated. If the size is 0, the
  ## function will allocate a full page of memory. If a specific size is
  ## provided, that amount of memory will be allocated, aligned to the next
  ## page size.
  ##  - `prot`: The memory protection flags for the allocated memory region.
  ## It is a bit mask of `PROT_X` (execute), `PROT_R` (read), `PROT_W`
  ## (write).
  ## 
  ## # Return Value
  ## The function returns the memory address of the allocated memory with
  ## the specified allocation options, or `ADDRESS_BAD` if it fails.
  ## 
  originalAllocmemory(size, prot)



proc originalAllocmemoryex(process: ptr Processt; size: csize_t; prot: uint32): uintptrt {. cdecl, importc: "LM_AllocMemoryEx".}
proc Allocmemoryex*(process: Processt; size: csize_t; prot: uint32): uintptrt {.exportpy.}  = 
  # AllocMemoryEx
  ## 
  ## ```c
  ##  address_t 
  ## AllocMemoryEx(const process_t *process,
  ## 		 size_t           size,
  ## 		 prot_t           prot);
  ## ```
  ## 
  ## # Description
  ## The function allocates memory in a specified process with the given size
  ## and memory protection flags.
  ## 
  ## # Parameters
  ##  - `process`: A pointer to the process that the memory will be allocated to.
  ##  - `size`: The size of memory to be allocated. If the size is 0, the
  ## function will allocate a full page of memory. If a specific size is
  ## provided, that amount of memory will be allocated, aligned to the next
  ## page size.
  ##  - `prot`: The memory protection flags for the allocated memory region.
  ## It is a bit mask of `PROT_X` (execute), `PROT_R` (read), `PROT_W`
  ## (write).
  ## 
  ## # Return Value
  ## The function returns a memory address of type `address_t` if the
  ## memory allocation is successful. If there are any issues, it returns
  ## `ADDRESS_BAD`.
  ## 
  originalAllocmemoryex(process.addr, size, prot)


proc originalFreememory(alloc: uintptrt; size: csize_t): boolt {.cdecl, importc: "LM_FreeMemory".}
proc Freememory*(alloc: uintptrt; size: csize_t): bool {.exportpy.}  = 
  # FreeMemory
  ## 
  ## ```c
  ##  bool_t 
  ## FreeMemory(address_t alloc,
  ## 	      size_t    size);
  ## ```
  ## 
  ## # Description
  ## The function deallocates memory that was previously allocated with
  ## `AllocMemory`.
  ## 
  ## # Parameters
  ##  - `alloc`: The address of the memory block that was previously allocated.
  ##  - `size`: The size of the memory block that was previously allocated.
  ## If the size is 0, the function will use the system's page size for unmapping
  ## the memory.
  ## 
  ## # Return Value
  ## The function returns `TRUE` if the memory deallocation operation
  ## is successful, and `FALSE` if the operation fails.
  ## 
  originalFreememory(alloc, size).bool



proc originalFreememoryex(process: ptr Processt; alloc: uintptrt; size: csize_t): boolt {. cdecl, importc: "LM_FreeMemoryEx".}
proc Freememoryex*(process: Processt; alloc: uintptrt; size: csize_t): bool {.exportpy.}  = 
  # FreeMemoryEx
  ## 
  ## ```c
  ##  bool_t 
  ## FreeMemoryEx(const process_t *process,
  ## 		address_t        alloc,
  ## 		size_t           size);
  ## ```
  ## 
  ## # Description
  ## The function deallocates memory that was previously allocated with
  ## `AllocMemoryEx` on a given process.
  ## 
  ## # Parameters
  ##  - `process`: A pointer to the process that the memory will be deallocated from.
  ##  - `alloc`: The address of the memory block that was previously allocated
  ## and needs to be freed.
  ##  - `size`: The size of the memory block that was previously allocated
  ## and now needs to be freed. If the size is 0, the function will use the
  ## system's page size as the default size for freeing the memory.
  ## 
  ## # Return Value
  ## The function returns a boolean value (`TRUE` or `FALSE`)
  ## indicating whether the memory deallocation operation was successful or
  ## not.
  ## 
  originalFreememoryex(process.addr, alloc, size).bool



proc originalDeeppointer(base: uintptrt; offsets: ptr uintptrt; noffsets: csize_t): uintptrt {. cdecl, importc: "LM_DeepPointer".}
proc Deeppointer*(base: uintptrt; offsets: seq[uintptrt]): uintptrt {.exportpy.}  = 
  # DeepPointer
  ## 
  ## ```c
  ##  address_t 
  ## DeepPointer(address_t        base,
  ## 	       const address_t *offsets,
  ## 	       size_t              noffsets);
  ## ```
  ## 
  ## # Description
  ## The function calculates a deep pointer address by applying a series of
  ## offsets to a base address and dereferencing intermediate pointers.
  ## 
  ## # Parameters
  ##  - `base`: The starting address from which to calculate the deep pointer.
  ##  - `offsets`: An array of offsets used to navigate through the memory addresses.
  ##  - `noffsets`: The number of offsets in the `offsets` array.
  ## 
  ## # Return Value
  ## The function returns a deep pointer calculated based on the provided
  ## base address, offsets, and number of offsets. The function iterates through
  ## the offsets, adjusting the base address and dereferencing accordingly.
  ## 
  originalDeeppointer(base, cast[ptr uintptrt](addr offsets[0]), offsets.len.csize_t)



proc originalDeeppointerex(process: ptr Processt; base: uintptrt; offsets: ptr uintptrt; noffsets: csize_t): uintptrt {.cdecl, importc: "LM_DeepPointerEx".}
proc Deeppointerex*(process: Processt; base: uintptrt; offsets: seq[uintptrt]): uintptrt {.exportpy.}  = 
  # DeepPointerEx
  ## 
  ## ```c
  ##  address_t 
  ## DeepPointerEx(const process_t *process,
  ## 		 address_t        base,
  ## 		 const address_t *offsets,
  ## 		 size_t           noffsets);
  ## ```
  ## 
  ## # Description
  ## The function `DeepPointerEx` calculates a deep pointer address by applying a series of offsets to a
  ## base address and dereferencing intermediate pointers in a given process's memory space.
  ## 
  ## # Parameters
  ##  - `process`: The `process` parameter is a pointer to a structure representing a process in the
  ## system. It's the process that the deep pointer will be calculated from.
  ##  - `base`: The `base` parameter in the `DeepPointerEx` function represents the starting address
  ## from which to calculate the deep pointer.
  ##  - `offsets`: The `offsets` parameter is a pointer to an array of address_t values. These values
  ## are used as offsets to navigate through memory addresses in the `DeepPointerEx` function.
  ##  - `noffsets`: The `noffsets` parameter in the `DeepPointerEx` function represents the number of
  ## offsets in the `offsets` array. It indicates how many elements are in the array that contains the
  ## offsets used to calculate the final memory address.
  ## 
  ## # Return Value
  ## The function `DeepPointerEx` returns a deep pointer calculated based on the provided base
  ## address, offsets, and number of offsets. The function iterates through the offsets, adjusting the
  ## base address and dereferencing accordingly.
  ## 
  originalDeeppointerex(process.addr, base, cast[ptr uintptrt](addr offsets[0]), offsets.len.csize_t)



proc originalDatascan(data: ptr uint8; datasize: csize_t; address: uintptrt; scansize: csize_t): uintptrt {.cdecl, importc: "LM_DataScan".}
proc Datascan*(data: seq[byte]; address: uintptrt): uintptrt {.exportpy.}  = 
  # DataScan
  ## 
  ## ```c
  ##  address_t 
  ## DataScan(bytearray_t data,
  ## 	    size_t      datasize,
  ## 	    address_t   address,
  ## 	    size_t      scansize);
  ## ```
  ## 
  ## # Description
  ## The function scans a specified memory address range for a specific data
  ## pattern and returns the address where the data is found.
  ## 
  ## # Parameters
  ##  - `data`: The data to be scanned for in memory.
  ##  - `datasize`: The size of the data array. It indicates the number of
  ## bytes that need to match consecutively in order to consider it a match.
  ##  - `address`: The starting memory address where the scanning operation
  ## will begin. The function will scan a range of memory starting from this
  ## address to find the data.
  ##  - `scansize`: The size of the memory region to scan starting from the
  ## specified `address`. It determines the range within which the function will
  ## search for a match with the provided `data` array.
  ## 
  ## # Return Value
  ## The function returns the memory address where a match for the
  ## provided data was found. If no match is found, it returns
  ## `ADDRESS_BAD`.
  ## 
  originalDatascan(cast[ptr uint8](addr data[0]), data.len.csize_t, address, data.len.csize_t)



proc originalDatascanex(process: ptr Processt; data: ptr uint8; datasize: csize_t; address: uintptrt; scansize: csize_t): uintptrt {.cdecl, importc: "LM_DataScanEx".}
proc Datascanex*(process: Processt; data: seq[byte]; address: uintptrt): uintptrt {.exportpy.}  = 
  # DataScanEx
  ## 
  ## ```c
  ##  address_t 
  ## DataScanEx(const process_t *process,
  ## 	      bytearray_t      data,
  ## 	      size_t           datasize,
  ## 	      address_t        address,
  ## 	      size_t           scansize);
  ## ```
  ## 
  ## # Description
  ## The function scans a specified memory address range for a specific data
  ## pattern in a given process and returns the address where the data is
  ## found.
  ## 
  ## # Parameters
  ##  - `process`: The process whose memory will be scanned.
  ##  - `data`: The data to be scanned for in memory.
  ##  - `datasize`: The size of the data array. It indicates the number of
  ## bytes that need to match consecutively in order to consider it a match.
  ##  - `address`: The starting memory address where the scanning operation
  ## will begin. The function will scan a range of memory starting from this
  ## address to find the data.
  ##  - `scansize`: The size of the memory region to scan starting from the
  ## specified `address`. It determines the range within which the function will
  ## search for a match with the provided `data` array.
  ## 
  ## # Return Value
  ## The function returns the memory address where a match for the
  ## provided data was found. If no match is found, it returns
  ## `ADDRESS_BAD`.
  ## 
  originalDatascanex(process.addr, cast[ptr uint8](addr data[0]), data.len.csize_t, address, data.len.csize_t)



proc originalPatternscan(pattern: ptr uint8; mask: cstring; address: uintptrt; scansize: csize_t): uintptrt {.cdecl, importc: "LM_PatternScan".}
proc Patternscan*(pattern: seq[byte]; mask: string; address: uintptrt): uintptrt {.exportpy.}  = 
  # PatternScan
  ## 
  ## ```c
  ##  address_t 
  ## PatternScan(bytearray_t pattern,
  ## 	       string_t    mask,
  ## 	       address_t   address,
  ## 	       size_t      scansize);
  ## ```
  ## 
  ## # Description
  ## The function searches for a specific pattern in memory based on a given
  ## mask.
  ## 
  ## # Parameters
  ##  - `pattern`: The pattern to be searched for in memory.
  ##  - `mask`: The pattern mask used for scanning memory. It is used to
  ## specify which bytes in the pattern should be matched against the memory
  ## content. The mask can contain characters such as '?' which act as
  ## wildcards, allowing any byte to be matched. You can also use 'x' to have
  ## an exact match.
  ##  - `address`: The starting memory address where the scanning operation
  ## will begin. The function will scan the memory starting from this address
  ## to find the pattern match.
  ##  - `scansize`: The size of the memory region to scan starting from the
  ## specified `address`. It determines the range within which the function
  ## will search for the specified pattern based on the provided `pattern` and
  ## `mask`.
  ## 
  ## # Return Value
  ## The function returns the memory address where a match for the
  ## given pattern and mask is found within the specified scan size starting
  ## from the provided address. If no match is found or if an error occurs,
  ## the function returns `ADDRESS_BAD`.
  ## 
  originalPatternscan(cast[ptr uint8](addr pattern[0]), mask, address, pattern.len.csize_t)



proc originalPatternscanex(process: ptr Processt; pattern: ptr uint8; mask: cstring; address: uintptrt; scansize: csize_t): uintptrt {.cdecl, importc: "LM_PatternScanEx".}
proc Patternscanex*(process: Processt; pattern: seq[byte]; mask: string; address: uintptrt, scansize: csize_t): uintptrt {.exportpy.}  = 
  # PatternScanEx
  ## 
  ## ```c
  ##  address_t 
  ## PatternScanEx(const process_t *process,
  ## 		 bytearray_t      pattern,
  ## 		 string_t         mask,
  ## 		 address_t        address,
  ## 		 size_t           scansize);
  ## ```
  ## 
  ## # Description
  ## The function searches for a specific pattern in memory in a given process based on a mask.
  ## 
  ## # Parameters
  ##  - `process`: The process whose memory will be scanned.
  ##  - `pattern`: The pattern to be searched for in memory.
  ##  - `mask`: The pattern mask used for scanning memory. It is used to specify which bytes in the
  ## pattern should be matched against the memory content. The mask can contain characters such as
  ## '?' which act as wildcards, allowing any byte to be matched. You can also use 'x' to have an exact
  ## match.
  ##  - `address`: The starting memory address where the scanning operation will begin. The function
  ## will scan the memory starting from this address to find the pattern match.
  ##  - `scansize`: The size of the memory region to scan starting from the specified `address`. It
  ## determines the range within which the function will search for the specified pattern based on the
  ## provided `pattern` and `mask`.
  ## 
  ## # Return Value
  ## The function returns the memory address where a match for the given pattern and mask is
  ## found within the specified scan size starting from the provided address. If no match is found or
  ## if an error occurs, the function returns `ADDRESS_BAD`.
  ## 
  originalPatternscanex(process.addr, cast[ptr uint8](addr pattern[0]), mask, address, scansize)



proc originalSigscan(signature: cstring; address: uintptrt; scansize: csize_t): uintptrt {. cdecl, importc: "LM_SigScan".}
proc Sigscan*(signature: string; address: uintptrt, scansize: csize_t): uintptrt {.exportpy.}  = 
  # SigScan
  ## 
  ## ```c
  ##  address_t 
  ## SigScan(string_t  signature,
  ## 	   address_t address,
  ## 	   size_t    scansize);
  ## ```
  ## 
  ## # Description
  ## The function searches for a specific signature pattern in memory starting from a given address
  ## within a specified scan size.
  ## 
  ## # Parameters
  ##  - `signature`: The signature to be scanned for in memory. It is used to identify a specific
  ## pattern of bytes in memory. You can use `??` to match against any byte, or the byte's hexadecimal
  ## value. Example: `"DE AD BE EF ?? ?? 13 37"`.
  ##  - `address`: The starting memory address where the signature scanning will begin. The function
  ## will scan the memory starting from this address to find the pattern match.
  ##  - `scansize`: The size of the memory region to scan starting from the `address` parameter. It
  ## specifies the number of bytes to search for the signature pattern within the memory region.
  ## 
  ## # Return Value
  ## The function retuns either the address of the pattern match found in the specified memory range
  ## or `ADDRESS_BAD` if no match is found (or an error occurs).
  ## 
  originalSigscan(signature, address, scansize)



proc originalSigscanex(process: ptr Processt; signature: cstring; address: uintptrt; scansize: csize_t): uintptrt {.cdecl, importc: "LM_SigScanEx".}
proc Sigscanex*(process: Processt; signature: string; address: uintptrt, scansize: csize_t): uintptrt {.exportpy.}  = 
  # SigScanEx
  ## 
  ## ```c
  ##  address_t 
  ## SigScanEx(const process_t *process,
  ## 	     string_t         signature,
  ## 	     address_t        address,
  ## 	     size_t           scansize);
  ## ```
  ## 
  ## # Description
  ## The function searches for a specific signature pattern in memory from a given process starting
  ## from a specific address within a specified scan size.
  ## 
  ## # Parameters
  ##  - `process`: The process whose memory will be scanned.
  ##  - `signature`: The signature to be scanned for in memory. It is used to identify a specific
  ## pattern of bytes in memory. You can use `??` to match against any byte, or the byte's hexadecimal
  ## value. Example: `"DE AD BE EF ?? ?? 13 37"`.
  ##  - `address`: The starting memory address where the signature scanning will begin. The function
  ## will scan the memory starting from this address to find the pattern match.
  ##  - `scansize`: The size of the memory region to scan starting from the `address` parameter. It
  ## specifies the number of bytes to search for the signature pattern within the memory region.
  ## 
  ## # Return Value
  ## The function retuns either the address of the pattern match found in the specified memory range
  ## or `ADDRESS_BAD` if no match is found (or an error occurs).
  ## 
  originalSigscanex(process.addr, signature, address, scansize)



proc originalGetarchitecture(): uint32 {.cdecl, importc: "LM_GetArchitecture".}
proc Getarchitecture*(): uint32 {.exportpy.}  = 
  # GetArchitecture
  ## 
  ## ```c
  ##  arch_t 
  ## GetArchitecture();
  ## ```
  ## 
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
  ## - Others (check the enum for `arch_t`)
  ## 
  originalGetarchitecture()



proc originalFindsymboladdress(module: ptr Modulet; symbolname: cstring): uintptrt {.cdecl, importc: "LM_FindSymbolAddress".}
proc Findsymboladdress*(module: Modulet; symbolname: string): uintptrt {.exportpy.}  = 
  # FindSymbolAddress
  ## 
  ## ```c
  ##  address_t 
  ## FindSymbolAddress(const module_t *module,
  ## 		     string_t        symbol_name);
  ## ```
  ## 
  ## # Description
  ## Finds the address of a symbol within a module.
  ## 
  ## # Parameters
  ##  - `module`: The module where the symbol will be looked up from.
  ##  - `symbol_name`: The name of the symbol to look up.
  ## 
  ## # Return Value
  ## Returns the address of the symbol, or `ADDRESS_BAD` if it fails.
  ## 
  originalFindsymboladdress(module.addr, symbolname)



proc originalAssemble(code: cstring; instructionout: ptr Instructiont): boolt {.cdecl, importc: "LM_Assemble".}
proc Assemble*(code: string): Instructiont {.exportpy.}  = 
  # Assemble
  ## 
  ## ```c
  ##  bool_t 
  ## Assemble(string_t code,
  ## 	     inst_t  *instruction_out);
  ## ```
  ## 
  ## # Description
  ## The function assembles a single instruction into machine code.
  ## 
  ## # Parameters
  ##  - `code`: The instruction to be assembled.
  ## Example: `"mov eax, ebx"`.
  ##  - `instruction_out`: The assembled instruction is populated into this parameter.
  ## 
  ## # Return Value
  ## The function returns `TRUE` if it succeeds in assembling the instruction, and
  ## populates the `instruction_out` parameter with the assembled instruction.
  ## If the instruction could not be assembled successfully, then the function returns `FALSE`.
  ## 
  discard originalAssemble(code, result.addr)



proc originalAssembleex(code: cstring; arch: uint32; bits: csize_t; runtimeaddress: uintptrt; payloadout: ptr ptr uint8): csize_t {. cdecl, importc: "LM_AssembleEx".}
#proc Assembleex*(code: string; runtimeaddress: uintptrt; arch: uint32  =
  # AssembleEx
  ## 
  ## ```c
  ##  size_t 
  ## AssembleEx(string_t  code,
  ##               arch_t    arch,
  ## 	      size_t    bits,
  ## 	      address_t runtime_address,
  ## 	      byte_t  **payload_out);
  ## ```
  ## 
  ## # Description
  ## The function assembles instructions into machine code.
  ## 
  ## # Parameters
  ##  - `code`: The instructions to be assembled.
  ## Example: `"mov eax, ebx ; jmp eax"`.
  ##  - `arch`: The architecture to be assembled.
  ##  - `bits`: The bitness of the architecture to be assembled.
  ## It can be `32` or `64`.
  ##  - `runtime_address`: The runtime address to resolve
  ## the addressing (for example, relative jumps will be resolved using this address).
  ##  - `payload_out`: A pointer to the buffer that will receive the assembled instructions.
  ## The buffer should be freed with `FreePayload` after use.
  ## 
  ## # Return Value
  ## On success, it returns the size of the assembled instructions, in bytes.
  ## On failure, it returns `0`.
  ## 
#[  Getarchitecture(); bits: csize_t

  var payload: ptr uint8
  let size = originalAssembleex(code, arch, bits, runtimeaddress, payload.addr)
  result = newSeq[byte](size)
  copyMem(result[0].addr, payload, size)]#

proc originalFreepayload(payload: ptr uint8): void {.cdecl, importc: "LM_FreePayload".}
proc Freepayload*(payload: seq[byte]): void {.exportpy.}  = 
  # FreePayload
  ## 
  ## ```c
  ##  void_t 
  ## FreePayload(byte_t *payload);
  ## ```
  ## 
  ## # Description
  ## The function deallocates memory allocated by `AssembleEx`.
  ## 
  ## # Parameters
  ##  - `payload`: The memory to be freed that was allocated by `AssembleEx`
  ## 
  ## # Return Value
  ## The function does not return a value
  ## 
  originalFreepayload(payload[0].addr)



proc originalDisassemble(machinecode: uintptrt; instructionout: ptr Instructiont): boolt {. cdecl, importc: "LM_Disassemble".}
proc Disassemble*(machinecode: uintptrt): Instructiont {.exportpy.}  = 
  # Disassemble
  ## 
  ## ```c
  ##  bool_t 
  ## Disassemble(address_t machine_code,
  ## 		inst_t   *instruction_out);
  ## ```
  ## 
  ## # Description
  ## The function disassembles one instruction into an `inst_t` struct.
  ## 
  ## # Parameters
  ##  - `machine_code`: The address of the instruction to be disassembled.
  ##  - `instruction_out`: The disassembled instruction is populated into this parameter.
  ## 
  ## # Return Value
  ## `TRUE` on success, `FALSE` on failure.
  ## 
  discard originalDisassemble(machinecode, result.addr)



proc originalDisassembleex(machinecode: uintptrt; arch: uint32; bits: csize_t; maxsize: csize_t; instructioncount: csize_t; runtimeaddress: uintptrt; instructionsout: ptr ptr Instructiont): csize_t {.cdecl, importc: "LM_DisassembleEx".}
#proc Disassembleex*(machinecode: uintptrt;runtimeaddress: uintptrt; arch: uint32  =
  # DisassembleEx
  ## 
  ## ```c
  ##  size_t 
  ## DisassembleEx(address_t machine_code,
  ## 		 arch_t    arch,
  ## 		 size_t    bits,
  ## 		 size_t    max_size,
  ## 		 size_t    instruction_count,
  ## 		 address_t runtime_address,
  ## 		 inst_t  **instructions_out);
  ## ```
  ## 
  ## # Description
  ## The function disassembles instructions into an array of
  ## `inst_t` structs.
  ## 
  ## # Parameters
  ##  - `machine_code`: The address of the instructions to be disassembled.
  ##  - `arch`: The architecture to be disassembled.
  ##  - `bits`: The bitness of the architecture to be disassembled.
  ## It can be `32` or `64`.
  ##  - `max_size`: The maximum number of bytes to disassemble (0 for as
  ## many as possible, limited by `instruction_count`).
  ##  - `instruction_count`: The amount of instructions
  ## to disassemble (0 for as many as possible, limited by `max_size`).
  ##  - `runtime_address`: The runtime address to resolve
  ## the addressing (for example, relative jumps will be resolved using this address).
  ##  - `instructions_out`: A pointer to the buffer that will receive the disassembled instructions.
  ## The buffer should be freed with `FreeInstructions` after use.
  ## 
  ## # Return Value
  ## On success, it returns the count of the instructions disassembled. On failure, it
  ## returns `0`.
  ## 
  #Getarchitecture(); bits: csize_t


proc originalFreeinstructions(instructions: ptr Instructiont): void {.cdecl, importc: "LM_FreeInstructions".}
proc Freeinstructions*(instructions: seq[Instructiont]): void {.exportpy.}  = 
  # FreeInstructions
  ## 
  ## ```c
  ##  void_t 
  ## FreeInstructions(inst_t *instructions);
  ## ```
  ## 
  ## # Description
  ## The function deallocates the memory allocated by `DisassembleEx` for the disassembled instructions.
  ## 
  ## # Parameters
  ##  - `instructions`: The disassembled instructions allocated by `DisassembleEx`
  ## 
  ## # Return Value
  ## The function does not return a value
  ## 
  originalFreeinstructions(instructions[0].addr)



proc originalCodelength(machinecode: uintptrt; minlength: csize_t): csize_t {.cdecl, importc: "LM_CodeLength".}
proc CodeLength*(machinecode: uintptrt; minlength: csize_t): csize_t {.exportpy.}  = 
  # CodeLength
  ## 
  ## ```c
  ##  size_t 
  ## CodeLength(address_t machine_code,
  ## 	      size_t    min_length);
  ## ```
  ## 
  ## # Description
  ## The function calculates the size aligned to the instruction length, based on a minimum size.
  ## 
  ## # Parameters
  ##  - `machine_code`: The address of the instructions.
  ##  - `min_length`: The minimum size to be aligned to instruction length.
  ## 
  ## # Return Value
  ## On success, it returns the aligned size to the next instruction's length. On failure, it returns `0`.
  ## 
  originalCodelength(machinecode, minlength)



proc originalCodelengthex(process: ptr Processt; machinecode: uintptrt; minlength: csize_t): csize_t {.cdecl, importc: "LM_CodeLengthEx".}
proc CodeLengthex*(process: Processt; machinecode: uintptrt; minlength: csize_t): csize_t {.exportpy.}  = 
  # CodeLengthEx
  ## 
  ## ```c
  ##  size_t 
  ## CodeLengthEx(const process_t *process,
  ## 		 address_t        machine_code,
  ## 		 size_t           min_length);
  ## ```
  ## 
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
  ## 
  originalCodelengthex(process.addr, machinecode, minlength)



proc originalHookcode(fromarg: uintptrt; to: uintptrt; trampolineout: ptr uintptrt): csize_t {. cdecl, importc: "LM_HookCode".}
proc Hookcode*(fromarg: uintptrt; to: uintptrt, trampout: uintptrt): csize_t {.exportpy.}  = 
  # HookCode
  ## 
  ## ```c
  ##  size_t 
  ## HookCode(address_t  from,
  ## 	    address_t  to,
  ## 	    address_t *trampoline_out);
  ## ```
  ## 
  ## # Description
  ## The function places a hook/detour onto the address `from`, redirecting it to the address `to`.
  ## Optionally, it generates a trampoline in `trampoline_out` to call the original function.
  ## 
  ## # Parameters
  ##  - `from`: The address where the hook will be placed.
  ##  - `to`: The address where the hook will jump to.
  ##  - `trampoline_out`: Optional pointer to an `address_t` variable that will receive a trampoline/gateway to call the original function.
  ## 
  ## # Return Value
  ## The amount of bytes occupied by the hook (aligned to the nearest instruction).
  ## 
  originalHookcode(fromarg, to, trampout.addr)



proc originalHookcodeex(process: ptr Processt; fromarg: uintptrt; to: uintptrt; trampolineout: ptr uintptrt): csize_t {.cdecl, importc: "LM_HookCodeEx".}
proc Hookcodeex*(process: Processt; fromarg: uintptrt; to: uintptrt, trampout: uintptrt): csize_t {.exportpy.}  = 
  # HookCodeEx
  ## 
  ## ```c
  ##  size_t 
  ## HookCodeEx(const process_t *process,
  ## 	      address_t        from,
  ## 	      address_t        to,
  ## 	      address_t       *trampoline_out);
  ## ```
  ## 
  ## # Description
  ## The function places a hook/detour onto the address `from` in a remote process, redirecting it to the address `to`.
  ## Optionally, it generates a trampoline in `trampoline_out` to call the original function in the remote process.
  ## 
  ## # Parameters
  ##  - `process`: The remote process to place the hook in.
  ##  - `from`: The address where the hook will be placed in the remote process.
  ##  - `to`: The address where the hook will jump to in the remote process.
  ##  - `trampoline_out`: Optional pointer to an `address_t` variable that will receive a trampoline/gateway to call the
  ## original function in the remote process.
  ## 
  ## # Return Value
  ## The amount of bytes occupied by the hook (aligned to the nearest instruction) in the remote process.
  ## 
  discard originalHookcodeex(process.addr, fromarg, to, trampout.addr)



proc originalUnhookcode(fromarg: uintptrt; trampoline: uintptrt; size: csize_t): boolt {. cdecl, importc: "LM_UnhookCode".}
proc Unhookcode*(fromarg: uintptrt; trampoline: uintptrt; size: csize_t): bool {.exportpy.}  = 
  # UnhookCode
  ## 
  ## ```c
  ##  bool_t 
  ## UnhookCode(address_t from,
  ## 	      address_t trampoline,
  ## 	      size_t    size);
  ## ```
  ## 
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
  ## 
  originalUnhookcode(fromarg, trampoline, size).bool



proc originalUnhookcodeex(process: ptr Processt; fromarg: uintptrt; trampoline: uintptrt; size: csize_t): boolt {.cdecl, importc: "LM_UnhookCodeEx".}
proc Unhookcodeex*(process: Processt; fromarg: uintptrt; trampoline: uintptrt; size: csize_t): bool {.exportpy.}  = 
  # UnhookCodeEx
  ## 
  ## ```c
  ##  bool_t 
  ## UnhookCodeEx(const process_t *process,
  ## 		address_t        from,
  ## 		address_t        trampoline,
  ## 		size_t           size);
  ## ```
  ## 
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
  ## 
  return  originalUnhookcodeex(process.addr, fromarg, trampoline, size).bool



#proc originalVmtnew(vtable: ptr uintptrt; vmtout: ptr Vmtt): boolt {.cdecl, importc: "LM_VmtNew".}
# Vmtnew*(vtable:  uintptrt; vmtout:  Vmtt): boolt {.exportpy.} = discard originalVmtnew(vtable.addr, vmtout.addr)

#proc originalVmthook(vmt: ptr Vmtt; fromfnindex: csize_t; to: uintptrt): boolt {.cdecl, importc: "LM_VmtHook".}
#proc Vmthook*(vmt: Vmtt; fromfnindex: csize_t; to: uintptrt): boolt {.exportpy.}  = 
  # VmtHook
  ## 
  ## ```c
  ##  bool_t 
  ## VmtHook(vmt_t    *vmt,
  ## 	   size_t    from_fn_index,
  ## 	   address_t to);
  ## ```
  ## 
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
  ## 
  #discard originalVmthook(vmt.addr, fromfnindex, to)



#proc originalVmtunhook(vmt: ptr Vmtt; fnindex: csize_t): void {.cdecl, importc: "LM_VmtUnhook".}
#proc Vmtunhook*(vmt:  Vmtt; fnindex: csize_t): void {.exportpy.}  = 
  # VmtUnhook
  ## 
  ## ```c
  ##  void_t 
  ## VmtUnhook(vmt_t *vmt,
  ## 	     size_t fn_index);
  ## ```
  ## 
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
  ## 
  #discard originalVmtunhook(vmt.addr, fnindex)


when defined(debugprint):
  var ownprocess: Processt = Getprocess()
  var ownprocessmodule: Modulet = Findmodule($charArrayToCstring(ownprocess.name))
  var externprocess: Processt = Findprocess("notepad.exe")
  var externprocessmodule: Modulet = Findmoduleex(externprocess, "notepad.exe")
  echo "Enumprocesses len: ", Enumprocesses().len
  echo "Enumthreads len: ", Enumthreads().len
  echo "Enumthreadsex len: ", Enumthreadsex(externprocess).len
  echo "Enummodules len: ", Enummodules().len
  echo "Enummodulesex len: ", Enummodulesex(externprocess).len
  echo "Enumsymbols len: ", Enumsymbols(ownprocessmodule).len
  echo "Enumsegments len: ", Enumsegments().len
  echo "Enumsegmentsex len: ", Enumsegmentsex(externprocess).len
  echo "Getprocess: ", Getprocess()
  echo "Getprocessex: ", Getprocessex(externprocess.pid)
  echo "Findprocess: ", Findprocess("notepad.exe")
  echo "Isprocessalive: ", Isprocessalive(ownprocess)
  echo "Getbits: ", Getbits()
  echo "Getsystembits: ", Getsystembits()
  echo "Getthread: ", Getthread()
  echo "Getthreadex: ", Getthreadex(externprocess)
  echo "Getthreadprocess: ", Getthreadprocess(Getthread())
  echo "Findmodule: ", Findmodule("ntdll.dll")
  echo "Findmoduleex: ", Findmoduleex(externprocess, "ntdll.dll")
  echo "Loadmodule: ", Loadmodule("HID.dll")
  echo "Loadmoduleex: ", Loadmoduleex(externprocess, "C:\\Windows\\System32\\HID.dll", externprocessmodule)
  echo "Unloadmodule: ", Unloadmodule(Findmodule("HID.dll"))
  echo "Unloadmoduleex: ", Unloadmoduleex(externprocess, externprocessmodule)
  echo "Findsymboladdress: ", Findsymboladdress(Findmodule("ntdll.dll"), "NtOpenFile").toHex
  echo "Findsegment: ", Findsegment(Findsymboladdress(Findmodule("ntdll.dll"), "NtOpenFile"))
  echo "Findsegmentex: ", Findsegmentex(externprocess, externprocessmodule.base)
  #cho "Readmemory: ", readmemory(ownprocessmodule.base, uint8).toHex
  #cho "Readmemoryex: ", readmemoryex(externprocess.addr, externprocessmodule.base, uint8).toHex
  #cho "Read_uint8: ", read_uint8(externprocess, externprocessmodule.base).toHex
  #cho "Read_uint16: ", read_uint16(externprocess, externprocessmodule.base).toHex
  #cho "Read_uint32: ", read_uint32(externprocess, externprocessmodule.base).toHex
  #cho "Read_uint64: ", read_uint64(externprocess, externprocessmodule.base).toHex
  #cho "Read_int8: ", read_int8(externprocess, externprocessmodule.base).toHex
  #cho "Read_int16: ", read_int16(externprocess, externprocessmodule.base).toHex
  #cho "Read_int32: ", read_int32(externprocess, externprocessmodule.base).toHex
  #cho "Read_int64: ", read_int64(externprocess, externprocessmodule.base).toHex
  #cho "Read_float: ", read_float(externprocess, externprocessmodule.base)
  #echo "Setmemory: ", Setmemory(Enummodules()[5].base, 0x90, 1)
  echo "Setmemoryex: ", Setmemoryex(externprocess, externprocessmodule.base, 0x90, 1)
  echo "Protmemory: ", Protmemory(ownprocessmodule.base, 1, Protxrw)
  echo "Protmemoryex: ", Protmemoryex(externprocess, externprocessmodule.base, 1, Protxrw)
  echo "Allocmemory: ", Allocmemory(1, Protxrw).toHex
  echo "Allocmemoryex: ", Allocmemoryex(externprocess, 1, Protxrw).toHex
  echo "Freememory: ", Freememory(Allocmemory(1, Protxrw), 1)
  echo "Freememoryex: ", Freememoryex(externprocess, Allocmemoryex(externprocess, 1, Protxrw), 1)
  echo "Deeppointer: ", Deeppointer(Findmodule("ntdll.dll").base, @[0x0.uintptrt, 0x0.uintptrt]).toHex
  echo "Deeppointerex: ", Deeppointerex(externprocess ,externprocessmodule.base + 0x000320D8, @[0x40.uintptrt, 0x38.uintptrt, 0x30.uintptrt, 0x50.uintptrt]).toHex
  echo "Datascan: ", Datascan(@[0x5A.byte, 0x90.byte], Findmodule("ntdll.dll").base).toHex
  #echo "Datascancheck: ", read_uint64(ownprocess, ownprocessmodule.base).toHex
  # let datapatttern: seq[byte] = @[0xE8, 0xFA, 0xCA, 0xFF, 0xFF , 0x85 , 0xFF , 0x74 , 0x38 , 0x48 , 0x8B , 0x0D , 0x8F , 0x26 , 0x02 , 0x00 , 0x8B , 0x1D , 0x21 , 0x29 , 0x02 , 0x00 , 0x8B]
  echo "Datascanex: ", Datascanex(externprocess, @[0x5A.byte, 0x90.byte, 0x90.byte], externprocessmodule.base).toHex
  #echo "Datascanexcheck: ", read_uint64(externprocess, externprocessmodule.base).toHex
  let  patternpattern = @[0x48.byte, 0xFF.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x0F.byte, 0x1F.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0xE9.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x33.byte, 0xC9]
  #echo "Patternscan: ", Patternscan(patternpattern, "xx?????xx???x????xx", Findmodule("ntdll.dll").base).toHex
  echo "Patternscanex: ", Patternscanex(externprocess, patternpattern, "xx?????xx???x????xx", externprocessmodule.base, externprocessmodule.size).toHex
  echo "Getarchitecture: ", Getarchitecture()
  echo "Assemble: ", Assemble("mov rax, 0x1234")
  var ins1 = Assemble("mov rax, 0x1234")
  #echo "Assembleex: ", Assembleex("mov rax, 0x1234", externprocessmodule.base)
  # var instruction: Instructiont
  echo "Disassemble: ", Disassemble(cast[uintptrt](ins1.bytes[0].addr))
  # var pl = Assembleex("mov rax, 0x1234", externprocessmodule.base)
  # var ins2: Instructiont
  #echo "Disassembleex: ", Disassembleex(Findsymboladdress(Findmodule("ntdll.dll"), "NtOpenFile"), Getarchitecture(), Getbits(), 1, 1, Findmodule("ntdll.dll").base)
  echo "Codelength: ", CodeLength(ownprocessmodule.base, 1)
  echo "Codelengthex: ", CodeLengthex(externprocess, externprocessmodule.base, 1)
  # var tramp: uintptrt
  #echo "Hookcode: ", Hookcode(ownprocessmodule.base + 0x000010.uintptrt, Allocmemory(32, Protxrw), tramp)
  #echo "tramp: ", tramp.toHex
  #echo "Hookcodeex: ", Hookcodeex(externprocess, externprocessmodule.base + 0x0000A70B.uintptrt, Allocmemoryex(externprocess, 32, Protxrw), tramp)
  #echo "tramp: ", tramp.toHex
  #echo "Unhookcode: ", Unhookcode(Findsymboladdress(Findmodule("ntdll.dll"), "NtOpenFile"), Findsymboladdress(Findmodule("ntdll.dll"), "NtClose"), 0)
  #echo "Unhookcodeex: ", Unhookcodeex(externprocess, Findsymboladdress(Findmodule("ntdll.dll"), "NtOpenFile"), Findsymboladdress(Findmodule("ntdll.dll"), "NtClose"), 0)
  echo Sigscanex(Findprocess("notepad.exe"), "E8 ? ? ? ? 85 FF 74 ? 48 8B", Findmoduleex(Findprocess("notepad.exe"), "notepad.exe").base, Findmoduleex(Findprocess("notepad.exe"), "notepad.exe").size).toHex

