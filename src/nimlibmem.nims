when defined(windows):
  withDir(thisDir()):
    const p = thisDir() & "/lib/libmem.lib"
    switch("cc", "vcc")
    switch("passL", p&" ntdll.lib shell32.lib")
    switch("passC", "/MD")
    switch("app", "lib")
    switch("out", "libmem.pyd")
    switch("tlsemulation", "off")
    switch("define", "release")
    switch("opt", "speed")
    switch("gc", "refc")
    switch("threads", "on")
    switch("define", "useMalloc")
