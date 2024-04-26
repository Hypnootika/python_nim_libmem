when defined(windows):
  withDir(thisDir()):
    const p = thisDir() & r"\..\src\lib\libmem.lib"

    switch("cc", "vcc")
    switch("define", "debug")
    switch("threads", "off")
    switch("verbosity", "0")
    switch("passL", p&" ntdll.lib shell32.lib")
    switch("passC", "/MD")
