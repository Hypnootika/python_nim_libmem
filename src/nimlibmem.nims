when defined(windows):
  withDir(thisDir()):
    const p = thisDir() & "/lib/libmem.lib"
    switch("cc", "vcc")
    switch("passL", p&" ntdll.lib shell32.lib")
    switch("passC", "/MD")

    when not defined(debugprint):
      switch("tlsemulation", "off")
      switch("gc", "refc")
      switch("threads", "on")
      switch("define", "useMalloc")
      switch("define", "release")
      switch("opt", "speed")
      switch("app", "lib")
      switch("out", "libmem.pyd")
