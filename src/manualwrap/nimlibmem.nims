when defined(windows):
  withDir(thisDir()):
    const p = thisDir() & "/lib/libmem.lib"
    switch("cc", "vcc")
    switch("passL", p&" ntdll.lib shell32.lib")
    switch("passC", "/MD")
    # Define this to be able to actually debug the Code in the main file.
    when not defined(debugprint):
      switch("tlsemulation", "off")
      switch("gc", "refc")
      switch("threads", "on")
      switch("define", "useMalloc")
      switch("define", "debug")
      switch("opt", "speed")
      switch("app", "lib")
      switch("out", "libmem.pyd")
