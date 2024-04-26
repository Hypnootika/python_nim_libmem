withDir(thisDir()):
  const p = thisDir() & "/lib/libmem.lib"
  switch("app", "lib")
  switch("out", "pynimlibmem/pynimlibmem.pyd")
  switch("cc", "vcc")
  switch("passL", p&" ntdll.lib shell32.lib")
  switch("passC", "/MD")
  switch("tlsemulation", "off")
  switch("threads", "on")
  switch("define", "useMalloc")
  switch("define", "release")
  switch("opt", "speed")

