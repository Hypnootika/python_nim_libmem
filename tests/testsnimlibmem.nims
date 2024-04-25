const p = getCurrentDir() & "\\src\\lib\\libmem.lib"
echo(p)
switch("cc", "vcc")
switch("define", "debug")
switch("threads", "off")

switch("passL", p&" ntdll.lib shell32.lib")
switch("passC", "/MD")