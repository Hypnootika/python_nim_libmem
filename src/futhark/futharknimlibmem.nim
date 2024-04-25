import futhark, os, typetraits, strutils, osproc

const lmem = staticExec("python " & currentSourcePath.parentDir / "../scripts/cleanlibmem.py")
when lmem != "":
  echo lmem
  quit(1)
sleep(1000)

proc renameCb(n, k: string, p = ""): string =
  n.replace("LM_", "").replace("lm_", "")

proc cleanupgeneratedfile() =
  if fileExists(currentSourcePath.parentDir.parentDir / "nimlibmemunformatted.nim"):
    removeFile(currentSourcePath.parentDir.parentDir / "nimlibmemunformatted.nim")
  if fileExists(currentSourcePath.parentDir.parentDir / "libmem_cleaned.h"):
    removeFile(currentSourcePath.parentDir.parentDir / "libmem_cleaned.h")

proc runPythonScript(script: string): string =
  result = execProcess("python " & script)

type
  cstr = distinct array[4096, char]

importc:
  outputPath currentSourcePath.parentDir.parentDir / "nimlibmemunformatted.nim"
  path "../."
  renameCallback renameCb
  "libmem_cleaned.h"

echo runPythonScript(currentSourcePath.parentDir.parentDir / "scripts/formatfutharkoutput.py")
if not fileExists(currentSourcePath.parentDir.parentDir / "nimlibmemunformatted.nim"):
  echo "Failed to generate nimlibmemunformatted.nim, retrying..."
  sleep(1000)
  echo runPythonScript(currentSourcePath.parentDir.parentDir / "scripts/formatfutharkoutput.py")
  if not fileExists(currentSourcePath.parentDir.parentDir / "nimlibmemunformatted.nim"):
    echo "Failed to generate nimlibmemunformatted.nim, aborting..."
    quit(1)


cleanupgeneratedfile()

when defined(GETDOCS):
  echo "Inserting documentation..."
  echo runPythonScript(currentSourcePath.parentDir.parentDir / "scripts/doc.py")


