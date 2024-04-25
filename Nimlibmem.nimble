# Package

version       = "0.1.0"
author        = "Hypnootika"
description   = "Nim bindings for Libmem"
license       = "MIT"
srcDir        = "src"
skipDirs      = @["tests"]
# Dependencies

requires "nim >= 2.0.0, winim, nimpy"



task(buildall, "Downloads libmem source code and generates Nim bindings"):
  exec "nim c -r src/githandler/libmemgithandler.nim"
  exec "nim c -r src/futhark/futharknimlibmem.nim"
