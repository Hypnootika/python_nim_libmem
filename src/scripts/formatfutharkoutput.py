import os
import re
from pathlib import Path

dataset = """import typetraits, strutils, os, sequtils, nimpy
type
  cstr = distinct array[4096, char]
  
pyExportModule("libmem")

converter stringtToCstring(x: cstr): cstring = cast[cstring]((distinctBase(cstr)x)[0].addr)

proc cb[T](c: ptr T; arg: pointer): bool {.cdecl.} =
  cast[ptr seq[T]](arg)[].add(c[])
  result = true
  
  
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
"""


def resup(inputfile, outputfile):
    with open(inputfile, "r") as f:
        data = f.read()
        data = re.sub(r"(,|;|{.)\s\s+", "\\g<1> ", data)
        data = re.sub(r"##.*", "", data)
        data = re.sub(r"proc (\w+)\*", "proc original\\g<1>", data)
    with open(outputfile, "w") as f:
        f.write(dataset + "\n" + data + "\n")


def preparewrappers(file):
    regex = re.compile(r"(proc .*?)\{", re.MULTILINE)
    enumprocs = []
    with open(file, "r+") as f:
        data = f.read()
        matches = regex.finditer(data)

        for matchNum, match in enumerate(matches, start=1):
            proc = match.group(1).replace("original", "")
            procnamepart, rest = proc.split("(")[0], proc.split("(")[1]
            procnamepart += "*"
            justname = procnamepart.split(" ")[1].replace("*", "")
            sig = "original" + justname
            retprep = rest.split("(")[0]
            retprep = re.sub(r"(: .*?);|(: .*?)\)", "", retprep)
            retprep = retprep.replace(" ", ", ")
            retprep = retprep.split(":")[0]
            proc = procnamepart + "(" + rest + "{.exportpy.}" + " = discard " + sig + "(" + retprep + ")"

            if "Enum" in proc:
                enumprocs.append("#" + proc)
                continue
            data += "\n" + "#" + proc + "\n"

        data = data + "\n\n"
        f.seek(0)
        f.write(data)
        origpart, newpart = data.split("#proc cb[T]*(c: ptr T; arg: pointer): bool {.exportpy.} = discard originalcb["
                                       "T](c, arg)")[0], data.split("#proc cb[T]*(c: ptr T; arg: pointer): bool {"
                                                                    ".exportpy.} = discard originalcb[T](c, arg)")[1]
        f.seek(0)
        f.write(origpart)

        for proc in enumprocs:
            f.write(proc + "\n")

        f.write(newpart)


def main():
    current_dir = Path(__file__).resolve().parent
    gen_file = current_dir.parent.joinpath("nimlibmemunformatted.nim")
    output_file = current_dir.parent.joinpath("pynimlibmem.nim")
    resup(gen_file, output_file)
    preparewrappers(output_file)


if __name__ == "__main__":
    main()
