import re
import os
from pathlib import Path
nim_file_path = Path(__file__).resolve().parent.parent.joinpath("libmem.nim")
doc_folder_path = Path(__file__).resolve().parent.parent.joinpath("docs")


def extract_proc_names(nim_path):
    proc_pattern = re.compile(r"proc (?P<name>\w+?)\*.*? =")
    with open(nim_path, 'r', encoding='utf-8') as file:
        content = file.read()
    return proc_pattern.findall(content)


def insert_documentation(nim_path, doc_path, _proc_name):
    with open(os.path.join(doc_path, f"LM_{_proc_name}.md"), 'r', encoding='utf-8') as file:
        doc_content = file.read()

    # Nim-Datei modifizieren
    with open(nim_path, 'r+', encoding='utf-8') as file:
        content = file.readlines()
        for i, line in enumerate(content):
            if f"proc {_proc_name}*" in line and " = " in line:
                insertationpoint = line.split(" = ")[1]
                doc_content = doc_content.replace("\n", "\n  ## ").replace("LM_API", "").replace("LM_CALL", "").replace(
                    "LM_", "").replace("lm_", "")
                content.insert(i + 1, line.split(" = ")[
                    0] + "  = " + "\n" + "  " + doc_content + '\n' + "  " + insertationpoint + '\n' + '\n')
                print(content[i - 1])
                break
        file.seek(0)
        content.remove(content[i])
        file.writelines(content)


def main():
    for proc_name in extract_proc_names(nim_file_path):
        insert_documentation(nim_file_path, doc_folder_path, proc_name)
