import re
import os

# Pfad zur Nim-Datei und zum Dokumentationsordner
nim_file_path = r"D:\Nim_Libmem\futharktests\src\nimlibmem.nim"
doc_folder_path = r"D:\Nim_Libmem\futharktests\src\docs"


def extract_proc_names(nim_path):
    proc_pattern = re.compile(r"proc (?P<name>\w+?)\*.*? =")
    with open(nim_path, 'r', encoding='utf-8') as file:
        content = file.read()
    return proc_pattern.findall(content)


def insert_documentation(nim_path, doc_path, proc_name):
    # Dokumentationsdatei lesen
    with open(os.path.join(doc_path, f"LM_{proc_name}.md"), 'r', encoding='utf-8') as file:
        doc_content = file.read()

    # Nim-Datei modifizieren
    with open(nim_path, 'r+', encoding='utf-8') as file:
        content = file.readlines()
        for i, line in enumerate(content):
            if f"proc {proc_name}*" in line and " = " in line:
                insertationpoint = line.split(" = ")[1]
                doc_content = doc_content.replace("\n", "\n  ## ").replace("LM_API", "").replace("LM_CALL", "").replace("LM_", "").replace("lm_", "")
                content.insert(i + 1, line.split(" = ")[
                    0] + "  = " + "\n" + "  " + doc_content + '\n' + "  " + insertationpoint + '\n' + '\n')
                print(content[i - 1])
                break
        file.seek(0)
        content.remove(content[i])
        file.writelines(content)


for proc_name in extract_proc_names(nim_file_path):
    insert_documentation(nim_file_path, doc_folder_path, proc_name)


# Hauptfunktion
def main():
    proc_names = extract_proc_names(nim_file_path)
    for proc_name in proc_names:
        if os.path.exists(os.path.join(doc_folder_path, f"{proc_name}.txt")):
            insert_documentation(nim_file_path, doc_folder_path, proc_name)

# Skript ausführen
