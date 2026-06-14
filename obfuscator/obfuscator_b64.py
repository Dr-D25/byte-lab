# Скрипт выполняет простую обфускацию Python-кода, кодируя содержимое исходного файла в формат Base64 и создавая новый файл-обёртку для его последующего выполнения. В сгенерированном файле исходный код восстанавливается во время запуска и передаётся интерпретатору через функции `compile()` и `exec()`. Такой подход позволяет скрыть исходный текст программы от поверхностного просмотра, сохраняя её функциональность. Код предназначен для изучения базовых методов обфускации и механизмов динамического выполнения кода в Python.


import base64
import sys

def obfuscate(input_file, output_file):
    with open(input_file, "r", encoding="utf-8") as f:
        code = f.read()

    
    b64_code = base64.b64encode(code.encode()).decode()

    
    stub = f'''
import base64
exec(compile(base64.b64decode("{b64_code}").decode(), "<string>", "exec"))
'''

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(stub)

    print(f"Обфускация завершена: {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Использование: python obfuscator.py <входной_файл.py> <выходной_файл.py>")
    else:
        obfuscate(sys.argv[1], sys.argv[2])
