# Скрипт выполняет обфускацию Python-программ путём компиляции исходного кода в байткод, его сериализации с помощью модуля `marshal`, последующего XOR-преобразования и кодирования в Base64. Полученная полезная нагрузка разбивается на несколько фрагментов и встраивается в автоматически создаваемый загрузочный модуль, который восстанавливает и выполняет исходный код во время запуска. Такой подход позволяет скрыть текст программы и затруднить её поверхностный анализ. Проект предназначен для изучения механизмов сериализации байткода, методов обфускации и особенностей динамического выполнения кода в Python.


import base64
import marshal
import random
import sys

def xor_encrypt(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)

def split_string(s: str, chunk_size: int = 50):
    return [s[i:i+chunk_size] for i in range(0, len(s), chunk_size)]

def obfuscate(input_file, output_file, xor_key=123):
    with open(input_file, "r", encoding="utf-8") as f:
        code = f.read()

    compiled = compile(code, "<string>", "exec")
    marshalled = marshal.dumps(compiled)

    encrypted = xor_encrypt(marshalled, xor_key)

    b64_encoded = base64.b64encode(encrypted).decode()

    chunks = split_string(b64_encoded, 60)
    joined_chunks = " +\n    ".join([f'"{chunk}"' for chunk in chunks])

    stub = f'''
import base64
import marshal

def __decrypt_xor(data, key):
    return bytes(b ^ key for b in data)

payload = (
    {joined_chunks}
)

exec(marshal.loads(__decrypt_xor(base64.b64decode(payload), {xor_key})))
'''

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(stub.strip())

    print(f"Обфускация завершена: {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Использование: python obfuscator_marshal.py <входной_файл.py> <выходной_файл.py>")
    else:
        obfuscate(sys.argv[1], sys.argv[2])
