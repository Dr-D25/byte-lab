# Скрипт реализует многоуровневую обфускацию Python-кода, сочетая компиляцию в байткод, сериализацию через `marshal`, XOR-шифрование и кодирование в Base64. Для усложнения анализа автоматически генерируются случайные имена переменных и функций, а закодированная полезная нагрузка разбивается на несколько строковых фрагментов. Во время выполнения загрузочный модуль восстанавливает исходный байткод и передаёт его интерпретатору через механизм динамического исполнения. Проект предназначен для изучения методов сокрытия структуры программ, сериализации байткода и различных техник обфускации кода на Python.


import base64
import marshal
import random
import string
import sys

def random_name(length=8):
    return ''.join(random.choices(string.ascii_letters, k=length))

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

    var_payload = random_name()
    var_key = random_name()
    var_decode = random_name()
    var_lambda = random_name()
    var_exec = random_name()

    joined_chunks = " +\n    ".join([f'"{chunk}"' for chunk in chunks])

    stub = f'''
import base64 as b64
import marshal as m

{var_payload} = (
    {joined_chunks}
)

{var_key} = {xor_key}
{var_lambda} = lambda d, k: bytes([x ^ k for x in d])

{var_exec} = m.loads({var_lambda}(b64.b64decode({var_payload}), {var_key}))
exec({var_exec})
'''

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(stub.strip())

    print(f"Полная обфускация с рандомными именами завершена: {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Использование: python obfuscator_randname.py <входной_файл.py> <выходной_файл.py>")
    else:
        obfuscate(sys.argv[1], sys.argv[2])
