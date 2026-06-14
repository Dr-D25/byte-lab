# Скрипт реализует многоступенчатую обфускацию Python-кода, используя компиляцию в байткод, сериализацию через `marshal`, XOR-преобразование и последующее кодирование в Base64. Для затруднения анализа автоматически генерируются случайные имена переменных, а полезная нагрузка разбивается на несколько строк и восстанавливается во время выполнения. Восстановление кода и импорт необходимых модулей осуществляются динамически, что позволяет скрыть внутреннюю структуру программы от поверхностного анализа. Проект предназначен для изучения методов защиты исходного кода, механизмов сериализации байткода и особенностей динамического выполнения программ на Python.


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
    payload_joined = " +\n    ".join([f'"{chunk}"' for chunk in chunks])

    n_payload = random_name()
    n_key = random_name()
    n_code = random_name()
    n_exec = random_name()

    decryption_stub = f"""
{n_payload} = (
    {payload_joined}
)
{n_key} = {xor_key}
{n_code} = __import__('marshal').loads(
    bytes([b ^ {n_key} for b in __import__('base64').b64decode({n_payload})])
)
exec({n_code})
"""

    encoded_stub = repr(decryption_stub)

    final_stub = f"""
try:
    import sys
    sys.setrecursionlimit(0)
    del __name__
except:
    pass

exec({encoded_stub})
"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(final_stub.strip())

    print(f"Oбфускация завершена: {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Использование: python obfuscator_hide_Import.py <input.py> <output.py>")
    else:
        obfuscate(sys.argv[1], sys.argv[2])
