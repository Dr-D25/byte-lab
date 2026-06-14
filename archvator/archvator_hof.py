# Скрипт реализует собственный архивный формат с использованием алгоритма сжатия Хаффмана для эффективного уменьшения размера данных. При создании архива для каждого файла строится индивидуальное дерево кодирования, а в архив сохраняются таблицы кодов, метаданные и сжатое содержимое. Программа поддерживает упаковку и последующее восстановление нескольких файлов с проверкой сигнатуры пользовательского формата. Код предназначен для изучения принципов построения архиваторов, алгоритмов префиксного кодирования и особенностей работы с бинарными данными.


import struct
import heapq
import os
from collections import Counter, namedtuple

ARCHIVE_SIGNATURE = b'Dr-D25Hof'

class Node(namedtuple("Node", "freq symbol left right")):
    def __lt__(self, other):
        return self.freq < other.freq

def build_tree(data: bytes):
    freq = Counter(data)
    heap = [Node(f, bytes([s]), None, None) for s, f in freq.items()]
    heapq.heapify(heap)

    while len(heap) > 1:
        left = heapq.heappop(heap)
        right = heapq.heappop(heap)
        heapq.heappush(heap, Node(left.freq + right.freq, None, left, right))

    return heap[0] if heap else None

def build_codes(node, prefix=b"", code_map=None):
    if code_map is None:
        code_map = {}
    if node.symbol is not None:
        code_map[node.symbol] = prefix
    else:
        build_codes(node.left, prefix + b"0", code_map)
        build_codes(node.right, prefix + b"1", code_map)
    return code_map

def huffman_compress(data: bytes):
    tree = build_tree(data)
    code_map = build_codes(tree)
    encoded_bits = b''.join(code_map[bytes([b])] for b in data)


    padding = (8 - len(encoded_bits) % 8) % 8
    encoded_bits += b"0" * padding
    byte_data = int(encoded_bits, 2).to_bytes(len(encoded_bits) // 8, 'big')

    return byte_data, code_map, padding

def huffman_decompress(data: bytes, code_map: dict, original_size: int, padding: int):

    rev_map = {v: k for k, v in code_map.items()}

    bit_string = bin(int.from_bytes(data, 'big'))[2:]
    bit_string = bit_string.zfill(len(data) * 8)
    bit_string = bit_string[:len(bit_string) - padding]

    out = bytearray()
    current = b""
    for bit in bit_string.encode():
        current += bytes([bit])
        if current in rev_map:
            out += rev_map[current]
            current = b""
    return bytes(out)

def serialize_code_map(code_map: dict) -> bytes:
    result = struct.pack('<I', len(code_map))
    for symbol, code in code_map.items():
        result += struct.pack('B', symbol[0])
        result += struct.pack('B', len(code))
        result += code
    return result

def deserialize_code_map(data: bytes):
    code_map = {}
    pos = 0
    count = struct.unpack('<I', data[:4])[0]
    pos += 4
    for _ in range(count):
        symbol = bytes([data[pos]])
        code_len = data[pos + 1]
        code = data[pos + 2:pos + 2 + code_len]
        code_map[symbol] = code
        pos += 2 + code_len
    return code_map


def pack(files, archive_name):
    with open(archive_name, 'wb') as archive:
        archive.write(ARCHIVE_SIGNATURE)
        archive.write(struct.pack('<I', len(files)))

        for filepath in files:
            filename = os.path.basename(filepath)
            with open(filepath, 'rb') as f:
                raw_data = f.read()

            compressed_data, code_map, padding = huffman_compress(raw_data)
            code_map_data = serialize_code_map(code_map)

            filename_bytes = filename.encode('utf-8')
            archive.write(struct.pack('B', len(filename_bytes)))
            archive.write(filename_bytes)
            archive.write(struct.pack('<I', len(raw_data)))
            archive.write(struct.pack('<I', len(compressed_data)))
            archive.write(struct.pack('<I', len(code_map_data)))
            archive.write(struct.pack('B', padding))
            archive.write(code_map_data)
            archive.write(compressed_data)

    print(f'✅ Архив создан: {archive_name}')


def unpack(archive_name, output_folder):
    with open(archive_name, 'rb') as archive:
        if archive.read(9) != ARCHIVE_SIGNATURE:
            raise ValueError("❌ Неверный формат архива")

        file_count = struct.unpack('<I', archive.read(4))[0]

        for _ in range(file_count):
            name_len = struct.unpack('B', archive.read(1))[0]
            name = archive.read(name_len).decode('utf-8')
            original_size = struct.unpack('<I', archive.read(4))[0]
            compressed_size = struct.unpack('<I', archive.read(4))[0]
            code_map_size = struct.unpack('<I', archive.read(4))[0]
            padding = struct.unpack('B', archive.read(1))[0]

            code_map_data = archive.read(code_map_size)
            compressed_data = archive.read(compressed_size)

            code_map = deserialize_code_map(code_map_data)
            raw_data = huffman_decompress(compressed_data, code_map, original_size, padding)

            path = os.path.join(output_folder, name)
            with open(path, 'wb') as f:
                f.write(raw_data)
            print(f'📄 Распакован файл: {path}')



if __name__ == '__main__':
    mode = input("Режим (pack/unpack): ").strip()

    if mode == 'pack':
        files = input("Введите пути к файлам через пробел: ").strip().split()
        pack(files, 'archive.Dr-D25')
    elif mode == 'unpack':
        folder = 'archvator'
        os.makedirs(folder, exist_ok=True)
        unpack('archive.Dr-D25', folder)
    else:
        print("❗ Неверный режим")
