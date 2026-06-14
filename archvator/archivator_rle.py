# Скрипт реализует собственный формат архива с использованием алгоритма сжатия RLE (Run-Length Encoding) для уменьшения размера повторяющихся последовательностей байтов. При упаковке в архив сохраняются имена файлов, размеры исходных данных и их сжатое представление, а при распаковке выполняется восстановление исходного содержимого с проверкой целостности. Программа поддерживает работу с несколькими файлами и использует уникальную сигнатуру для идентификации формата архива. Код предназначен для изучения принципов построения пользовательских архивных форматов и базовых алгоритмов сжатия данных.


import struct
import os

ARCHIVE_SIGNATURE = b'Dr-D25-RLE'


def rle_compress(data: bytes) -> bytes:
    result = bytearray()
    i = 0
    while i < len(data):
        count = 1
        while i + count < len(data) and data[i] == data[i + count] and count < 255:
            count += 1
        result.extend([count, data[i]])
        i += count
    return bytes(result)


def rle_decompress(data: bytes) -> bytes:
    result = bytearray()
    i = 0
    while i < len(data):
        count = data[i]
        byte = data[i + 1]
        result.extend([byte] * count)
        i += 2
    return bytes(result)


def pack(files, archive_name):
    with open(archive_name, 'wb') as archive:
        archive.write(ARCHIVE_SIGNATURE)
        archive.write(struct.pack('<I', len(files)))

        for filepath in files:
            filename = os.path.basename(filepath)
            with open(filepath, 'rb') as f:
                raw_data = f.read()
                data = rle_compress(raw_data)

            filename_bytes = filename.encode('utf-8')
            archive.write(struct.pack('B', len(filename_bytes)))
            archive.write(filename_bytes)
            archive.write(struct.pack('<I', len(data)))
            archive.write(struct.pack('<I', len(raw_data)))
            archive.write(data)

    print(f'✅ Упаковано {len(files)} файлов в {archive_name} с RLE-сжатием')


def unpack(archive_name, output_folder):
    with open(archive_name, 'rb') as archive:
        if archive.read(6) != ARCHIVE_SIGNATURE:
            raise ValueError('❌ Неверный формат архива (ожидалась сигнатура MYRLE1)')

        file_count = struct.unpack('<I', archive.read(4))[0]

        for _ in range(file_count):
            name_len = struct.unpack('B', archive.read(1))[0]
            name = archive.read(name_len).decode('utf-8')
            comp_size = struct.unpack('<I', archive.read(4))[0]
            orig_size = struct.unpack('<I', archive.read(4))[0]
            data = archive.read(comp_size)

            raw_data = rle_decompress(data)
            assert len(raw_data) == orig_size, "❌ Ошибка при распаковке: несоответствие размера"

            output_path = os.path.join(output_folder, name)
            with open(output_path, 'wb') as f:
                f.write(raw_data)
            print(f'📄 Распакован файл: {output_path}')



if __name__ == '__main__':
    import sys

    mode = input("Режим (pack/unpack): ").strip()

    if mode == 'pack':
        files = input("Введите пути к файлам через пробел: ").strip().split()
        pack(files, 'archive_rle.Dr-D25')
    elif mode == 'unpack':
        folder = 'unpacked_rle'
        os.makedirs(folder, exist_ok=True)
        unpack('archive_rle.Dr-D25', folder)
    else:
        print("❗ Неверный режим")
