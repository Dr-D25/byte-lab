# Скрипт реализует простой пользовательский формат архива с собственной сигнатурой и поддержкой упаковки и распаковки нескольких файлов. В процессе создания архива сохраняются имена файлов и их содержимое, что позволяет впоследствии восстановить исходную структуру данных. Программа выполняет проверку сигнатуры архива и извлекает все содержащиеся в нём файлы в указанную директорию. Код может использоваться в образовательных целях для изучения принципов построения бинарных форматов и механизмов сериализации данных.


import struct
import os

ARCHIVE_SIGNATURE = b'Dr-D25'

def pack(files, archive_name):
    with open(archive_name, 'wb') as archive:
        archive.write(ARCHIVE_SIGNATURE)
        archive.write(struct.pack('<I', len(files)))

        for filepath in files:
            filename = os.path.basename(filepath)
            with open(filepath, 'rb') as f:
                data = f.read()

            filename_bytes = filename.encode('utf-8')
            archive.write(struct.pack('B', len(filename_bytes)))
            archive.write(filename_bytes)
            archive.write(struct.pack('<I', len(data)))
            archive.write(data)

    print(f'✅ Упаковано {len(files)} файлов в {archive_name}')


def unpack(archive_name, output_folder):
    with open(archive_name, 'rb') as archive:
        if archive.read(6) != ARCHIVE_SIGNATURE:
            raise ValueError('❌ Неверный формат архива')

        file_count = struct.unpack('<I', archive.read(4))[0]

        for _ in range(file_count):
            name_len = struct.unpack('B', archive.read(1))[0]
            name = archive.read(name_len).decode('utf-8')
            size = struct.unpack('<I', archive.read(4))[0]
            data = archive.read(size)

            output_path = os.path.join(output_folder, name)
            with open(output_path, 'wb') as f:
                f.write(data)
            print(f'📄 Распакован файл: {output_path}')



if __name__ == '__main__':
    import sys
    import os

    mode = input("Режим (pack/unpack): ").strip()

    if mode == 'pack':
        files = input("Введите пути к файлам через пробел: ").strip().split()
        pack(files, 'archive.myarch')
    elif mode == 'unpack':
        folder = 'unpacked'
        os.makedirs(folder, exist_ok=True)
        unpack('archive.Dr-D25', folder)
    else:
        print("❗ Неверный режим")
