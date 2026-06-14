# Скрипт формирует 512-байтный бинарный файл sector.bin, содержащий набор заранее определённых машинных последовательностей (gadgets), завершающихся инструкцией ret. После объединения всех последовательностей данные дополняются нулевыми байтами до размера загрузочного сектора и завершаются сигнатурой 0x55AA. Полученный файл может использоваться в экспериментальных целях для исследования структуры загрузочных секторов и анализа коротких инструкционных последовательностей. По завершении работы программа сохраняет результат в файл и выводит сообщение об успешном создании сектора.

gadgets = [
    bytes([0x58, 0xC3]),             # pop ax; ret
    bytes([0x31, 0xDB, 0xC3]),       # xor bx, bx; ret
    bytes([0x8B, 0xCA, 0xC3]),       # mov cx, dx; ret
    bytes([0x01, 0xD8, 0xC3]),       # add ax, bx; ret
    bytes([0x29, 0xCA, 0xC3]),       # sub dx, cx; ret
    bytes([0x40, 0xC3]),             # inc ax; ret
    bytes([0x4B, 0xC3]),             # dec bx; ret
    bytes([0x51, 0x5A, 0xC3]),       # push cx; pop dx; ret
    bytes([0x90, 0x90, 0xC3]),       # nop; nop; ret
]

data = b''.join(gadgets)

if len(data) < 510:
    data += bytes(510 - len(data))
else:
    data = data[:510]

data += bytes([0x55, 0xAA])

with open("sector.bin", "wb") as f:
    f.write(data)

print("[+] sector.bin успешно создан (512 байт)")
