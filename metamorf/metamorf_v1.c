// Программа демонстрирует технику динамического шифрования и последующего выполнения машинного кода в памяти с использованием простого XOR-преобразования. Перед запуском полезная нагрузка шифруется случайным ключом, а затем восстанавливается специальным декодирующим фрагментом кода, сгенерированным во время выполнения. Для размещения и исполнения кода используется выделяемая область памяти с разрешением на выполнение. Код предназначен для изучения принципов работы саморасшифровывающихся фрагментов, динамической генерации кода и особенностей выполнения машинных инструкций в среде Windows.


#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

unsigned char payload[] = {
    0x6A, 0x00,                               // push 0
    0x68, 0x6C, 0x6C, 0x6F, 0x00,             // push "llo\0"
    0x68, 0x6F, 0x20, 0x66, 0x72,             // push "o fr"
    0x68, 0x48, 0x65, 0x6C, 0x6C,             // push "Hell"
    0x8D, 0x4C, 0x24, 0x04,                   // lea ecx, [esp+4]
    0x6A, 0x00,                               // push 0
    0x51,                                     // push ecx (message)
    0x68, 0x48, 0x69, 0x21, 0x00,             // push "Hi!"
    0x6A, 0x00,                               // push 0
    0xB8, 0, 0, 0, 0,                         // mov eax, MessageBoxA
    0xFF, 0xD0,                               // call eax
    0xC3                                      // ret
};
size_t payload_size = sizeof(payload);

int generate_decryptor(unsigned char *buf, unsigned char key, void *shellcode_addr, size_t len) {
    int i = 0;

    // mov ecx, len
    buf[i++] = 0xB9;
    memcpy(&buf[i], &len, sizeof(DWORD)); i += 4;

    // mov esi, shellcode_addr
    buf[i++] = 0xBE;
    memcpy(&buf[i], &shellcode_addr, sizeof(void*)); i += sizeof(void*);

    // mov al, key
    buf[i++] = 0xB0;
    buf[i++] = key;

    // loop:
    buf[i++] = 0x30; buf[i++] = 0x06;       // xor [esi], al
    buf[i++] = 0x46;                        // inc esi
    buf[i++] = 0x49;                        // dec ecx
    buf[i++] = 0x75; buf[i++] = 0xFA;       // jne -6
    buf[i++] = 0xFF; buf[i++] = 0xE6;       // jmp esi (исполнить расшифрованный код)

    return i;
}

int main() {
    srand((unsigned)time(NULL));

    FARPROC msgbox_addr = GetProcAddress(LoadLibraryA("user32.dll"), "MessageBoxA");
    if (!msgbox_addr) {
        printf("Failed to get MessageBoxA\n");
        return 1;
    }

    memcpy(payload + 29, &msgbox_addr, sizeof(void*));

    unsigned char key = (rand() % 254) + 1;

    unsigned char encrypted[payload_size];
    for (size_t i = 0; i < payload_size; i++)
        encrypted[i] = payload[i] ^ key;

    size_t total_size = 64 + payload_size;
    unsigned char *mem = VirtualAlloc(NULL, total_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) {
        printf("VirtualAlloc failed\n");
        return 1;
    }

    unsigned char *code_loc = mem + 64;

    memcpy(code_loc, encrypted, payload_size);

    int decryptor_len = generate_decryptor(mem, key, code_loc, payload_size);

    printf("[+] Shellcode ready (XOR key = 0x%02X)\n", key);
    printf("[+] Total size: %d bytes\n", decryptor_len + (int)payload_size);

    ((void(*)())mem)();

    VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}
