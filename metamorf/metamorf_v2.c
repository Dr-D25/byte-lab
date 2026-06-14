// Программа загружает последовательность байтов из внешнего файла и размещает её в выделенной области памяти с разрешением на выполнение. После чтения содержимого файла управление передаётся загруженному коду посредством приведения адреса памяти к указателю на функцию. По завершении выполнения выделенные ресурсы освобождаются. Код предназначен для демонстрации механизмов динамической загрузки и исполнения машинного кода в памяти, а также для изучения особенностей работы с исполняемыми областями памяти в Windows.


#include <windows.h>
#include <stdio.h>

int main() {
    FILE *f = fopen("shellcode.bin", "rb");
    if (!f) {
        printf("Cannot open shellcode.bin\n");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    rewind(f);

    unsigned char *shellcode = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    fread(shellcode, 1, size, f);
    fclose(f);

    printf("[+] Shellcode loaded (%zu bytes), executing...\n", size);
    ((void(*)())shellcode)();

    VirtualFree(shellcode, 0, MEM_RELEASE);
    return 0;
}
