; Сборка на NASM представляет собой позиционно-независимый 32-битный shellcode, выполняющий динамическое разрешение адресов API-функций без использования таблицы импорта. Код получает доступ к структурам PEB и экспортной таблице `kernel32.dll`, находит `GetProcAddress`, а затем использует его для получения адресов необходимых функций и вызова `MessageBoxA`. Такой подход позволяет выполнять код независимо от загрузчика PE и делает его пригодным для исследований в области низкоуровневого программирования и механизмов разрешения API во время выполнения. Пример демонстрирует принципы построения автономного shellcode и взаимодействия с системными библиотеками Windows.
;

;nasm -f bin messagebox_shellcode.asm -o shellcode.bin

BITS 32
GLOBAL _start

SECTION .text
_start:
    xor     eax, eax
    mov     eax, [fs:eax+0x30]         ; PEB
    mov     eax, [eax+0x0C]            ; PEB->Ldr
    mov     esi, [eax+0x1C]            ; InInitializationOrderModuleList
    lodsd
    mov     ebx, [eax+0x08]            ; base address of kernel32.dll

    ; Find GetProcAddress
    mov     edx, [ebx+0x3C]            ; PE header
    add     edx, ebx
    mov     edx, [edx+0x78]            ; export table RVA
    add     edx, ebx
    mov     ecx, [edx+0x20]            ; name ptrs
    add     ecx, ebx

find_getproc:
    inc     edi
    mov     esi, [ecx+edi*4]
    add     esi, ebx
    cmp     dword [esi], 0x50746547    ; 'GetP'
    jne     find_getproc
    cmp     dword [esi+4], 0x41636F72  ; 'rocA'
    jne     find_getproc

    ; found: edi = index
    mov     ecx, [edx+0x24]            ; ordinals
    add     ecx, ebx
    movzx   eax, word [ecx+edi*2]

    mov     ecx, [edx+0x1C]            ; function RVA table
    add     ecx, ebx
    mov     eax, [ecx+eax*4]
    add     eax, ebx                   ; eax = GetProcAddress

    push    ebx                        ; hModule = kernel32
    push    0x41617242                 ; "raBA"
    push    0x79726C69                 ; "ilry"
    mov     esi, esp
    push    esi                        ; "LibraryA"
    push    eax                        ; GetProcAddress
    call    eax                        ; eax = LoadLibraryA

    push    0x216F6C6C                 ; "llo!"
    push    0x6548206D                 ; "m He"
    push    0x6F6C6C65                 ; "ello"
    mov     esi, esp

    push    0x21692048                 ; "Hi! "
    mov     edi, esp

    push    0x0                        ; MB_OK
    push    esi                        ; lpText
    push    edi                        ; lpCaption
    push    0x0                        ; hWnd

    ; Get MessageBoxA
    push    eax                        ; hModule = user32
    push    0x41786F62                 ; "boxA"
    push    0x65676173                 ; "sage"
    push    0x4D                     ; "M"
    mov     esi, esp
    push    esi
    call    eax                        ; call GetProcAddress

    call    eax                        ; MessageBoxA
    ret
