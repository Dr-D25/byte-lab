# Скрипт предназначен для статического анализа загрузочных секторов (MBR/VBR) и выполняет их дизассемблирование в 16-битном режиме с помощью Capstone. В процессе анализа вычисляется энтропия данных, определяется тип загрузчика, извлекаются параметры BPB и проводится частотный анализ используемых инструкций. Программа также выявляет подозрительные конструкции, признаки возможного XOR-шифрования и аномальное количество NOP-инструкций. Результаты исследования сохраняются в HTML-отчёт с подробной информацией о коде и обнаруженных артефактах, что делает инструмент полезным для изучения загрузчиков и анализа потенциально вредоносных boot-секторов.


import sys
from capstone import *
from collections import namedtuple
import os
from math import log2
from collections import Counter
from tqdm import tqdm

ENTROPY_THRESHOLD = 7.5
SUSPICIOUS_MNEMONICS = ['int', 'xor', 'rol', 'ror', 'shl', 'shr', 'jmp'] # добавить еще.
NOISE_BYTES = [0x00, 0x90, 0xCC] # добавить еще 

InstructionInfo = namedtuple("InstructionInfo", ["address", "mnemonic", "op_str", "comment", "color"])


def load_bootsector(path):
    with open(path, 'rb') as f:
        data = f.read()
        if len(data) != 512:
            raise ValueError("Boot sector must be exactly 512 bytes.")
        return data


def detect_type(sector):
    if sector[0x1FE:0x200] != b'\x55\xAA':
        return "Unknown"

    if sector[0x1C2:0x1C6] in [b'\x00\x00\x00\x00']:
        return "VBR"
    if sector[0x1BE:0x1BE+16][4] != 0x00:
        return "MBR"
    return "VBR"


def parse_bpb(data):
    try:
        bytes_per_sector = int.from_bytes(data[11:13], 'little')
        sectors_per_cluster = data[13]
        fs_type = data[54:62].decode(errors='ignore').strip()
        return {
            "Bytes per Sector": bytes_per_sector,
            "Sectors per Cluster": sectors_per_cluster,
            "Filesystem Type": fs_type
        }
    except Exception:
        return {}


def calc_entropy(data):
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    entropy = -sum((f / len(data)) * log2(f / len(data)) for f in freq if f)
    return entropy


def disasm_sector(data):
    md = Cs(CS_ARCH_X86, CS_MODE_16)
    md.detail = True
    instructions = []

    for insn in md.disasm(data, 0x7C00):
        color = ""
        comment = ""

        if insn.mnemonic in SUSPICIOUS_MNEMONICS:
            color = "red"
            comment = "Подозрительная инструкция"

        if insn.mnemonic == "int":
            try:
                int_num = int(insn.op_str, 16)
                if int_num in (0x10, 0x13):
                    color = "orange"
                    comment = f"Вызов прерывания int 0x{int_num:02X} (BIOS)"
            except ValueError:
                pass

        seg_regs = ['cs', 'ds', 'es']
        ops = insn.op_str.lower()
        if any(reg in ops for reg in seg_regs):
            if not color:
                color = "blue"
            comment = (comment + " ") if comment else ""
            comment += "Использование сегментного регистра"

        instructions.append(
            InstructionInfo(insn.address, insn.mnemonic, insn.op_str, comment.strip(), color)
        )
    return instructions


def analyze_instruction_frequency(instructions):
    mnemonics = [ins.mnemonic for ins in instructions]
    freq = Counter(mnemonics)
    total = len(instructions)

    nop_count = freq.get('nop', 0)
    nop_ratio = nop_count / total if total else 0

    return freq, nop_count, nop_ratio


def detect_xor_key(data):
    baseline_entropy = calc_entropy(data)
    best_key = None
    best_entropy = baseline_entropy

    for key in range(256):
        xored = bytes(b ^ key for b in data)
        ent = calc_entropy(xored)
        if ent < best_entropy:
            best_entropy = ent
            best_key = key

    if best_key is not None and baseline_entropy - best_entropy > 1.5:
        return best_key, best_entropy
    return None, None


def print_progress_bar(iteration, total, prefix='', suffix='', length=40, fill='█'):
    percent = f"{100 * (iteration / float(total)):.1f}"
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end='\r')
    if iteration == total:
        print()

def generate_html_report(instructions, entropy, boot_type, bpb_info, out_path, freq=None, nop_info=None, xor_info=None):
    lines = []

    lines.append("""<html>
    <head>
    <meta charset="UTF-8">
    <title>Boot Sector Analysis</title>
    <style>
        body { font-family: Consolas, monospace; }
        table { border-collapse: collapse; }
        td, th { border: 1px solid #aaa; padding: 4px; }
    </style>
    </head>
    <body>""")

    lines.append(f"<h2>Тип загрузчика: {boot_type}</h2>")
    suspicious_html = '<b style="color:red">(возможно шифрование)</b>' if entropy > ENTROPY_THRESHOLD else ''
    lines.append(f"<p>Энтропия: {entropy:.2f} {suspicious_html}</p>")

    if bpb_info:
        lines.append("<h3>BIOS Parameter Block (BPB)</h3><ul>")
        for k, v in bpb_info.items():
            lines.append(f"<li>{k}: {v}</li>")
        lines.append("</ul>")

    if freq:
        lines.append("<h3>Частотный анализ мнемоник</h3><table>")
        lines.append("<tr><th>Мнемоника</th><th>Количество</th></tr>")
        for mnemonic, count in sorted(freq.items(), key=lambda x: x[1], reverse=True):
            color = "red" if mnemonic == "nop" and nop_info and nop_info[1] > 0.1 else ""
            style = f" style='color:{color}'" if color else ""
            lines.append(f"<tr><td{style}>{mnemonic}</td><td>{count}</td></tr>")
        lines.append("</table>")

        if nop_info and nop_info[1] > 0.1:
            lines.append(f"<p style='color:red;'>[!] Высокое число NOP инструкций: {nop_info[0]} ({nop_info[1]:.2%})</p>")

    if xor_info and xor_info[0] is not None:
        key, ent_after_xor = xor_info
        lines.append(f"<h3>Обнаружение XOR-шифрования</h3>")
        lines.append(f"<p>Найден потенциальный XOR-ключ: <b>0x{key:02X}</b> с пониженной энтропией: {ent_after_xor:.2f}</p>")

    lines.append("<h3>Дизассемблированный код</h3><table border='1' cellpadding='4'>")
    lines.append("<tr><th>Адрес</th><th>Инструкция</th><th>Комментарий</th></tr>")

    for ins in tqdm(instructions, desc="Генерация отчёта", ncols=80):
        color = f" style='color:{ins.color}'" if ins.color else ""
        lines.append(f"<tr><td>{hex(ins.address)}</td><td{color}>{ins.mnemonic} {ins.op_str}</td><td>{ins.comment}</td></tr>")

    lines.append("</table></body></html>")

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))


def main():
    if len(sys.argv) != 2:
        print("Usage: python analyze_bootsector.py path\\to\\sector.bin")
        return

    path = sys.argv[1]
    sector = load_bootsector(path)
    boot_type = detect_type(sector)
    entropy = calc_entropy(sector)
    bpb = parse_bpb(sector) if boot_type == "VBR" else {}

    instructions = disasm_sector(sector)
    freq, nop_count, nop_ratio = analyze_instruction_frequency(instructions)
    print(f"[+] Инструкций всего: {len(instructions)}")
    print(f"[+] Частотный анализ мнемоник: {freq}")
    if nop_ratio > 0.1:
        print(f"[!] Высокое число NOP инструкций: {nop_count} ({nop_ratio:.2%})")

    key, ent_after_xor = detect_xor_key(sector)
    if key is not None:
        print(f"[!] Найден потенциальный XOR-ключ: 0x{key:02X} с пониженной энтропией {ent_after_xor:.2f}")
    out_html = os.path.splitext(path)[0] + "_report.html"
    freq, nop_count, nop_ratio = analyze_instruction_frequency(instructions)
    key, ent_after_xor = detect_xor_key(sector)

    out_html = os.path.splitext(path)[0] + "_report.html"
    generate_html_report(
        instructions,
        entropy,
        boot_type,
        bpb,
        out_html,
        freq=freq,
        nop_info=(nop_count, nop_ratio),
        xor_info=(key, ent_after_xor)
    )

    generate_html_report(instructions, entropy, boot_type, bpb, out_html)

    print(f"[+] Анализ завершён. Отчёт: {out_html}")


if __name__ == "__main__":
    main()
