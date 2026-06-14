# Скрипт предназначен для поиска потенциальных ROP-гаджетов в 16-битном загрузочном секторе размером 512 байт с использованием библиотеки Capstone. Он перебирает различные смещения и длины последовательностей, выделяя инструкции, оканчивающиеся на ret, а также позволяет фильтровать результаты по заданным мнемоникам и количеству инструкций. Найденные гаджеты сохраняются в HTML-отчёт с таблицей и интерактивными диаграммами, отображающими распределение гаджетов по длине и числу инструкций. Инструмент может использоваться для исследования структуры загрузочных секторов и анализа коротких инструкционных последовательностей в учебных и экспериментальных целях.

# python find_rop_gadgets.py sector.bin 1 5 1 5 pop,xor,mov


import sys
import os
from capstone import *

def load_bootsector(path):
    with open(path, 'rb') as f:
        data = f.read()
        if len(data) != 512:
            raise ValueError("Boot sector must be exactly 512 bytes.")
        return data

def find_rop_gadgets(data, min_len=1, max_len=5, min_instr=1, max_instr=5, filter_mnemonics=None):
    md = Cs(CS_ARCH_X86, CS_MODE_16)
    md.detail = False
    gadgets = []

    data_len = len(data)

    for offset in range(data_len):
        for length in range(min_len, max_len + 1):
            if offset + length > data_len:
                continue
            code_slice = data[offset:offset+length]
            instructions = list(md.disasm(code_slice, 0x7C00 + offset))
            if not instructions:
                continue

            last_byte = code_slice[-1]
            if last_byte not in (0xC3, 0xC2):
                continue
            if instructions[-1].mnemonic != "ret":
                continue
            if not (min_instr <= len(instructions) <= max_instr):
                continue

            if filter_mnemonics:
                mnems = [ins.mnemonic for ins in instructions]
                if not any(m in mnems for m in filter_mnemonics):
                    continue

            gadget_str = "; ".join(f"{ins.mnemonic} {ins.op_str}".strip() for ins in instructions)
            gadgets.append((0x7C00 + offset, length, len(instructions), gadget_str))

    gadgets.sort(key=lambda x: (x[1], x[0]))
    return gadgets

def generate_html_report(gadgets, out_path):
    length_stats = {}
    instr_count_stats = {}

    for _, length, instr_count, _ in gadgets:
        length_stats[length] = length_stats.get(length, 0) + 1
        instr_count_stats[instr_count] = instr_count_stats.get(instr_count, 0) + 1

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write("""
        <html><head><meta charset="utf-8">
        <title>ROP Gadgets Report</title>
        <style>
            body { font-family: Consolas, monospace; background: #f0f0f0; padding: 20px; }
            table { border-collapse: collapse; width: 100%; background: white; }
            th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
            th { background-color: #2c3e50; color: white; }
            tr:nth-child(even) { background-color: #ecf0f1; }
            tr:hover { background-color: #d1d8e0; }
            .chart-container { width: 45%; display: inline-block; margin: 1em; vertical-align: top; }
        </style>
        <!-- Chart.js CDN -->
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        </head><body>
        <h2>ROP Gadgets Report</h2>
        """)

        if not gadgets:
            f.write("<p>ROP-гаджеты не обнаружены.</p>")
        else:
            f.write(f"<p>Найдено гаджетов: {len(gadgets)}</p>")

            f.write("<table>")
            f.write("<tr><th>Адрес</th><th>Длина (байт)</th><th>Инструкций</th><th>Инструкция</th></tr>")
            for addr, length, instr_count, gadget_str in gadgets:
                f.write(f"<tr><td>{hex(addr)}</td><td>{length}</td><td>{instr_count}</td><td>{gadget_str}</td></tr>")
            f.write("</table>")

            f.write("""
            <div class="chart-container">
                <canvas id="lengthChart"></canvas>
            </div>
            <div class="chart-container">
                <canvas id="instrCountChart"></canvas>
            </div>

            <script>
                const lengthCtx = document.getElementById('lengthChart').getContext('2d');
                const lengthChart = new Chart(lengthCtx, {
                    type: 'bar',
                    data: {
                        labels: """ + str(list(length_stats.keys())) + """,
                        datasets: [{
                            label: 'Количество гаджетов по длине (байт)',
                            data: """ + str(list(length_stats.values())) + """,
                            backgroundColor: 'rgba(54, 162, 235, 0.7)'
                        }]
                    },
                    options: { scales: { y: { beginAtZero: true } } }
                });

                const instrCtx = document.getElementById('instrCountChart').getContext('2d');
                const instrChart = new Chart(instrCtx, {
                    type: 'bar',
                    data: {
                        labels: """ + str(list(instr_count_stats.keys())) + """,
                        datasets: [{
                            label: 'Количество гаджетов по количеству инструкций',
                            data: """ + str(list(instr_count_stats.values())) + """,
                            backgroundColor: 'rgba(255, 99, 132, 0.7)'
                        }]
                    },
                    options: { scales: { y: { beginAtZero: true } } }
                });
            </script>
            """)

        f.write("</body></html>")

def main():
    if len(sys.argv) < 2:
        print("Usage: python find_rop_gadgets.py path\\to\\sector.bin [min_len max_len min_instr max_instr mnemonics]")
        print("mnemonics: comma-separated list, e.g. pop,xor,mov")
        return

    path = sys.argv[1]
    min_len = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    max_len = int(sys.argv[3]) if len(sys.argv) > 3 else 5
    min_instr = int(sys.argv[4]) if len(sys.argv) > 4 else 1
    max_instr = int(sys.argv[5]) if len(sys.argv) > 5 else 5

    filter_mnemonics = None
    if len(sys.argv) > 6:
        filter_mnemonics = sys.argv[6].split(',')

    sector = load_bootsector(path)
    gadgets = find_rop_gadgets(sector, min_len, max_len, min_instr, max_instr, filter_mnemonics)

    if gadgets:
        print(f"[!] Найдено {len(gadgets)} потенциальных ROP-гаджетов.")
    else:
        print("[+] ROP-гаджеты не обнаружены.")

    out_html = os.path.splitext(path)[0] + "_rop_report.html"
    generate_html_report(gadgets, out_html)
    print(f"[+] Отчёт сохранён в: {out_html}")

if __name__ == "__main__":
    main()
