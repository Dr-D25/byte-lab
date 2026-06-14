# Скрипт выполняет статический анализ .NET PE-файлов и извлекает информацию из метаданных, включая список методов и строковых ресурсов. В процессе анализа выявляются потенциально обфусцированные методы, подозрительные строки и признаки использования base64- и GZIP-упакованных данных. Также выполняется поиск методов, связанных с динамической загрузкой, дешифрованием и выполнением кода. Результаты анализа сохраняются в интерактивный HTML-отчёт с возможностью фильтрации, просмотра статистики и изучения обнаруженных артефактов.


import sys
import os
import base64
import gzip
import json
from dnfile import dnPE
from collections import Counter
from html import escape

def is_obfuscated(name):
    return any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.' for c in name)

def extract_strings(pe):
    strings = []
    if not hasattr(pe.net, "user_streams"):
        return strings
    for s in pe.net.user_streams:
        if s.name == "#US":
            data = s.get_data()
            cur = 0
            while cur < len(data):
                if data[cur] == 0:
                    cur += 1
                    continue
                end = data.find(b'\x00', cur)
                if end == -1:
                    break
                try:
                    st = data[cur:end].decode('utf-8')
                    if len(st) > 4:
                        strings.append(st)
                except UnicodeDecodeError:
                    pass
                cur = end + 1
    return strings

def analyze_dotnet(file_path):
    print(f"[+] Анализ .NET файла: {file_path}")
    if not os.path.exists(file_path):
        print("[-] Файл не найден")
        return

    try:
        pe = dnPE(file_path)
    except Exception as e:
        print(f"[-] Не удалось загрузить PE-файл: {e}")
        return

    methods = []
    suspicious_methods = []
    strings = extract_strings(pe)
    suspicious_strings = []

    # Метаданные и методы
    try:
        if hasattr(pe.net, "metadata") and pe.net.metadata:
            stream = pe.net.metadata.get_stream("#~")
            if hasattr(stream, "tables") and hasattr(stream.tables, "MethodDef"):
                methods = list(stream.tables.MethodDef)
            else:
                print(" - Таблица методов не найдена.")
        else:
            print(" - Метаданные не обнаружены или повреждены.")
    except Exception as e:
        print(f" - Ошибка при чтении метаданных: {e}")

    # Анализ методов
    for m in methods:
        try:
            name = m.get_name()
            if is_obfuscated(name):
                suspicious_methods.append(name)
        except Exception:
            continue

    # Анализ подозрительных строк (base64 и длинные)
    encoded = [s for s in strings if "==" in s or s.startswith("TV") or len(s) > 100]

    # Попытка распаковки base64->gzip
    decoded_payloads = []
    for s in encoded[:10]:
        try:
            decoded = base64.b64decode(s)
            if decoded[:2] == b'\x1f\x8b':
                decompressed = gzip.decompress(decoded)
                decoded_payloads.append(decompressed[:100])
            else:
                decoded_payloads.append(decoded[:100])
        except Exception:
            decoded_payloads.append(b'')

    # Подозрительные вызовы (в названии метода)
    suspicious_calls = ['Assembly.Load', 
                                        'Invoke', 
                                        'Decrypt', 
                                        'Execute', 
                                        'Run', 
                                        'LoadModule']
    suspicious_found = [m for m in methods if any(call in getattr(m, 'get_name', lambda: '')() for call in suspicious_calls)]

    # Частотный анализ по методам
    method_names = []
    for m in methods:
        try:
            method_names.append(m.get_name())
        except Exception:
            continue
    method_freq = Counter(method_names)

    # Генерация HTML отчёта
    report_path = os.path.splitext(file_path)[0] + "_dotnet_report.html"
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<title>Отчет .NET анализа - {escape(os.path.basename(file_path))}</title>
<style>
body {{ font-family: Arial, sans-serif; background: #1e1e1e; color: #d4d4d4; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #555; padding: 8px; text-align: left; }}
th {{ background-color: #333; cursor: pointer; }}
tr:hover {{ background-color: #444; }}
input[type=text] {{ width: 300px; margin-bottom: 10px; padding: 5px; background: #2d2d2d; border: 1px solid #555; color: #ddd; }}
code {{ background-color: #252526; padding: 2px 4px; border-radius: 3px; }}
.collapsible {{
  background-color: #333;
  color: white;
  cursor: pointer;
  padding: 10px;
  width: 100%;
  border: none;
  text-align: left;
  outline: none;
  font-size: 15px;
}}

.active, .collapsible:hover {{
  background-color: #555;
}}

.content {{
  padding: 0 18px;
  display: none;
  overflow: hidden;
  background-color: #222;
}}
</style>
</head>
<body>

<h1>Отчет .NET анализа: {escape(os.path.basename(file_path))}</h1>

<h2>Общая статистика</h2>
<ul>
<li>Общее количество методов: {len(methods)}</li>
<li>Подозрительных методов (обфусцированных): {len(suspicious_methods)}</li>
<li>Найдено строк: {len(strings)}</li>
<li>Подозрительных base64/длинных строк: {len(encoded)}</li>
<li>Подозрительные вызовы в методах: {len(suspicious_found)}</li>
</ul>

<h2>Фильтр методов</h2>
<input type="text" id="methodFilter" onkeyup="filterTable('methodFilter', 'methodsTable')" placeholder="Поиск метода...">

<table id="methodsTable">
<thead>
<tr><th>Имя метода</th><th>Частота</th></tr>
</thead>
<tbody>
""")
        for m, c in method_freq.most_common():
            m_esc = escape(m)
            style = "color:#f00;" if is_obfuscated(m) else ""
            f.write(f"<tr><td style='{style}'>{m_esc}</td><td>{c}</td></tr>")
        f.write("</tbody></table>")

        f.write("""
<h2>Подозрительные методы (обфусцированные)</h2>
<button class="collapsible">Показать / Скрыть</button>
<div class="content">
<ul>
""")
        for m in suspicious_methods:
            f.write(f"<li><code>{escape(m)}</code></li>")
        f.write("</ul></div>")

        f.write("""
<h2>Подозрительные строки (base64 / длинные)</h2>
<button class="collapsible">Показать / Скрыть</button>
<div class="content">
<ul>
""")
        for s in encoded[:50]:
            f.write(f"<li><code>{escape(s)}</code></li>")
        f.write("</ul></div>")

        f.write("""
<h2>Распакованные Base64->GZIP payloads (первые 100 байт)</h2>
<button class="collapsible">Показать / Скрыть</button>
<div class="content">
""")
        for p in decoded_payloads:
            hex_repr = p.hex() if p else "(не удалось распаковать)"
            f.write(f"<pre>{hex_repr}</pre><hr>")
        f.write("</div>")

        f.write("""
<script>
function filterTable(inputId, tableId) {
    var input, filter, table, tr, td, i, txtValue;
    input = document.getElementById(inputId);
    filter = input.value.toLowerCase();
    table = document.getElementById(tableId);
    tr = table.getElementsByTagName("tr");
    for (i = 1; i < tr.length; i++) {
        td = tr[i].getElementsByTagName("td")[0];
        if (td) {
            txtValue = td.textContent || td.innerText;
            tr[i].style.display = txtValue.toLowerCase().indexOf(filter) > -1 ? "" : "none";
        }
    }
}
var coll = document.getElementsByClassName("collapsible");
for (let i = 0; i < coll.length; i++) {
  coll[i].addEventListener("click", function() {
    this.classList.toggle("active");
    var content = this.nextElementSibling;
    content.style.display = content.style.display === "block" ? "none" : "block";
  });
}
</script>

</body>
</html>
""")

    print(f"[+] Отчет сгенерирован: {report_path}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Использование: python analyze_dotnet.py путь\\к\\файлу.exe")
        sys.exit(1)
    analyze_dotnet(sys.argv[1])
