# pexw - Cross-Platform PE String Extractor

Кроссплатформенный инструмент для извлечения и расшифровки строк из PE файлов (DLL/EXE).

## Особенности

- **Кроссплатформенность**: Windows, Linux, macOS
- **Capstone дизассемблер**: Точный анализ машинного кода
- **XOR дешифрование**: Автоматическое дешифрование с ключом 0x5
- **Экспорт**: JSON и CSV форматы

## Версии

### expwds.c (Windows-only)
- Использует WinAPI для работы с файлами
- Ручной парсинг PE структур
- Не требует внешних библиотек

### expwds_cross.c (Cross-platform)
- Работает на Windows, Linux, macOS
- Использует Capstone для дизассемблирования
- Универсальные POSIX API для файлов

## Установка зависимостей

### Windows (MSYS2/MinGW)
```bash
pacman -S mingw-w64-x86_64-capstone
```

### Windows (MSYS2/UCRT64)
```bash
pacman -S mingw-w64-ucrt-x86_64-capstone
```

### Linux (Debian/Ubuntu)
```bash
sudo apt-get install libcapstone-dev
```

### Linux (Fedora/RHEL)
```bash
sudo dnf install capstone-devel
```

### macOS
```bash
brew install capstone
```

## Сборка

### Сборка с помощью CMake (рекомендуется)

```bash
cd utils
mkdir build
cd build

# Конфигурация
cmake ..

# Компиляция
cmake --build .

# Установка (опционально)
cmake --install .
```

### Сравнение систем сборки

| Функция | CMake | Meson |
|---------|-------|-------|
| Поиск зависимостей | ✅ | ✅ |
| Кроссплатформенность | ✅ | ✅ |
| Автоопределение компилятора | ✅ | ✅ |
| Параллельная сборка | ✅ | ✅ |
| Установка | ✅ | ✅ |
| Синтаксис | CMakeLists.txt | meson.build |
| Генератор | Ninja/Make | Ninja |
| Скорость конфигурации | Средняя | Быстрая |

## Использование

#### Windows (MSYS2)
```bash
gcc expwds_cross.c -o expwds_cross -lcapstone -O2
```

#### Linux
```bash
gcc expwds_cross.c -o expwds_cross -lcapstone -O2 -Wall
```

#### macOS
```bash
gcc expwds_cross.c -o expwds_cross -lcapstone -O2 -Wall
```

### Windows-only версия (без Capstone)
```bash
gcc expwds.c -o expwds.exe -O2
```

## Использование

```bash
# Базовое использование
./expwds_cross SoulWorker64.dll

# С указанием выходных файлов
./expwds_cross SoulWorker64.dll output.json output.csv

# Windows версия
./expwds.exe SoulWorker64.dll
```

## Выходные форматы

### JSON (dictionary.json)
```json
{
  "image_base": "0x180000000",
  "decryption_key": "0x05",
  "data_entries": [
    {
      "marker": "data88",
      "encrypted": "F?YRjw...",
      "decrypted": "C:\\Workspace...",
      "rdata_rva": "0x3E400",
      "string_rva": "0x42A10"
    }
  ]
}
```

### CSV (strings.csv)
```csv
Marker,Encrypted,Decrypted,RDATA_RVA,STRING_RVA
"data88","F?YRjw...","C:\\Workspace...",0x3E400,0x42A10
```

## Алгоритм работы

1. **Загрузка PE файла**: Memory mapping для эффективной работы
2. **Парсинг заголовков**: DOS, NT, Optional Headers
3. **Поиск секций**: .text (код) и .rdata (данные)
4. **Поиск маркеров**: Сканирование dataXX паттернов
5. **Дизассемблирование**: Анализ .text с помощью Capstone
6. **Поиск функций**: 
   - Функция инициализации маркеров
   - Функция инициализации строк
7. **Сопоставление**: Связывание маркеров со строками (reverse order)
8. **Дешифрование**: XOR каждого байта с 0x5
9. **Экспорт**: JSON и CSV

## Техническая информация

### Структура PE файла
```
DOS Header (MZ)
  └─> e_lfanew → NT Headers (PE)
                   ├─> File Header
                   └─> Optional Header64
                         └─> Sections
                               ├─> .text (код)
                               └─> .rdata (данные)
```

### Поиск функций инициализации

**Паттерн пролога функции:**
```asm
push rbp          ; или
sub rsp, 0x38     ; Выделение стека
```

**Паттерн LEA для .rdata:**
```asm
lea rdx, [rip + disp]  ; 48 8D 15 [disp]
```

**Критерии функции маркеров:**
- ≥15 LEA инструкций
- Все ссылки на dataXX маркеры
- Нет ссылок на другие строки

**Критерии функции строк:**
- ≥15 LEA инструкций  
- Все ссылки НЕ на маркеры
- Находится после функции маркеров

### XOR дешифрование
```c
for (int i = 0; i < len; i++) {
    decrypted[i] = encrypted[i] ^ 0x05;
}
```

## Различия версий

| Функция | expwds.c | expwds_cross.c |
|---------|----------|----------------|
| Windows | ✅ | ✅ |
| Linux | ❌ | ✅ |
| macOS | ❌ | ✅ |
| WinAPI | ✅ | ❌ |
| POSIX | ❌ | ✅ |
| Capstone | ❌ | ✅ |
| Зависимости | Нет | libcapstone |
| Размер exe | ~50KB | ~100KB |

## Примеры

### Анализ SoulWorker64.dll
```bash
./expwds_cross 'F:\Games\SoulWorker\SoulWorker64.dll'
```

Вывод:
```
[+] DOS Header: 0x108
[+] PE Signature found
[+] Machine: 0x8664
[+] Sections: 6
[+] Image Base: 0x180000000
[+] .text VA=0x1000 Size=0x2B5E9
[+] .rdata VA=0x3E000 Size=0x1E7D0
[+] Total: 21 markers
[+] Marker function at 0x7A20 (21 markers)
[+] String function at 0x7B60 (21 strings)
[+] Mapped: 21
```

### Анализ BaseDX11.dll
```bash
./expwds_cross 'F:\Games\SoulWorker\BaseDX11.dll'
```

## Устранение проблем

### "Capstone library not found"
- **Windows**: `pacman -S mingw-w64-x86_64-capstone`
- **Linux**: `sudo apt-get install libcapstone-dev`
- **macOS**: `brew install capstone`

### "Invalid DOS signature"
- Проверьте, что файл является PE (не упакован/защищен)

### "Required sections not found"
- PE файл должен содержать .text и .rdata секции

### "Marker function not found"
- Возможно другой паттерн инициализации
- Попробуйте Windows версию (другая эвристика)

## Лицензия

MIT License

## Авторы

- Original Windows version
- Cross-platform port with Capstone integration

## См. также

- [Capstone Engine](http://www.capstone-engine.org/)
- [PE Format Specification](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
