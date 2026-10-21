#!/usr/bin/env bash
# SupremeDuelist: APK -> Java + структура IL2CPP + тела методов + читаемый вид.
# Запуск из каталога доставки (там, где лежат base.apk / split_config.arm64_v8a.apk).
#
#   ./run.sh            # весь конвейер
#   SKIP_PULL=1 ./run.sh
#   SKIP_EXPORT=1 ./run.sh
#
set -euo pipefail

APP=${APP:-com.Neurononfire.SupremeDuelist}
WORK=${WORK:-$PWD}
GHIDRA=${GHIDRA:-$HOME/Tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadless}
JADX=${JADX:-jadx}
DOTNET=${DOTNET:-$HOME/.dotnet/dotnet}
THREADS=${THREADS:-4}
CPP2IL=${CPP2IL:-$WORK/tools/cpp2il/cpp2il}

cd "$WORK"
say() { printf '\n=== %s ===\n' "$*"; }

# 1) APK с устройства
if [ -z "${SKIP_PULL:-}" ]; then
  say "pull APK"
  BASE=$(adb shell pm path "$APP" | sed 's/^package://' | tr -d '\r' | head -1)
  adb pull "$BASE" base.apk
  adb shell pm path "$APP" | sed 's/^package://' | tr -d '\r' |
    grep -E 'split_config\.arm64' | head -1 | xargs -r adb pull
fi

# 2) Java-слой
if [ ! -d src ]; then
  say "jadx"
  "$JADX" -d src --threads-count "$THREADS" base.apk split_config.arm64_v8a.apk
fi

# 3) IL2CPP: метаданные + нативная библиотека
mkdir -p il2cpp
[ -f il2cpp/global-metadata.dat ] || \
  unzip -j -o base.apk 'assets/bin/Data/Managed/Metadata/global-metadata.dat' -d il2cpp
[ -f il2cpp/libil2cpp.so ] || \
  unzip -j -o split_config.arm64_v8a.apk 'lib/arm64-v8a/libil2cpp.so' -d il2cpp

# 4) Структура: типы/методы/RVA + DummyDll
if [ ! -f dump/dump.cs ]; then
  say "Il2CppDumper"
  "$DOTNET" tools/Il2CppDumper/Il2CppDumper.dll \
    il2cpp/libil2cpp.so il2cpp/global-metadata.dat dump
fi

# 5) Скелеты C# (Cpp2IL): поля, сигнатуры, пустые тела
if [ ! -d cs_skeletons ]; then
  say "Cpp2IL"
  "$CPP2IL" --game-path tools/merged.apk --output-to cs_skeletons --output-as diffable-cs
fi

# 6) Ghidra: импорт + дизассемблирование только тел методов
if [ ! -d ghidra_proj2 ]; then
  say "Ghidra setup (только тела методов)"
  GHIDRA_HEADLESS_MAXMEM=2600m "$GHIDRA" \
    "$WORK/ghidra_proj2" Il2Cpp -import "$WORK/il2cpp/libil2cpp.so" -noanalysis \
    -scriptPath "$WORK/ghidra_scripts" -postScript Il2CppSetupBodies.java "$WORK/ghidra_in"
fi

# 7) Декомпиляция тел (быстрый режим: 3 с на метод)
if [ -z "${SKIP_EXPORT:-}" ] && [ ! -f csharp/INDEX.txt ]; then
  say "Ghidra export"
  GHIDRA_HEADLESS_MAXMEM=2600m "$GHIDRA" \
    "$WORK/ghidra_proj2" Il2Cpp -process "libil2cpp.so" -noanalysis \
    -scriptPath "$WORK/ghidra_scripts" -postScript Il2CppExport.java \
    "$WORK/ghidra_in" "$WORK/csharp" "$THREADS"
fi

# 8) Читаемый вид: имена параметров, вызовов Unity, полей
if [ -d csharp ]; then
  say "beautify"
  python3 beautify.py csharp csharp_pretty
fi

say "готово: src/ cs_skeletons/ dump/dump.cs csharp/ csharp_pretty/"
