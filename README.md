# supreme-duelist-tools

Инструменты для декомпиляции Unity **IL2CPP**-приложений: Java-слой, метаданные, C#-скелеты,
тела методов через Ghidra headless, пост-обработка в читаемый вид.

В репозитории **нет** кода или бинарей каких-либо игр — только скрипты.
Входные данные (APK, `libil2cpp.so`, `global-metadata.dat`) и результаты лежат
в отдельном приватном репозитории и подключаются через `PRIVATE_REPO_TOKEN`.

## Конвейер

```
APK ──jadx──► src/ (Java)
   └─unzip──► global-metadata.dat + libil2cpp.so
                  ├─ Il2CppDumper ──► dump.cs, script.json, il2cpp.h, DummyDll/
                  ├─ Cpp2IL       ──► cs_skeletons/ (структура C#, пустые тела)
                  └─ Ghidra       ──► csharp/ (тела методов, C-псевдокод)
                                          └─ beautify.py ──► csharp_pretty/
```

| Файл | Назначение |
|---|---|
| `run.sh` | весь конвейер одной командой |
| `beautify.py` | имена параметров, вызовов Unity, полей из `dump.cs` |
| `ghidra_scripts/Il2CppSetupBodies.java` | импорт + дизассемблирование **только тел методов** |
| `ghidra_scripts/Il2CppExport.java` | декомпиляция тел, таймаут на метод, N потоков |
| `ghidra_scripts/Il2CppSetup.java` | полный вариант (вся `.text`, для сравнения) |
| `.github/workflows/decompile.yml` | прогон на GitHub Actions (4 vCPU / 16 ГБ) |

## Почему Ghidra «вязнет» на IL2CPP

1. `Funcdata::startProcessing()` вызывает `followFlow(0, ~0)` — обход потока **не ограничен
   телом функции** (`funcdata.cc`, `funcdata_op.cc`).
2. `FlowInfo::checkContainedCall()` (`flow.cc`) превращает `bl` в **ветвь**, если цель уже
   попала в посещённый код (`Possible PIC construction … Changing call to branch`).
3. Хвостовые вызовы `b <addr>` для декомпилятора неотличимы от внутренних переходов.

В IL2CPP методы лежат вплотную, делят общие хвосты и хелперы, а часть RVA указывает
на фрагменты чужих тел — поэтому декомпилятор втягивает соседний код и раздувает CFG.
Отключаемой опции для этого нет; лечится тайм-боксом на метод
(`decompileFunction(f, N, monitor)`) либо изоляцией тел в отдельном адресном пространстве.

## Запуск

```bash
./run.sh                 # локально, нужны APK + split_config.arm64_v8a.apk
SKIP_PULL=1 ./run.sh     # без adb pull
```

Требования: `jadx`, `~/.dotnet/dotnet` + Il2CppDumper, Cpp2IL, Ghidra 12.x, Python 3.
