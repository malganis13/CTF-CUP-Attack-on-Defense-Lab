# Установка как приложения

Один код, две платформы, запуск мышью. Консоль не нужна ни там, ни там.

## Windows 11

Готовый файл: `dist\AD-Audit.exe` (≈9 МБ, без консоли).

- двойной клик → приложение поднимает локальный сервер и открывает браузер;
- рядом с exe появляется `config.json` (цель без пароля), больше ничего не пишется;
- остановить: кнопка «Остановить сервер» в сайдбаре, либо закрыть процесс `AD-Audit.exe`;
- если 8765 занят другим экземпляром — просто откроется он, второй процесс не стартует.

Пересобрать:

```powershell
.\packaging\windows\build.ps1
.\packaging\windows\build.ps1 -OutDir D:\dist   # если на C: мало места
```

Нужен Python 3.10+ и `pyinstaller`; скрипт поставит его сам.

## Linux (Arch, Nyarch, любая с Python 3.10+)

```bash
cd ad-audit/packaging/linux
chmod +x install.sh uninstall.sh
./install.sh              # в ~/.local, без root
sudo ./install.sh --system  # в /usr/local, для всех
```

Что ставится:

- `~/.local/share/ad-audit/` — приложение (stdlib, без venv и зависимостей);
- `~/.local/bin/ad-audit` — лаунчер;
- `~/.local/share/applications/ad-audit.desktop` — ярлык «AD Audit» в меню;
- иконка в `~/.local/share/icons/hicolor/scalable/apps/ad-audit.svg`.

Запуск: из меню приложений или `ad-audit`. Демо без цели: `ad-audit --demo`.

Удалить: `./uninstall.sh` (или `sudo ./uninstall.sh --system`).

## Почему без зависимостей

Сервер, сканер, пробы и отчёты — стандартная библиотека Python. SSH берётся
системный (`ssh`), поэтому на Linux с OpenSSH всё работает сразу. `paramiko`
нужен только для входа по паролю — ставится отдельно, приложение его не требует.
