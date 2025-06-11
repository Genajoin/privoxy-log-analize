#!/bin/bash

# Скрипт запуска Privoxy Log Analyzer с автоматической загрузкой на веб-сервер

set -e

ENV_NAME="privoxy-log-analyzer"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Логирование для crontab
LOG_FILE="${SCRIPT_DIR}/logs/privoxy_analyzer.log"
mkdir -p "${SCRIPT_DIR}/logs"

# Функция логирования
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Загружаем переменные из .env файла если он существует
if [[ -f "${SCRIPT_DIR}/.env" ]]; then
    log "Загрузка настроек из .env файла"
    export $(grep -v '^#' "${SCRIPT_DIR}/.env" | xargs)
fi

# Настройки для автоматической загрузки (можно переопределить через переменные окружения)
UPLOAD_USER="${PRIVOXY_UPLOAD_USER:-}"
UPLOAD_HOST="${PRIVOXY_UPLOAD_HOST:-your-server.com}"
UPLOAD_PATH="${PRIVOXY_UPLOAD_PATH:-~/public_html/reports}"

log "=== Запуск Privoxy Log Analyzer ==="

# Ищем conda в различных стандартных местах
CONDA_PATHS=(
    "/home/$(whoami)/miniforge3/bin/conda"
    "/home/$(whoami)/miniconda3/bin/conda"
    "/home/$(whoami)/anaconda3/bin/conda"
    "/opt/conda/bin/conda"
    "/usr/local/bin/conda"
)

CONDA_EXE=""
for path in "${CONDA_PATHS[@]}"; do
    if [[ -x "$path" ]]; then
        CONDA_EXE="$path"
        break
    fi
done

# Если conda не найдена в стандартных местах, попробуем через PATH
if [[ -z "$CONDA_EXE" ]] && command -v conda &> /dev/null; then
    CONDA_EXE=$(which conda)
fi

if [[ -z "$CONDA_EXE" ]]; then
    log "Ошибка: conda не найдена. Установите Anaconda или Miniconda."
    exit 1
fi

log "Используется conda: $CONDA_EXE"

# Инициализируем conda для bash
eval "$("$CONDA_EXE" shell.bash hook)" 2>/dev/null || {
    log "Ошибка: не удалось инициализировать conda"
    exit 1
}

# Проверяем существование окружения
if ! "$CONDA_EXE" env list | grep -q "^${ENV_NAME}\s"; then
    log "Создание conda окружения ${ENV_NAME}..."
    "$CONDA_EXE" env create -f "${SCRIPT_DIR}/environment.yml" >> "$LOG_FILE" 2>&1
    log "Окружение создано."
else
    log "Окружение ${ENV_NAME} уже существует."
fi

# Активируем окружение
log "Активация окружения ${ENV_NAME}..."
conda activate "${ENV_NAME}" 2>/dev/null || {
    log "Ошибка: не удалось активировать окружение ${ENV_NAME}"
    exit 1
}

# Переходим в рабочую директорию
cd "${SCRIPT_DIR}"

# Определяем параметры запуска
if [[ "$#" -gt 0 ]]; then
    # Если переданы аргументы, используем их
    log "Запуск анализа логов с параметрами: $*"
    python main.py "$@" >> "$LOG_FILE" 2>&1
else
    # Автоматический режим с загрузкой на веб-сервер
    if [[ -n "$UPLOAD_USER" ]]; then
        log "Запуск анализа логов с автоматической загрузкой на $UPLOAD_HOST"
        python main.py --upload --upload-user "$UPLOAD_USER" --upload-host "$UPLOAD_HOST" --upload-path "$UPLOAD_PATH" >> "$LOG_FILE" 2>&1
    else
        log "Запуск анализа логов без загрузки (PRIVOXY_UPLOAD_USER не задан)"
        python main.py >> "$LOG_FILE" 2>&1
    fi
fi

log "Анализ завершен успешно."

# Очистка старых логов (оставляем последние 30 дней)
find "${SCRIPT_DIR}/logs" -name "privoxy_analyzer.log.*" -mtime +30 -delete 2>/dev/null || true

# Ротация лога если он больше 10MB
if [[ -f "$LOG_FILE" ]] && [[ $(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE" 2>/dev/null || echo 0) -gt 10485760 ]]; then
    mv "$LOG_FILE" "${LOG_FILE}.$(date +%Y%m%d_%H%M%S)"
    log "Лог файл ротирован"
fi