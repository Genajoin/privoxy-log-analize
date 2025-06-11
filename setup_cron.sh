#!/bin/bash

# Скрипт для настройки crontab для Privoxy Log Analyzer

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRON_SCRIPT="$SCRIPT_DIR/run.sh"

echo "=== Настройка автоматического запуска Privoxy Log Analyzer ==="

# Проверяем существование основного скрипта
if [[ ! -f "$CRON_SCRIPT" ]]; then
    echo "Ошибка: файл $CRON_SCRIPT не найден"
    exit 1
fi

# Убеждаемся что скрипт исполняемый
chmod +x "$CRON_SCRIPT"

echo "Выберите частоту запуска:"
echo "1) Каждые 15 минут"
echo "2) Каждый час"
echo "3) Каждые 4 часа"
echo "4) Каждые 12 часов"
echo "5) Один раз в день (в 06:00)"
echo "6) Пользовательская настройка"

read -p "Введите номер (1-6): " choice

case $choice in
    1)
        CRON_SCHEDULE="*/15 * * * *"
        DESCRIPTION="каждые 15 минут"
        ;;
    2)
        CRON_SCHEDULE="0 * * * *"
        DESCRIPTION="каждый час"
        ;;
    3)
        CRON_SCHEDULE="0 */4 * * *"
        DESCRIPTION="каждые 4 часа"
        ;;
    4)
        CRON_SCHEDULE="0 */12 * * *"
        DESCRIPTION="каждые 12 часов"
        ;;
    5)
        CRON_SCHEDULE="0 6 * * *"
        DESCRIPTION="ежедневно в 06:00"
        ;;
    6)
        read -p "Введите cron расписание (например, '0 */2 * * *'): " CRON_SCHEDULE
        DESCRIPTION="пользовательское расписание"
        ;;
    *)
        echo "Неверный выбор"
        exit 1
        ;;
esac

# Запрашиваем настройки SSH
echo ""
echo "Настройка SSH для загрузки на веб-сервер:"
read -p "Введите SSH пользователя для timeweb.flybeeper.com: " SSH_USER

if [[ -z "$SSH_USER" ]]; then
    echo "Пользователь не указан, загрузка на веб-сервер будет отключена"
    ENV_VARS=""
else
    echo "SSH пользователь: $SSH_USER"
    
    # Проверяем наличие SSH ключей
    if [[ ! -f ~/.ssh/id_rsa && ! -f ~/.ssh/id_ed25519 ]]; then
        echo "Внимание: SSH ключи не найдены в ~/.ssh/"
        echo "Убедитесь что настроен доступ по ключам к серверу $SSH_USER@timeweb.flybeeper.com"
    fi
    
    ENV_VARS="PRIVOXY_UPLOAD_USER='$SSH_USER' "
fi

# Создаем cron задачу
CRON_LINE="$CRON_SCHEDULE cd '$SCRIPT_DIR' && ${ENV_VARS}'$CRON_SCRIPT' >/dev/null 2>&1"

echo ""
echo "Будет добавлена следующая cron задача:"
echo "$CRON_LINE"
echo "Описание: запуск $DESCRIPTION"
echo ""

read -p "Продолжить? (y/N): " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "Отменено"
    exit 0
fi

# Добавляем в crontab
(crontab -l 2>/dev/null | grep -v "$CRON_SCRIPT"; echo "$CRON_LINE") | crontab -

if [[ $? -eq 0 ]]; then
    echo "✓ Cron задача успешно добавлена"
    echo ""
    echo "Текущие cron задачи:"
    crontab -l | grep "$CRON_SCRIPT" || echo "Нет задач для данного скрипта"
    echo ""
    echo "Логи будут сохраняться в: $SCRIPT_DIR/logs/privoxy_analyzer.log"
    echo ""
    echo "Для удаления задачи выполните:"
    echo "crontab -e"
    echo ""
    echo "Для просмотра логов выполните:"
    echo "tail -f '$SCRIPT_DIR/logs/privoxy_analyzer.log'"
else
    echo "✗ Ошибка при добавлении cron задачи"
    exit 1
fi