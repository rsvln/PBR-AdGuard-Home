#!/bin/sh

# Wrapper скрипт для запуска PBR-AdGuard синхронизации
# Устанавливает переменные окружения и запускает Python сервис

export ADGUARD_URL="http://127.0.0.1:8070"
export ADGUARD_USER="admin"
export ADGUARD_PASS="ВАШ_ПАРОЛЬ"
export SYNC_INTERVAL="2"

exec /usr/bin/python3 /opt/pbr-sync/pbr_sync.py
