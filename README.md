# PBR-AdGuard Home синхронизация

Сервис для автоматической синхронизации IP адресов между AdGuard Home Query Log и PBR nftables sets в OpenWrt.

## Описание

Этот сервис решает фундаментальную проблему несовместимости AdGuard Home и Policy-Based Routing (PBR) в OpenWrt.

### Проблематика

При попытке использовать AdGuard Home совместно с PBR и получать детальную статистику по локальным клиентам возникает неразрешимый конфликт:

**Суть проблемы:**
- Для статистики по клиентам AdGuard Home должен видеть реальные IP адреса запросов
- Для работы PBR с доменами dnsmasq должен обрабатывать DNS запросы и заполнять nft sets
- Эти требования взаимоисключающи в стандартной архитектуре OpenWrt

**Испробованные варианты (не работают):**
- Docker в bridge режиме → все запросы от IP контейнера
- Docker в host режиме → все запросы от IP хоста OpenWrt  
- Docker на macvlan → все запросы от IP macvlan интерфейса
- Форвардинг через dnsmasq + EDNS → AdGuard Home все равно видит только 127.0.0.1
- Любое размещение AdGuard Home → либо нет статистики, либо не работает PBR с доменами

**Корневая причина:**
OpenWrt архитектурно не позволяет одновременно:
1. Передавать реальные IP клиентов в AdGuard Home для статистики
2. Обрабатывать DNS запросы в dnsmasq для автоматического заполнения PBR nft sets

### Решение

PBR Sync Service обходит архитектурные ограничения через API интеграцию:
1. AdGuard Home получает реальные IP клиентов (любым способом - redirect, ECS и т.д.)
2. Сервис мониторит Query Log AdGuard Home через REST API
3. При обнаружении доменов из PBR политик извлекает IP адреса и добавляет в nft sets
4. PBR получает заполненные nft sets и корректно маршрутизирует трафик по доменам

**Результат**: впервые становится возможным одновременное использование детальной статистики AdGuard Home и полнофункционального PBR с доменами в OpenWrt.

## Возможности

- Автоматическое обнаружение PBR nft sets
- Мониторинг AdGuard Home Query Log через API
- Синхронизация IP адресов в реальном времени
- Фильтрация недопустимых IP (0.0.0.0, 127.x.x.x)
- Настраиваемая частота опроса
- Автоматическая перезагрузка PBR для очистки правил
- Логирование всех операций

## Требования

- OpenWrt с установленным PBR
- AdGuard Home с включенным API
- Python 3 с модулями: requests, schedule
- Redirect правила DNS для видимости IP клиентов

## Установка

### 1. Установка зависимостей

```bash
opkg update
opkg install python3 python3-pip
pip3 install requests schedule
```

### 2. Создание структуры

```bash
mkdir -p /opt/pbr-sync
cd /opt/pbr-sync
```

### 3. Копирование файлов

Скопируйте в директорию `/opt/pbr-sync/`:
- `pbr_sync.py` - основной сервис
- `start.sh` - wrapper скрипт

### 4. Настройка конфигурации

Отредактируйте `start.sh`:
```bash
nano /opt/pbr-sync/start.sh
```

Измените переменные:
```bash
export ADGUARD_URL="http://127.0.0.1:8070"    # URL AdGuard Home
export ADGUARD_USER="admin"                     # Пользователь
export ADGUARD_PASS="ВАШ_ПАРОЛЬ"              # Пароль
export SYNC_INTERVAL="2"                       # Интервал в минутах
```

### 5. Установка прав

```bash
chmod +x /opt/pbr-sync/start.sh
chmod +x /opt/pbr-sync/pbr_sync.py
```

### 6. Создание init.d сервиса

```bash
cp pbr-sync /etc/init.d/
chmod +x /etc/init.d/pbr-sync
```

### 7. Включение автозапуска

```bash
/etc/init.d/pbr-sync enable
/etc/init.d/pbr-sync start
```

## Настройка redirect правил

Для полной функциональности включите redirect правила DNS:

```bash
uci add firewall redirect
uci set firewall.@redirect[-1].name='dns_redirect_udp'
uci set firewall.@redirect[-1].src='lan'
uci set firewall.@redirect[-1].proto='udp'
uci set firewall.@redirect[-1].src_dport='53'
uci set firewall.@redirect[-1].dest_port='5353'
uci set firewall.@redirect[-1].target='DNAT'

uci add firewall redirect
uci set firewall.@redirect[-1].name='dns_redirect_tcp'
uci set firewall.@redirect[-1].src='lan'
uci set firewall.@redirect[-1].proto='tcp'
uci set firewall.@redirect[-1].src_dport='53'
uci set firewall.@redirect[-1].dest_port='5353'
uci set firewall.@redirect[-1].target='DNAT'

uci commit firewall
/etc/init.d/firewall restart
```

## Управление сервисом

```bash
# Запуск
/etc/init.d/pbr-sync start

# Остановка
/etc/init.d/pbr-sync stop

# Перезапуск
/etc/init.d/pbr-sync stop
/etc/init.d/pbr-sync start

# Статус
ps | grep pbr_sync
```

## Мониторинг

### Просмотр логов

```bash
# Текущие логи
tail -f /var/log/pbr-sync.log

# Системные логи
logread | grep pbr-sync
```

### Проверка nft sets

```bash
# Список PBR sets
nft list table inet fw4 | grep "set pbr"

# Содержимое конкретного set
nft list set inet fw4 pbr_awgmd_4_dst_ip_cfg066ff5
```

### Тестирование

```bash
# Проверка AdGuard Home API
curl -s http://127.0.0.1:8070/control/status

# Проверка PBR конфигурации
uci show pbr

# DNS запрос для тестирования
nslookup youtube.com
```

## Расписание работы

- **Синхронизация доменов**: каждые N минут (настраивается)
- **Перезагрузка конфигурации**: каждый час
- **Перезапуск PBR**: ежедневно в 06:00

## Настройка параметров

Все настройки находятся в `/opt/pbr-sync/start.sh`:

- `ADGUARD_URL` - URL веб-интерфейса AdGuard Home
- `ADGUARD_USER` - имя пользователя для API
- `ADGUARD_PASS` - пароль для API
- `SYNC_INTERVAL` - интервал синхронизации в минутах

После изменения параметров перезапустите сервис.

## Архитектура

```
Клиенты → redirect (53→5353) → AdGuard Home
    ↓                               ↑ ↓
dnsmasq ← форвардинг ←──────────────┘ │
    ↓                                 │
nft sets ← PBR                        │
    ↑                                 │
PBR Sync Service ←── Query Log API ───┘
```

**Поток данных:**
1. Клиенты делают DNS запросы на порт 53
2. Redirect правила перенаправляют их на AdGuard Home (5353)
3. AdGuard Home обрабатывает запросы и логирует их с реальными IP клиентов
4. PBR Sync Service опрашивает Query Log API AdGuard Home
5. При обнаружении доменов из PBR политик добавляет IP в nft sets
6. dnsmasq продолжает работать с форвардингом для системных запросов
7. PBR использует заполненные nft sets для маршрутизации трафика

## Результат

После установки у вас будет:
- Видимость реальных IP клиентов в AdGuard Home
- Автоматическое заполнение PBR nft sets
- Работающий PBR с доменами через VPN
- Фильтрация рекламы и трекеров через AdGuard Home

## Устранение неполадок

### Сервис не запускается
```bash
# Проверьте права доступа
ls -la /opt/pbr-sync/
chmod +x /opt/pbr-sync/*.sh

# Проверьте Python модули
python3 -c "import requests, schedule"
```

### Ошибки авторизации
```bash
# Проверьте AdGuard Home API
curl -u admin:пароль http://127.0.0.1:8070/control/status
```

### IP не добавляются в sets
```bash
# Проверьте PBR nft sets
nft list table inet fw4 | grep pbr

# Проверьте логи
tail -20 /var/log/pbr-sync.log
```

### Redirect правила не работают
```bash
# Проверьте правила firewall
uci show firewall | grep redirect
iptables -t nat -L PREROUTING
```

## Версия

Версия 1.0 - Финальная рабочая версия
