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
- Форвардинг через dnsmasq + ECS → AdGuard Home все равно видит только 127.0.0.1
- Любое размещение AdGuard Home → либо нет статистики, либо не работает PBR с доменами

**Корневая причина:**
AdGuard Home не поддерживает корректную обработку EDNS Client Subnet (ECS) при форвардинге запросов. Даже при включении ECS в dnsmasq и AdGuard Home, реальные IP клиентов не передаются и в логах AdGuard Home всегда отображается IP хоста OpenWrt (см. [GitHub issue #1727](https://github.com/AdguardTeam/AdGuardHome/issues/1727)).

Это архитектурная проблема AdGuard Home, которая делает невозможным одновременное использование:
1. Детальной статистики по IP клиентов в AdGuard Home
2. Автоматического заполнения PBR nft sets через dnsmasq при форвардинге

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
- **Прогрев доменов через FlareSolverr** (опционально) - решает проблему пустых nft sets после перезагрузки PBR с обходом Cloudflare/капч
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

### Основные параметры

- `ADGUARD_URL` - URL веб-интерфейса AdGuard Home (по умолчанию: `http://127.0.0.1:8070`)
- `ADGUARD_USER` - имя пользователя для API
- `ADGUARD_PASS` - пароль для API
- `SYNC_INTERVAL` - интервал синхронизации в минутах (по умолчанию: `2`)

### Прогрев доменов (опционально)

- `FLARESOLVERR_ENABLED` - включить прогрев доменов через FlareSolverr (`true`/`false`, по умолчанию: `false`)
- `FLARESOLVERR_URL` - URL FlareSolverr сервиса (по умолчанию: `http://localhost:8191`)
- `FLARESOLVERR_TIMEOUT` - максимальное время ожидания ответа в мс (по умолчанию: `60000`)

После изменения параметров перезапустите сервис.

## Прогрев доменов после перезагрузки PBR

### Проблема

После ежедневной перезагрузки PBR все nftables sets очищаются. IP адреса снова попадут в sets только после реальных DNS запросов от пользователей. Это означает, что маршрутизация не работает до первого обращения к сайту.

### Решение

Автоматический прогрев доменов через **FlareSolverr** - специализированный прокси-сервис для обхода Cloudflare и других антибот защит. После перезагрузки PBR сервис открывает все домены из активных политик через FlareSolverr, что вызывает DNS запросы и заполняет nftables sets.

**Почему FlareSolverr, а не обычный браузер?**
- YouTube, Google и другие сервисы используют Cloudflare и защиту от ботов
- Обычные headless браузеры (Puppeteer, Selenium) детектируются и блокируются капчами
- FlareSolverr использует undetected-chrome для обхода антибот систем
- Специально создан для решения проблемы с Cloudflare Challenge

### Установка FlareSolverr (Docker)

На вашем роутере NanoPi R5S с 4GB RAM можно запустить FlareSolverr в Docker:

```bash
# Запуск FlareSolverr
docker run -d \
  --name flaresolverr \
  -p 8191:8191 \
  -e LOG_LEVEL=info \
  --restart unless-stopped \
  ghcr.io/flaresolverr/flaresolverr:latest
```

**Проверка работы:**
```bash
curl http://localhost:8191/v1 -H "Content-Type: application/json" \
  -d '{"cmd":"request.get","url":"https://www.google.com"}'
```

### Настройка прогрева

Отредактируйте `/opt/pbr-sync/start.sh`:

```bash
export FLARESOLVERR_ENABLED="true"
export FLARESOLVERR_URL="http://localhost:8191"
export FLARESOLVERR_TIMEOUT="60000"  # 60 секунд на загрузку страницы
```

Перезапустите сервис:

```bash
/etc/init.d/pbr-sync restart
```

### Как это работает

1. PBR перезагружается в 06:00 (очищаются nft sets)
2. Сервис обнаруживает пустые sets
3. Читает все домены из активных политик PBR
4. Для каждого домена делает запрос через FlareSolverr API
5. FlareSolverr:
   - Открывает страницу в undetected-chrome
   - Автоматически решает Cloudflare Challenge
   - Обходит капчи и антибот защиты
   - Возвращает успешный результат
6. Браузер загружает страницу → делает DNS запросы
7. AdGuard Home резолвит домены → запросы попадают в Query Log
8. Сервис извлекает IP из Query Log → добавляет в nft sets
9. Маршрутизация работает сразу после перезагрузки

**Примечание:** Если FlareSolverr не настроен (`FLARESOLVERR_ENABLED=false`), сервис работает в обычном режиме - IP добавляются по мере реальных запросов от пользователей.

### Производительность

- Прогрев ~10-20 доменов: 2-5 минут
- FlareSolverr использует ~300-500 MB RAM
- Подходит для роутеров с 4GB+ RAM
- После прогрева контейнер можно остановить: `docker stop flaresolverr`

## Альтернативные схемы развертывания

### Схема 1: AdGuard Home на порту 53

```
Клиенты → AdGuard Home (53) 
             ↑ ↓
   Query Log API ←→ PBR Sync Service → nft sets ← PBR
```

**Настройка:**
```bash
# Отключить DNS в dnsmasq (оставить только DHCP)
uci set dhcp.@dnsmasq[0].port='0'
uci commit dhcp

# В AdGuard Home настроить порт 53
# AdGuardHome.yaml: port: 53

# DHCP автоматически раздает IP роутера как DNS сервер
```

**Преимущества:**
- Максимально простая архитектура
- Полная видимость IP клиентов без redirect правил
- Высокая производительность AdGuard Home
- Локальные домены через DNS rewrites в AdGuard Home

### Схема 2: C redirect правилами

```
Клиенты → redirect (53→5353) → AdGuard Home
    ↓                               ↑ ↓
dnsmasq ← форвардинг ←──────────────┘ │
    ↓                                 │
nft sets ← PBR                        │
    ↑                                 │
PBR Sync Service ←── Query Log API ───┘
```

**Когда использовать:**
- Нужна интеграция с существующими dnsmasq настройками
- Требуется сохранить форвардинг для системных запросов
- Сложная конфигурация локальных доменов в dnsmasq

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
