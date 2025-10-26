#!/usr/bin/env python3
"""
PBR-AdGuard Home синхронизация
Мониторит AdGuard Home Query Log и обновляет nftables sets для PBR
"""

import os
import sys
import time
import json
import logging
import requests
import subprocess
import re
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Set
import schedule
from pathlib import Path

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/pbr-sync.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class PBRConfig:
    """Парсер конфигурации PBR из UCI"""
    
    def __init__(self, config_path="/etc/config/pbr"):
        self.config_path = config_path
        self.policies = {}
        self.load_config()
    
    def load_config(self):
        """Загружает конфигурацию PBR из UCI"""
        try:
            result = subprocess.run(
                ["uci", "show", "pbr"],
                capture_output=True,
                text=True,
                check=True
            )
            
            self.policies = {}
            current_policy = None
            
            for line in result.stdout.strip().split('\n'):
                if '=policy' in line:
                    # Новая политика
                    policy_id = re.search(r'pbr\.@policy\[(\d+)\]', line)
                    if policy_id:
                        current_policy = policy_id.group(1)
                        self.policies[current_policy] = {
                            'name': '',
                            'interface': '',
                            'domains': [],
                            'enabled': True  # По умолчанию политика активна
                        }
                
                elif current_policy and 'name=' in line:
                    name = line.split('name=')[1].strip("'\"")
                    self.policies[current_policy]['name'] = name
                
                elif current_policy and 'interface=' in line:
                    interface = line.split('interface=')[1].strip("'\"")
                    self.policies[current_policy]['interface'] = interface
                
                elif current_policy and 'dest_addr=' in line:
                    dest_addr = line.split('dest_addr=')[1].strip("'\"")
                    # Разбиваем домены по пробелам
                    domains = [d.strip() for d in dest_addr.split() if self.is_domain(d)]
                    self.policies[current_policy]['domains'] = domains

                elif current_policy and 'enabled=' in line:
                    enabled = line.split('enabled=')[1].strip("'\"")
                    # enabled может быть '1' или '0'
                    self.policies[current_policy]['enabled'] = enabled == '1'

            enabled_count = sum(1 for p in self.policies.values() if p['enabled'])
            logger.info(f"Загружено {len(self.policies)} PBR политик ({enabled_count} активных)")
            for policy_id, policy in self.policies.items():
                status = "✓" if policy['enabled'] else "✗"
                logger.info(f"  [{status}] {policy['name']}: {len(policy['domains'])} доменов -> {policy['interface']}")
        
        except Exception as e:
            logger.error(f"Ошибка загрузки PBR конфигурации: {e}")
    
    def is_domain(self, text: str) -> bool:
        """Проверяет является ли строка доменным именем"""
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(domain_pattern, text)) and '.' in text
    
    def get_all_domains(self) -> Dict[str, str]:
        """Возвращает словарь домен -> интерфейс для всех активных политик"""
        domain_map = {}
        for policy in self.policies.values():
            # Учитываем только активные (enabled) политики
            if policy['enabled']:
                for domain in policy['domains']:
                    domain_map[domain] = policy['interface']
        return domain_map

    def get_name_to_interface_map(self) -> Dict[str, str]:
        """Возвращает словарь имя политики -> интерфейс для всех активных политик"""
        name_map = {}
        for policy in self.policies.values():
            # Учитываем только активные (enabled) политики
            if policy['enabled'] and policy['name']:
                name_map[policy['name'].lower()] = policy['interface']
        return name_map

class AdGuardHomeAPI:
    """Клиент для работы с AdGuard Home API"""
    
    def __init__(self, base_url: str, username: str = None, password: str = None):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        
        if username and password:
            self.login(username, password)
    
    def login(self, username: str, password: str):
        """Авторизация в AdGuard Home"""
        try:
            response = self.session.post(
                f"{self.base_url}/control/login",
                json={"name": username, "password": password},
                timeout=10
            )
            response.raise_for_status()
            logger.info("Успешная авторизация в AdGuard Home")
        except Exception as e:
            logger.error(f"Ошибка авторизации в AdGuard Home: {e}")
            raise
    
    def get_query_log(self, search_domain: str = None, limit: int = 100) -> List[Dict]:
        """Получает лог запросов из AdGuard Home"""
        try:
            params = {"limit": limit}
            if search_domain:
                params["search"] = search_domain
            
            response = self.session.get(
                f"{self.base_url}/control/querylog",
                params=params,
                timeout=10
            )
            response.raise_for_status()
            
            data = response.json()
            return data.get('data', [])
        
        except Exception as e:
            logger.error(f"Ошибка получения query log: {e}")
            return []

class NFTablesManager:
    """Управление nftables sets"""

    def __init__(self, pbr_config: PBRConfig):
        self.pbr_config = pbr_config
        self.nft_sets = {}
        self.discover_sets()
    
    def discover_sets(self):
        """Обнаруживает существующие PBR nft sets"""
        try:
            result = subprocess.run(
                ["nft", "list", "table", "inet", "fw4"],
                capture_output=True,
                text=True,
                check=True
            )

            # Получаем маппинг name -> interface из PBR конфигурации (только для активных политик)
            name_to_interface = self.pbr_config.get_name_to_interface_map()

            current_set = None
            for line in result.stdout.split('\n'):
                line = line.strip()

                # Ищем PBR sets
                if 'set pbr_' in line and '{' in line:
                    set_name = re.search(r'set (pbr_\w+)', line)
                    if set_name:
                        current_set = set_name.group(1)
                        self.nft_sets[current_set] = {
                            'interface': None,  # Будет определен по комментарию
                            'elements': set()
                        }

                # Ищем комментарий с именем политики (в отдельной строке)
                elif current_set and 'comment' in line:
                    comment_match = re.search(r'comment "(\w+)"', line)
                    if comment_match:
                        comment = comment_match.group(1)
                        # Определяем интерфейс по комментарию из PBR конфигурации
                        # Если комментарий соответствует имени активной политики - используем её интерфейс
                        # Иначе используем комментарий как имя интерфейса напрямую
                        interface = name_to_interface.get(comment.lower(), comment)
                        self.nft_sets[current_set]['interface'] = interface
                
                # Ищем элементы sets
                elif current_set and 'elements = {' in line:
                    elements_text = line.split('elements = {')[1]
                    if '}' in elements_text:
                        elements_text = elements_text.split('}')[0]
                    
                    # Парсим IP адреса (только одиночные IP, игнорируем диапазоны)
                    ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
                    ips = re.findall(ip_pattern, elements_text)
                    self.nft_sets[current_set]['elements'].update(ips)
                    current_set = None
            
            logger.info(f"Обнаружено {len(self.nft_sets)} PBR nft sets")
            for set_name, info in self.nft_sets.items():
                logger.info(f"  {set_name}: {len(info['elements'])} элементов -> {info['interface']}")
        
        except Exception as e:
            logger.error(f"Ошибка обнаружения nft sets: {e}")
            import traceback
            logger.error(traceback.format_exc())
    
    def add_ip_to_set(self, set_name: str, ip_address: str) -> bool:
        """Добавляет IP адрес в nft set"""
        try:
            # Проверяем что IP еще не добавлен
            if set_name in self.nft_sets:
                if ip_address in self.nft_sets[set_name]['elements']:
                    return True  # Уже есть
            
            # Добавляем IP в set
            result = subprocess.run(
                ["nft", "add", "element", "inet", "fw4", set_name, f"{{ {ip_address} }}"],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                if set_name not in self.nft_sets:
                    self.nft_sets[set_name] = {'elements': set()}
                self.nft_sets[set_name]['elements'].add(ip_address)
                logger.info(f"Добавлен IP {ip_address} в set {set_name}")
                return True
            else:
                logger.error(f"Ошибка добавления IP {ip_address} в set {set_name}: {result.stderr}")
                return False
        
        except Exception as e:
            logger.error(f"Ошибка добавления IP {ip_address} в set {set_name}: {e}")
            return False
    
    def find_set_for_interface(self, interface: str) -> str:
        """Находит nft set для указанного интерфейса"""
        for set_name, info in self.nft_sets.items():
            if info.get('interface') == interface:
                return set_name
        return None

class PBRSyncService:
    """Основной сервис синхронизации"""
    
    def __init__(self):
        self.pbr_config = PBRConfig()
        self.adguard = AdGuardHomeAPI(
            os.getenv('ADGUARD_URL', 'http://127.0.0.1:8070'),
            os.getenv('ADGUARD_USER'),
            os.getenv('ADGUARD_PASS')
        )
        self.nft_manager = NFTablesManager(self.pbr_config)
        self.processed_queries = set()
        # Устанавливаем last_check с timezone
        self.last_check = datetime.now(timezone.utc) - timedelta(minutes=5)
        self.sync_interval = int(os.getenv('SYNC_INTERVAL', 2))

        # Настройки FlareSolverr для прогрева доменов
        self.flaresolverr_enabled = os.getenv('FLARESOLVERR_ENABLED', 'false').lower() == 'true'
        self.flaresolverr_url = os.getenv('FLARESOLVERR_URL', 'http://localhost:8191')
        self.flaresolverr_timeout = int(os.getenv('FLARESOLVERR_TIMEOUT', 60000))
    
    def parse_query_time(self, time_str: str) -> datetime:
        """Парсит время из AdGuard Home с правильной обработкой timezone"""
        try:
            # AdGuard Home возвращает время в формате ISO с Z
            if time_str.endswith('Z'):
                time_str = time_str[:-1] + '+00:00'
            
            # Парсим время и убеждаемся что у него есть timezone
            dt = datetime.fromisoformat(time_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            
            return dt
        except Exception as e:
            logger.error(f"Ошибка парсинга времени '{time_str}': {e}")
            return datetime.now(timezone.utc)
    
    def sync_domains(self):
        """Основной цикл синхронизации доменов"""
        logger.info("Начинаем синхронизацию доменов...")
        
        domain_map = self.pbr_config.get_all_domains()
        
        if not domain_map:
            logger.warning("Нет доменов для мониторинга в PBR конфигурации")
            return
        
        added_count = 0
        
        # Для каждого домена из PBR конфигурации
        for domain, interface in domain_map.items():
            try:
                # Получаем recent query log для этого домена
                queries = self.adguard.get_query_log(search_domain=domain, limit=50)
                
                for query in queries:
                    query_time = self.parse_query_time(query.get('time', ''))
                    
                    # Обрабатываем только новые запросы
                    if query_time <= self.last_check:
                        continue
                    
                    query_id = f"{query.get('time')}_{query.get('name')}_{query.get('client')}"
                    if query_id in self.processed_queries:
                        continue
                    
                    self.processed_queries.add(query_id)
                    
                    # Извлекаем IP адреса из ответа
                    answer = query.get('answer', [])
                    for ans in answer:
                        if ans.get('type') == 'A' and ans.get('value'):
                            ip_address = ans['value']
                            
                            # Фильтруем недопустимые IP адреса
                            if ip_address == '0.0.0.0' or ip_address.startswith('127.'):
                                continue
                            
                            # Находим соответствующий nft set
                            nft_set = self.nft_manager.find_set_for_interface(interface)
                            if nft_set:
                                if self.nft_manager.add_ip_to_set(nft_set, ip_address):
                                    added_count += 1
                                    logger.info(f"Синхронизирован {domain} -> {ip_address} в {nft_set}")
            
            except Exception as e:
                logger.error(f"Ошибка обработки домена {domain}: {e}")
        
        # Обновляем время последней проверки с timezone
        self.last_check = datetime.now(timezone.utc)
        
        if added_count > 0:
            logger.info(f"Синхронизация завершена. Добавлено {added_count} IP адресов")
        
        # Очищаем старые processed_queries (оставляем только за последний час)
        if len(self.processed_queries) > 1000:
            self.processed_queries.clear()
    
    def reload_pbr_config(self):
        """Перезагружает конфигурацию PBR"""
        logger.info("Перезагрузка PBR конфигурации...")
        self.pbr_config.load_config()
        self.nft_manager.discover_sets()

    def warmup_domains(self):
        """Прогревает домены после перезагрузки PBR через FlareSolverr"""
        if not self.flaresolverr_enabled:
            logger.info("Прогрев доменов отключен (FLARESOLVERR_ENABLED=false)")
            return

        logger.info("Начинаем прогрев доменов через FlareSolverr (обход Cloudflare/капч)...")

        # Берем ВСЕ домены из всех активных политик
        domains = set()
        for policy in self.pbr_config.policies.values():
            if policy['enabled']:
                domains.update(policy['domains'])

        if not domains:
            logger.warning("Нет доменов для прогрева")
            return

        logger.info(f"Будет прогрето {len(domains)} доменов")

        success_count = 0
        error_count = 0

        for domain in domains:
            try:
                logger.info(f"Прогрев {domain}...")
                response = requests.post(
                    f'{self.flaresolverr_url}/v1',
                    json={
                        'cmd': 'request.get',
                        'url': f'https://{domain}',
                        'maxTimeout': self.flaresolverr_timeout
                    },
                    timeout=120
                )
                response.raise_for_status()

                result = response.json()
                if result.get('status') == 'ok':
                    success_count += 1
                    logger.info(f"✓ {domain} прогрет успешно")
                else:
                    error_count += 1
                    error_msg = result.get('message', 'Unknown error')
                    logger.error(f"✗ FlareSolverr ошибка для {domain}: {error_msg}")
            except Exception as e:
                error_count += 1
                logger.error(f"✗ Ошибка прогрева {domain}: {e}")

        logger.info(f"Прогрев завершен: {success_count} успешно, {error_count} ошибок")

    def restart_pbr_service(self):
        """Перезапускает PBR сервис (ежедневная очистка)"""
        logger.info("Перезапуск PBR сервиса для очистки правил...")
        try:
            subprocess.run(["/etc/init.d/pbr", "restart"], check=True)
            time.sleep(10)  # Ждем перезапуска
            self.nft_manager.discover_sets()
            logger.info("PBR сервис успешно перезапущен")

            # Прогреваем домены после перезагрузки
            self.warmup_domains()
        except Exception as e:
            logger.error(f"Ошибка перезапуска PBR: {e}")
    
    def run(self):
        """Запуск сервиса"""
        logger.info(f"Запуск PBR-AdGuard синхронизации с интервалом {self.sync_interval} минут...")
        
        # Планируем задачи с настраиваемым интервалом
        schedule.every(self.sync_interval).minutes.do(self.sync_domains)
        schedule.every(1).hours.do(self.reload_pbr_config)
        schedule.every().day.at("06:00").do(self.restart_pbr_service)
        
        # Первоначальная синхронизация
        self.sync_domains()
        
        # Основной цикл
        try:
            while True:
                schedule.run_pending()
                time.sleep(30)
        except KeyboardInterrupt:
            logger.info("Получен сигнал завершения")
        except Exception as e:
            logger.error(f"Критическая ошибка: {e}")
            sys.exit(1)

if __name__ == "__main__":
    service = PBRSyncService()
    service.run()
