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
                            'domains': []
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
            
            logger.info(f"Загружено {len(self.policies)} PBR политик")
            for policy_id, policy in self.policies.items():
                logger.info(f"  {policy['name']}: {len(policy['domains'])} доменов -> {policy['interface']}")
        
        except Exception as e:
            logger.error(f"Ошибка загрузки PBR конфигурации: {e}")
    
    def is_domain(self, text: str) -> bool:
        """Проверяет является ли строка доменным именем"""
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(domain_pattern, text)) and '.' in text
    
    def get_all_domains(self) -> Dict[str, str]:
        """Возвращает словарь домен -> интерфейс для всех политик"""
        domain_map = {}
        for policy in self.policies.values():
            for domain in policy['domains']:
                domain_map[domain] = policy['interface']
        return domain_map

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
    
    def __init__(self):
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
            
            current_set = None
            for line in result.stdout.split('\n'):
                line = line.strip()
                
                # Ищем PBR sets
                if 'set pbr_' in line and '{' in line:
                    set_name = re.search(r'set (pbr_\w+)', line)
                    if set_name:
                        current_set = set_name.group(1)
                        self.nft_sets[current_set] = {
                            'interface': 'awgmd',  # По умолчанию awgmd для всех PBR sets
                            'elements': set()
                        }
                
                # Ищем комментарий с именем интерфейса (в отдельной строке)
                elif current_set and 'comment' in line:
                    comment_match = re.search(r'comment "(\w+)"', line)
                    if comment_match:
                        comment = comment_match.group(1)
                        # Определяем интерфейс по комментарию
                        if comment in ['youtube', 'ai', 'p']:
                            self.nft_sets[current_set]['interface'] = 'awgmd'
                        else:
                            self.nft_sets[current_set]['interface'] = comment
                
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
        self.nft_manager = NFTablesManager()
        self.processed_queries = set()
        # Устанавливаем last_check с timezone
        self.last_check = datetime.now(timezone.utc) - timedelta(minutes=5)
        self.sync_interval = int(os.getenv('SYNC_INTERVAL', 2))
    
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
    
    def restart_pbr_service(self):
        """Перезапускает PBR сервис (ежедневная очистка)"""
        logger.info("Перезапуск PBR сервиса для очистки правил...")
        try:
            subprocess.run(["/etc/init.d/pbr", "restart"], check=True)
            time.sleep(10)  # Ждем перезапуска
            self.nft_manager.discover_sets()
            logger.info("PBR сервис успешно перезапущен")
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
