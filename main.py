#!/usr/bin/env python3
"""
Privoxy Log Analyzer

Проект для анализа лог файла прокси сервера Privoxy.
Анализирует количество и частоту запросов к anthropic.com.
"""

import re
import json
import argparse
import os
from datetime import datetime, date
from collections import defaultdict, Counter
from typing import Dict, Tuple
import paramiko
from pathlib import Path


def load_env_file(env_file_path: str = ".env") -> Dict[str, str]:
    """Загрузка переменных из .env файла"""
    env_vars = {}
    env_path = Path(env_file_path)
    
    if env_path.exists():
        try:
            with open(env_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    # Пропускаем пустые строки и комментарии
                    if line and not line.startswith('#'):
                        if '=' in line:
                            key, value = line.split('=', 1)
                            key = key.strip()
                            value = value.strip()
                            # Убираем кавычки если есть
                            if value.startswith('"') and value.endswith('"'):
                                value = value[1:-1]
                            elif value.startswith("'") and value.endswith("'"):
                                value = value[1:-1]
                            env_vars[key] = value
        except Exception as e:
            print(f"Предупреждение: Ошибка чтения .env файла: {e}")
    
    return env_vars


class PrivoxyLogAnalyzer:
    def __init__(self, ssh_host: str = "10.1.1.1", ssh_user: str = "root", 
                 log_path: str = "/var/log/privoxy.log", data_dir: str = "data",
                 upload_host: str = None, upload_user: str = None, upload_path: str = None):
        self.ssh_host = ssh_host
        self.ssh_user = ssh_user
        self.log_path = log_path
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        
        # Параметры для загрузки отчета
        self.upload_host = upload_host
        self.upload_user = upload_user
        self.upload_path = upload_path
        
        # Регулярное выражение для парсинга строк лога
        self.log_pattern = re.compile(
            r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}) \w+ Request: (api\.anthropic\.com:\d+/)'
        )
    
    def connect_ssh(self) -> paramiko.SSHClient:
        """Подключение к SSH серверу"""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(self.ssh_host, username=self.ssh_user)
        return ssh
    
    def download_log(self) -> str:
        """Скачивание лог файла с сервера"""
        ssh = self.connect_ssh()
        try:
            _, stdout, _ = ssh.exec_command(f"cat {self.log_path}")
            log_content = stdout.read().decode('utf-8')
            return log_content
        finally:
            ssh.close()
    
    def parse_log_line(self, line: str) -> Tuple[datetime, str]:
        """Парсинг одной строки лога"""
        match = self.log_pattern.match(line.strip())
        if match:
            timestamp_str, domain = match.groups()
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.%f")
            return timestamp, domain
        return None, None
    
    def analyze_log(self, log_content: str) -> Dict:
        """Анализ содержимого лога"""
        daily_stats = defaultdict(lambda: {'requests': 0, 'hourly': Counter()})
        
        for line in log_content.split('\n'):
            timestamp, domain = self.parse_log_line(line)
            if timestamp and domain:
                day_key = timestamp.date().isoformat()
                hour_key = timestamp.hour
                
                daily_stats[day_key]['requests'] += 1
                daily_stats[day_key]['hourly'][hour_key] += 1
        
        return dict(daily_stats)
    
    def save_daily_data(self, daily_stats: Dict):
        """Сохранение данных по дням"""
        today = date.today().isoformat()
        
        for day, stats in daily_stats.items():
            filename = self.data_dir / f"{day}.json"
            
            # Не перезаписываем существующие файлы, кроме сегодняшнего дня
            if filename.exists() and day != today:
                continue
            
            # Сегодняшний день перезаписываем (неполные данные)
            if day == today or not filename.exists():
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump({
                        'date': day,
                        'total_requests': stats['requests'],
                        'hourly_distribution': dict(stats['hourly'])
                    }, f, indent=2, ensure_ascii=False)
    
    def generate_report(self) -> str:
        """Генерация отчета по всем сохраненным данным"""
        report = []
        report.append("# Отчет по запросам к anthropic.com\n")
        
        total_requests = 0
        all_hourly = Counter()
        
        # Читаем все файлы с данными (новые даты вверху)
        json_files = sorted(self.data_dir.glob("*.json"), reverse=True)
        
        for json_file in json_files:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                day = data['date']
                requests = data['total_requests']
                hourly = data['hourly_distribution']
                
                total_requests += requests
                for hour, count in hourly.items():
                    all_hourly[int(hour)] += count
                
                report.append(f"## {day}")
                report.append(f"Всего запросов: {requests}")
                report.append("Распределение по часам:")
                
                for hour in range(24):
                    count = hourly.get(str(hour), 0)
                    if count > 0:
                        report.append(f"  {hour:02d}:00 - {count} запросов")
                report.append("")
        
        # Общая статистика
        report.append("## Общая статистика")
        report.append(f"Всего запросов: {total_requests}")
        report.append(f"Проанализировано дней: {len(json_files)}")
        
        if all_hourly:
            peak_hour = all_hourly.most_common(1)[0]
            report.append(f"Пиковый час: {peak_hour[0]:02d}:00 ({peak_hour[1]} запросов)")
        
        return "\n".join(report)
    
    def generate_html_report(self, report_md: str = None) -> str:
        """Генерация HTML отчета для веб-просмотра"""
        if report_md is None:
            report_md = self.generate_report()
        
        # Простое преобразование Markdown в HTML
        html_lines = []
        html_lines.append("<!DOCTYPE html>")
        html_lines.append("<html lang='ru'>")
        html_lines.append("<head>")
        html_lines.append("    <meta charset='UTF-8'>")
        html_lines.append("    <meta name='viewport' content='width=device-width, initial-scale=1.0'>")
        html_lines.append("    <title>Privoxy Log Report</title>")
        html_lines.append("    <style>")
        html_lines.append("        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }")
        html_lines.append("        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }")
        html_lines.append("        h1 { color: #333; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }")
        html_lines.append("        h2 { color: #4CAF50; margin-top: 30px; }")
        html_lines.append("        .stats { background: #f9f9f9; padding: 15px; border-radius: 5px; margin: 15px 0; }")
        html_lines.append("        .hourly { margin-left: 20px; font-family: monospace; }")
        html_lines.append("        .timestamp { color: #888; font-size: 0.9em; float: right; }")
        html_lines.append("    </style>")
        html_lines.append("    <script>")
        html_lines.append("        // Автоперезагрузка страницы каждые 15 минут")
        html_lines.append("        setTimeout(function() {")
        html_lines.append("            location.reload();")
        html_lines.append("        }, 15 * 60 * 1000); // 15 минут в миллисекундах")
        html_lines.append("    </script>")
        html_lines.append("</head>")
        html_lines.append("<body>")
        html_lines.append("    <div class='container'>")
        
        # Добавляем временную метку обновления
        update_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        html_lines.append(f"        <div class='timestamp'>Обновлено: {update_time}</div>")
        
        # Конвертируем Markdown в HTML
        for line in report_md.split('\n'):
            line = line.strip()
            if line.startswith('# '):
                html_lines.append(f"        <h1>{line[2:]}</h1>")
            elif line.startswith('## '):
                html_lines.append(f"        <h2>{line[3:]}</h2>")
            elif line.startswith('  '):
                html_lines.append(f"        <div class='hourly'>{line}</div>")
            elif line.startswith('Всего запросов:') or line.startswith('Проанализировано дней:') or line.startswith('Пиковый час:'):
                html_lines.append(f"        <div class='stats'><strong>{line}</strong></div>")
            elif line == 'Распределение по часам:':
                html_lines.append(f"        <div><strong>{line}</strong></div>")
            elif line and not line.startswith('#'):
                html_lines.append(f"        <div>{line}</div>")
            elif line == '':
                html_lines.append("        <br>")
        
        html_lines.append("    </div>")
        html_lines.append("</body>")
        html_lines.append("</html>")
        
        return "\n".join(html_lines)
    
    def upload_report(self, report_file: Path):
        """Загрузка отчета на веб-сервер"""
        if not all([self.upload_host, self.upload_user, self.upload_path]):
            print("Параметры загрузки не заданы, пропускаем")
            return
        
        # Проверяем существование файла отчета
        if not report_file.exists():
            print(f"Ошибка: Файл отчета не найден: {report_file}")
            return
        
        print(f"Загрузка отчета на {self.upload_host}...")
        
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            ssh.connect(self.upload_host, username=self.upload_user)
            
            # Создаем SFTP соединение
            sftp = ssh.open_sftp()
            
            # Преобразуем ~ в абсолютный путь
            if self.upload_path.startswith('~'):
                home_output = sftp.normalize('.')
                upload_path_abs = self.upload_path.replace('~', home_output)
            else:
                upload_path_abs = self.upload_path
            
            # Убеждаемся что директория существует
            try:
                # Создаем директории рекурсивно
                path_parts = upload_path_abs.strip('/').split('/')
                current_path = '/'
                for part in path_parts:
                    if part:
                        current_path = current_path.rstrip('/') + '/' + part
                        try:
                            sftp.mkdir(current_path)
                        except IOError:
                            pass  # Директория уже существует
            except Exception as e:
                print(f"Предупреждение: Ошибка при создании директорий: {e}")
            
            # Читаем существующий Markdown отчет и генерируем HTML
            try:
                with open(report_file, 'r', encoding='utf-8') as f:
                    report_md = f.read()
            except Exception as e:
                print(f"Ошибка: Не удалось прочитать файл отчета: {e}")
                return
            
            html_content = self.generate_html_report(report_md)
            
            # Создаем временный HTML файл
            html_file = self.data_dir / "report.html"
            try:
                with open(html_file, 'w', encoding='utf-8') as f:
                    f.write(html_content)
            except Exception as e:
                print(f"Ошибка: Не удалось сохранить HTML файл: {e}")
                return
            
            # Проверяем что HTML файл создался
            if not html_file.exists():
                print(f"Ошибка: HTML файл не был создан: {html_file}")
                return
            
            # Загружаем как index.html
            index_path = f"{upload_path_abs}/index.html"
            try:
                sftp.put(str(html_file), index_path)
            except Exception as e:
                print(f"Ошибка: Не удалось загрузить файл через SFTP: {e}")
                return
            
            print(f"Отчет успешно загружен как: {index_path}")
            
            sftp.close()
            
        except Exception as e:
            print(f"Ошибка загрузки: {e}")
        finally:
            ssh.close()
    
    def run_analysis(self, upload_report: bool = False):
        """Основной процесс анализа"""
        print("Скачивание логов...")
        log_content = self.download_log()
        
        print("Анализ логов...")
        daily_stats = self.analyze_log(log_content)
        
        print("Сохранение данных...")
        self.save_daily_data(daily_stats)
        
        print("Генерация отчета...")
        report = self.generate_report()
        
        # Сохранение отчета
        report_file = self.data_dir / "report.md"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report)
        
        print(f"Отчет сохранен в {report_file}")
        
        # Загрузка отчета на сервер (если запрошено)
        if upload_report:
            self.upload_report(report_file)
        
        return report


def main():
    # Загружаем переменные из .env файла
    env_vars = load_env_file()
    
    parser = argparse.ArgumentParser(description='Privoxy Log Analyzer')
    parser.add_argument('--host', default=env_vars.get('PRIVOXY_SSH_HOST', '192.168.1.1'), 
                       help='SSH host для скачивания логов')
    parser.add_argument('--user', default=env_vars.get('PRIVOXY_SSH_USER', 'root'), 
                       help='SSH user для скачивания логов')
    parser.add_argument('--log-path', default=env_vars.get('PRIVOXY_LOG_PATH', '/var/log/privoxy.log'), 
                       help='Путь к лог файлу на сервере')
    parser.add_argument('--data-dir', default=env_vars.get('PRIVOXY_DATA_DIR', 'data'), 
                       help='Локальная директория для данных')
    
    # Параметры для загрузки отчета
    parser.add_argument('--upload', action='store_true', help='Загрузить отчет на веб-сервер')
    parser.add_argument('--upload-host', default=env_vars.get('PRIVOXY_UPLOAD_HOST', 'your-server.com'), 
                       help='Хост для загрузки отчета')
    parser.add_argument('--upload-user', default=env_vars.get('PRIVOXY_UPLOAD_USER'), 
                       help='Пользователь для загрузки отчета')
    parser.add_argument('--upload-path', default=env_vars.get('PRIVOXY_UPLOAD_PATH', '~/public_html/reports'), 
                       help='Путь для загрузки отчета')
    
    args = parser.parse_args()
    
    # Определяем параметры загрузки
    upload_host = args.upload_host if args.upload else None
    upload_user = args.upload_user if args.upload else None
    upload_path = args.upload_path if args.upload else None
    
    analyzer = PrivoxyLogAnalyzer(
        ssh_host=args.host,
        ssh_user=args.user,
        log_path=args.log_path,
        data_dir=args.data_dir,
        upload_host=upload_host,
        upload_user=upload_user,
        upload_path=upload_path
    )
    
    try:
        report = analyzer.run_analysis(upload_report=args.upload)
        print("\n" + "="*50)
        print("ОТЧЕТ:")
        print("="*50)
        print(report)
    except Exception as e:
        print(f"Ошибка: {e}")


if __name__ == "__main__":
    main()