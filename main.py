#!/usr/bin/env python3
"""
Privoxy Log Analyzer

Проект для анализа лог файла прокси сервера Privoxy.
Анализирует количество и частоту запросов к указанному домену.
"""

import re
import json
import argparse
import os
from datetime import datetime, date, timedelta
from collections import defaultdict, Counter
from typing import Dict, Tuple, List
import paramiko
from pathlib import Path
import csv


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
                 target_domain: str = "example.com",
                 upload_host: str = None, upload_user: str = None, upload_path: str = None,
                 month_start_day: int = 27):
        self.ssh_host = ssh_host
        self.ssh_user = ssh_user
        self.log_path = log_path
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        self.target_domain = target_domain
        self.month_start_day = month_start_day
        
        # Параметры для загрузки отчета
        self.upload_host = upload_host
        self.upload_user = upload_user
        self.upload_path = upload_path
        
        # Регулярное выражение для парсинга строк лога (с экранированием точек в домене)
        escaped_domain = target_domain.replace('.', '\\.')
        self.log_pattern = re.compile(
            rf'(\d{{4}}-\d{{2}}-\d{{2}} \d{{2}}:\d{{2}}:\d{{2}}\.\d{{3}}) \w+ Request: ({escaped_domain}:\d+/)'
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
    
    def analyze_sessions(self, daily_stats: Dict) -> Dict:
        """Анализ 5-часовых сессий"""
        # Создаем список всех временных точек с данными
        time_points = []
        
        for day, stats in daily_stats.items():
            day_date = datetime.strptime(day, "%Y-%m-%d").date()
            for hour, count in stats['hourly'].items():
                if count > 0:
                    dt = datetime.combine(day_date, datetime.min.time()) + timedelta(hours=int(hour))
                    time_points.append((dt, day, int(hour), count))
        
        # Сортируем по времени
        time_points.sort()
        
        if not time_points:
            return daily_stats
        
        # Инициализируем session_num = 0 для всех часов
        for day, stats in daily_stats.items():
            stats['sessions'] = {}
            for hour in range(24):
                stats['sessions'][hour] = 0
        
        # Анализируем сессии
        session_num = 1
        i = 0
        
        while i < len(time_points):
            # Начинаем новую сессию
            session_start = time_points[i][0]
            session_end = session_start + timedelta(hours=5)
            
            # Отмечаем все активные часы в текущем 5-часовом окне
            j = i
            while j < len(time_points) and time_points[j][0] < session_end:
                dt, day, hour, count = time_points[j]
                daily_stats[day]['sessions'][hour] = session_num
                j += 1
            
            # Проверяем есть ли активность после текущей сессии
            has_next_activity = j < len(time_points)
            
            # Переходим к следующей активной точке
            if has_next_activity:
                session_num += 1
                i = j
            else:
                break
        
        return daily_stats
    
    def load_all_data_with_sessions(self) -> Dict:
        """Загрузка всех данных из JSON файлов и анализ сессий"""
        daily_stats = {}
        
        # Читаем все JSON файлы
        json_files = sorted(self.data_dir.glob("*.json"))
        for json_file in json_files:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                day = data['date']
                daily_stats[day] = {
                    'requests': data['total_requests'],
                    'hourly': data['hourly_distribution']
                }
        
        # Анализируем сессии
        daily_stats = self.analyze_sessions(daily_stats)
        return daily_stats
    
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
        report.append(f"# Отчет по запросам к {self.target_domain}\n")
        
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
    
    def generate_csv_report(self) -> str:
        """Генерация CSV отчета с данными date, time, queries, session_num"""
        csv_rows = []
        csv_rows.append(['date', 'time', 'queries', 'session_num'])
        
        # Загружаем все данные с анализом сессий
        daily_stats = self.load_all_data_with_sessions()
        
        # Сортируем дни по дате
        for day in sorted(daily_stats.keys()):
            stats = daily_stats[day]
            hourly = stats['hourly']
            sessions = stats['sessions']
                
            # Добавляем все 24 часа для каждого дня
            for hour in range(24):
                time_str = f"{hour:02d}:00"
                queries = hourly.get(str(hour), 0)
                session_num = sessions.get(hour, 0)
                
                csv_rows.append([day, time_str, queries, session_num])
        
        return csv_rows
    
    def generate_html_report(self) -> str:
        """Генерация HTML отчета в табличном формате"""
        html_lines = []
        html_lines.append("<!DOCTYPE html>")
        html_lines.append("<html lang='ru'>")
        html_lines.append("<head>")
        html_lines.append("    <meta charset='UTF-8'>")
        html_lines.append("    <meta name='viewport' content='width=device-width, initial-scale=1.0'>")
        html_lines.append("    <title>Privoxy Log Report</title>")
        html_lines.append("    <style>")
        html_lines.append("        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }")
        html_lines.append("        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }")
        html_lines.append("        h1 { color: #333; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; text-align: center; }")
        html_lines.append("        .stats-summary { background: #f9f9f9; padding: 15px; border-radius: 5px; margin: 20px 0; }")
        html_lines.append("        .stats-summary h2 { margin-top: 0; color: #4CAF50; }")
        html_lines.append("        table { width: 100%; border-collapse: collapse; margin: 20px 0; }")
        html_lines.append("        th, td { padding: 8px 12px; text-align: left; border: 1px solid #ddd; }")
        html_lines.append("        th { background-color: #4CAF50; color: white; font-weight: bold; }")
        html_lines.append("        tr:nth-child(even) { background-color: #f9f9f9; }")
        html_lines.append("        .session-active { background-color: #e8f5e8 !important; }")
        html_lines.append("        .session-rest { background-color: #fff !important; }")
        html_lines.append("        .timestamp { color: #888; font-size: 0.9em; float: right; }")
        html_lines.append("        .date-header { background-color: #2196F3 !important; color: white; font-weight: bold; }")
        html_lines.append("        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin: 20px 0; }")
        html_lines.append("        .stat-card { background: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #4CAF50; }")
        html_lines.append("    </style>")
        html_lines.append("    <script>")
        html_lines.append("        setTimeout(function() { location.reload(); }, 15 * 60 * 1000);")
        html_lines.append("    </script>")
        html_lines.append("</head>")
        html_lines.append("<body>")
        html_lines.append("    <div class='container'>")
        
        # Временная метка обновления
        update_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        html_lines.append(f"        <div class='timestamp'>Обновлено: {update_time}</div>")
        html_lines.append(f"        <h1>Отчет по запросам к {self.target_domain}</h1>")
        
        # Загружаем все данные с анализом сессий
        daily_stats = self.load_all_data_with_sessions()
        total_requests = 0
        all_hourly = Counter()
        session_stats = []
        
        for day, stats in daily_stats.items():
            total_requests += stats['requests']
            hourly = stats['hourly']
            for hour, count in hourly.items():
                all_hourly[int(hour)] += count
            
            # Подсчет сессий
            sessions = stats['sessions']
            day_sessions = set()
            for hour, session_num in sessions.items():
                if session_num > 0:
                    day_sessions.add(session_num)
            session_stats.append(len(day_sessions))
        
        json_files = list(self.data_dir.glob("*.json"))
        
        # Общая статистика
        html_lines.append("        <div class='stats-summary'>")
        html_lines.append("            <h2>Общая статистика</h2>")
        html_lines.append("            <div class='stats-grid'>")
        html_lines.append(f"                <div class='stat-card'>Всего запросов: <strong>{total_requests}</strong></div>")
        html_lines.append(f"                <div class='stat-card'>Проанализировано дней: <strong>{len(json_files)}</strong></div>")
        
        if all_hourly:
            peak_hour = all_hourly.most_common(1)[0]
            html_lines.append(f"                <div class='stat-card'>Пиковый час: <strong>{peak_hour[0]:02d}:00 ({peak_hour[1]} запросов)</strong></div>")
        
        if session_stats:
            max_sessions = max(session_stats) if session_stats else 0
            avg_sessions = sum(session_stats) / len(session_stats) if session_stats else 0
            html_lines.append(f"                <div class='stat-card'>Макс. сессий в день: <strong>{max_sessions}</strong></div>")
            html_lines.append(f"                <div class='stat-card'>Среднее сессий в день: <strong>{avg_sessions:.1f}</strong></div>")
            
            # Подсчет сессий за последний месяц
            today = datetime.now().date()
            # Определяем начало текущего месяца
            if today.day >= self.month_start_day:
                month_start = today.replace(day=self.month_start_day)
            else:
                # Если сегодня до начала месяца, то берем предыдущий месяц
                if today.month == 1:
                    month_start = today.replace(year=today.year-1, month=12, day=self.month_start_day)
                else:
                    month_start = today.replace(month=today.month-1, day=self.month_start_day)
            
            # Подсчитываем уникальные сессии за последний месяц
            month_sessions_set = set()
            for day, stats in daily_stats.items():
                day_date = datetime.strptime(day, '%Y-%m-%d').date()
                if day_date >= month_start:
                    sessions = stats['sessions']
                    for hour, session_num in sessions.items():
                        if session_num > 0:
                            month_sessions_set.add(session_num)
            month_sessions = len(month_sessions_set)
            
            html_lines.append(f"                <div class='stat-card'>Сессий за последний месяц: <strong>{month_sessions}</strong></div>")
        
        html_lines.append("            </div>")
        html_lines.append("        </div>")
        
        # Таблица с данными
        html_lines.append("        <table>")
        html_lines.append("            <thead>")
        html_lines.append("                <tr>")
        html_lines.append("                    <th>Дата</th>")
        html_lines.append("                    <th>Время</th>")
        html_lines.append("                    <th>Запросы</th>")
        html_lines.append("                    <th>Сессия №</th>")
        html_lines.append("                </tr>")
        html_lines.append("            </thead>")
        html_lines.append("            <tbody>")
        
        # Генерируем данные таблицы (свежие данные сверху)
        csv_data = self.generate_csv_report()
        
        # Разбиваем данные по дням и переворачиваем порядок
        days_data = {}
        for row in csv_data[1:]:  # Пропускаем заголовок
            date, time, queries, session_num = row
            if date not in days_data:
                days_data[date] = []
            days_data[date].append((date, time, queries, session_num))
        
        # Сортируем дни в обратном порядке (свежие сверху)
        sorted_days = sorted(days_data.keys(), reverse=True)
        
        for day in sorted_days:
            # Вычисляем статистику для дня
            day_data = days_data[day]
            day_requests = sum(int(row[2]) for row in day_data)
            day_sessions = set()
            for row in day_data:
                if int(row[3]) > 0:
                    day_sessions.add(int(row[3]))
            day_session_count = len(day_sessions)
            
            # Добавляем заголовок дня со статистикой
            html_lines.append(f"                <tr class='date-header'>")
            html_lines.append(f"                    <td colspan='4'>── {day} ── Запросов: {day_requests}, Сессий: {day_session_count} ──</td>")
            html_lines.append("                </tr>")
            
            # Добавляем строки для каждого часа дня (в обратном порядке 23:00-00:00)
            for row in reversed(day_data):
                date, time, queries, session_num = row
                
                # Определяем CSS класс для строки
                css_class = "session-active" if int(session_num) > 0 else "session-rest"
                
                html_lines.append(f"                <tr class='{css_class}'>")
                html_lines.append(f"                    <td>{date}</td>")
                html_lines.append(f"                    <td>{time}</td>")
                html_lines.append(f"                    <td>{queries}</td>")
                html_lines.append(f"                    <td>{session_num if int(session_num) > 0 else '-'}</td>")
                html_lines.append("                </tr>")
        
        html_lines.append("            </tbody>")
        html_lines.append("        </table>")
        html_lines.append("    </div>")
        html_lines.append("</body>")
        html_lines.append("</html>")
        
        return "\n".join(html_lines)
    
    def upload_report(self, report_file: Path, csv_file: Path = None):
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
            
            # Генерируем HTML отчет
            html_content = self.generate_html_report()
            
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
            
            # Загружаем HTML как index.html
            index_path = f"{upload_path_abs}/index.html"
            try:
                sftp.put(str(html_file), index_path)
                print(f"HTML отчет успешно загружен как: {index_path}")
            except Exception as e:
                print(f"Ошибка: Не удалось загрузить HTML файл через SFTP: {e}")
                return
            
            # Загружаем CSV файл если он указан
            if csv_file and csv_file.exists():
                csv_path = f"{upload_path_abs}/report.csv"
                try:
                    sftp.put(str(csv_file), csv_path)
                    print(f"CSV отчет успешно загружен как: {csv_path}")
                except Exception as e:
                    print(f"Ошибка: Не удалось загрузить CSV файл через SFTP: {e}")
            
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
        
        # Сохранение Markdown отчета
        report_file = self.data_dir / "report.md"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report)
        
        print(f"Markdown отчет сохранен в {report_file}")
        
        # Генерация и сохранение CSV отчета
        print("Генерация CSV отчета...")
        csv_data = self.generate_csv_report()
        csv_file = self.data_dir / "report.csv"
        
        with open(csv_file, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            writer.writerows(csv_data)
        
        print(f"CSV отчет сохранен в {csv_file}")
        
        # Загрузка отчета на сервер (если запрошено)
        if upload_report:
            self.upload_report(report_file, csv_file)
        
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
    parser.add_argument('--target-domain', default=env_vars.get('PRIVOXY_TARGET_DOMAIN', 'example.com'), 
                       help='Целевой домен для анализа')
    parser.add_argument('--month-start-day', type=int, default=int(env_vars.get('PRIVOXY_MONTH_START_DAY', '27')), 
                       help='День начала месяца для статистики')
    
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
        target_domain=args.target_domain,
        upload_host=upload_host,
        upload_user=upload_user,
        upload_path=upload_path,
        month_start_day=args.month_start_day
    )
    
    try:
        analyzer.run_analysis(upload_report=args.upload)
        # Подсчитываем количество JSON файлов для краткой статистики
        json_files = list(analyzer.data_dir.glob("*.json"))
        print(f"Анализ завершен. Обработано дней: {len(json_files)}")
        print("Отчет сохранен в data/report.md")
        if args.upload:
            print("Отчет загружен на веб-сервер")
    except Exception as e:
        print(f"Ошибка: {e}")


if __name__ == "__main__":
    main()