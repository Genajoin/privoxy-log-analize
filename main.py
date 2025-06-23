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
from datetime import datetime, date, timedelta, timezone
import zoneinfo
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
        
        # Часовой пояс логов на сервере
        self.server_timezone = zoneinfo.ZoneInfo("Europe/Ljubljana")
        
        # Параметры для загрузки отчета
        self.upload_host = upload_host
        self.upload_user = upload_user
        self.upload_path = upload_path
        
        # Регулярное выражение для парсинга строк лога (с экранированием точек в домене)
        escaped_domain = target_domain.replace('.', '\\.')
        self.log_pattern = re.compile(
            rf'(\d{{4}}-\d{{2}}-\d{{2}} \d{{2}}:\d{{2}}:\d{{2}}\.\d{{3}}) \w+ Request: ({escaped_domain}:\d+/)'
        )
    
    def convert_local_to_utc(self, local_date: date, local_hour: int) -> datetime:
        """Конвертирует локальную дату и час в UTC datetime"""
        # Создаем datetime в местном часовом поясе сервера
        local_dt = datetime.combine(local_date, datetime.min.time()) + timedelta(hours=local_hour)
        local_dt = local_dt.replace(tzinfo=self.server_timezone)
        
        # Конвертируем в UTC
        utc_dt = local_dt.astimezone(timezone.utc)
        return utc_dt
    
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
        
        # Читаем все JSON файлы, исключаем report.json
        json_files = sorted([f for f in self.data_dir.glob("*.json") if f.name != "report.json"])
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
        
        # Читаем все файлы с данными (новые даты вверху), исключаем report.json
        json_files = sorted([f for f in self.data_dir.glob("*.json") if f.name != "report.json"], reverse=True)
        
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
        """Генерация HTML отчета с динамической загрузкой через JavaScript"""
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
        html_lines.append("        .loading { text-align: center; color: #666; font-size: 18px; margin: 40px 0; }")
        html_lines.append("        .error { text-align: center; color: #d32f2f; font-size: 16px; margin: 40px 0; padding: 20px; background: #ffebee; border-radius: 5px; }")
        html_lines.append("        .stats-summary { background: #f9f9f9; padding: 15px; border-radius: 5px; margin: 20px 0; }")
        html_lines.append("        .stats-summary h2 { margin-top: 0; color: #4CAF50; }")
        html_lines.append("        table { width: 100%; border-collapse: collapse; margin: 20px 0; }")
        html_lines.append("        th, td { padding: 8px 12px; text-align: left; border: 1px solid #ddd; }")
        html_lines.append("        th { background-color: #4CAF50; color: white; font-weight: bold; }")
        html_lines.append("        tr:nth-child(even) { background-color: #f9f9f9; }")
        html_lines.append("        .session-active { background-color: #e8f5e8 !important; }")
        html_lines.append("        .session-rest { background-color: #fff !important; }")
        html_lines.append("        .predicted-next-session { background-color: #ffebee !important; border: 2px solid #f44336 !important; }")
        html_lines.append("        .timestamp { color: #888; font-size: 0.9em; float: right; }")
        html_lines.append("        .timezone-info { color: #666; font-size: 0.85em; margin-left: 10px; }")
        html_lines.append("        .date-header { background-color: #2196F3 !important; color: white; font-weight: bold; }")
        html_lines.append("        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin: 20px 0; }")
        html_lines.append("        .stat-card { background: #f0f8ff; padding: 15px; border-radius: 5px; border-left: 4px solid #4CAF50; }")
        html_lines.append("        .hidden { display: none; }")
        html_lines.append("    </style>")
        html_lines.append("</head>")
        html_lines.append("<body>")
        html_lines.append("    <div class='container'>")
        html_lines.append("        <div class='timestamp' id='updateTime'>")
        html_lines.append("            <span id='updateTimeText'>Загрузка...</span>")
        html_lines.append("            <span class='timezone-info' id='timezoneInfo'></span>")
        html_lines.append("        </div>")
        html_lines.append("        <h1 id='reportTitle'>Отчет по запросам - Загрузка...</h1>")
        html_lines.append("        ")
        html_lines.append("        <div class='loading' id='loadingIndicator'>")
        html_lines.append("            Загрузка данных...")
        html_lines.append("        </div>")
        html_lines.append("        ")
        html_lines.append("        <div class='error hidden' id='errorIndicator'>")
        html_lines.append("            Ошибка загрузки данных. Попробуйте обновить страницу.")
        html_lines.append("        </div>")
        html_lines.append("        ")
        html_lines.append("        <div class='stats-summary hidden' id='statsSummary'>")
        html_lines.append("            <h2>Общая статистика</h2>")
        html_lines.append("            <div class='stats-grid' id='statsGrid'>")
        html_lines.append("                <!-- Статистика будет загружена через JavaScript -->")
        html_lines.append("            </div>")
        html_lines.append("        </div>")
        html_lines.append("        ")
        html_lines.append("        <table class='hidden' id='dataTable'>")
        html_lines.append("            <thead>")
        html_lines.append("                <tr>")
        html_lines.append("                    <th>Дата</th>")
        html_lines.append("                    <th>Время</th>")
        html_lines.append("                    <th>Запросы</th>")
        html_lines.append("                    <th>Сессия №</th>")
        html_lines.append("                </tr>")
        html_lines.append("            </thead>")
        html_lines.append("            <tbody id='dataTableBody'>")
        html_lines.append("                <!-- Данные будут загружены через JavaScript -->")
        html_lines.append("            </tbody>")
        html_lines.append("        </table>")
        html_lines.append("    </div>")
        html_lines.append("    ")
        html_lines.append("    <script>")
        html_lines.append("        let reportData = null;")
        html_lines.append("        let userTimezone = Intl.DateTimeFormat().resolvedOptions().timeZone;")
        html_lines.append("        ")
        html_lines.append("        function formatLocalDateTime(utcIsoString) {")
        html_lines.append("            const date = new Date(utcIsoString);")
        html_lines.append("            return {")
        html_lines.append("                date: date.toLocaleDateString('ru-RU'),")
        html_lines.append("                time: date.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })")
        html_lines.append("            };")
        html_lines.append("        }")
        html_lines.append("        ")
        html_lines.append("        function showError() {")
        html_lines.append("            document.getElementById('loadingIndicator').classList.add('hidden');")
        html_lines.append("            document.getElementById('errorIndicator').classList.remove('hidden');")
        html_lines.append("        }")
        html_lines.append("        ")
        html_lines.append("        function hideLoading() {")
        html_lines.append("            document.getElementById('loadingIndicator').classList.add('hidden');")
        html_lines.append("        }")
        html_lines.append("        ")
        html_lines.append("        function renderStats(summary) {")
        html_lines.append("            const statsGrid = document.getElementById('statsGrid');")
        html_lines.append("            let statsHtml = '';")
        html_lines.append("            ")
        html_lines.append("            statsHtml += `<div class='stat-card'>Всего запросов: <strong>${summary.total_requests}</strong></div>`;")
        html_lines.append("            statsHtml += `<div class='stat-card'>Проанализировано дней: <strong>${summary.total_days}</strong></div>`;")
        html_lines.append("            ")
        html_lines.append("            if (summary.peak_hour !== null) {")
        html_lines.append("                statsHtml += `<div class='stat-card'>Пиковый час: <strong>${summary.peak_hour.toString().padStart(2, '0')}:00 (${summary.peak_hour_count} запросов)</strong></div>`;")
        html_lines.append("            }")
        html_lines.append("            ")
        html_lines.append("            if (summary.max_sessions_per_day > 0) {")
        html_lines.append("                statsHtml += `<div class='stat-card'>Макс. сессий в день: <strong>${summary.max_sessions_per_day}</strong></div>`;")
        html_lines.append("                statsHtml += `<div class='stat-card'>Среднее сессий в день: <strong>${summary.avg_sessions_per_day}</strong></div>`;")
        html_lines.append("                statsHtml += `<div class='stat-card'>Сессий за последний месяц: <strong>${summary.sessions_this_month}</strong></div>`;")
        html_lines.append("            }")
        html_lines.append("            ")
        html_lines.append("            statsGrid.innerHTML = statsHtml;")
        html_lines.append("            document.getElementById('statsSummary').classList.remove('hidden');")
        html_lines.append("        }")
        html_lines.append("        ")
        html_lines.append("        function renderTable(tableData, predictedNextSession) {")
        html_lines.append("            const tbody = document.getElementById('dataTableBody');")
        html_lines.append("            let tableHtml = '';")
        html_lines.append("            ")
        html_lines.append("            // Группируем данные по дням")  
        html_lines.append("            const dayGroups = {};")
        html_lines.append("            const dayStats = {};")
        html_lines.append("            ")
        html_lines.append("            tableData.forEach(row => {")
        html_lines.append("                if (!dayGroups[row.date]) {")
        html_lines.append("                    dayGroups[row.date] = [];")
        html_lines.append("                    dayStats[row.date] = { requests: 0, sessions: new Set() };")
        html_lines.append("                }")
        html_lines.append("                dayGroups[row.date].push(row);")
        html_lines.append("                dayStats[row.date].requests += row.queries;")
        html_lines.append("                if (row.session_num > 0) {")
        html_lines.append("                    dayStats[row.date].sessions.add(row.session_num);")
        html_lines.append("                }")
        html_lines.append("            });")
        html_lines.append("            ")
        html_lines.append("            // Сортируемые дни (новые сверху)")
        html_lines.append("            const sortedDays = Object.keys(dayGroups).sort().reverse();")
        html_lines.append("            ")
        html_lines.append("            // Если есть прогноз на следующий день - добавляем его первым")
        html_lines.append("            if (predictedNextSession && sortedDays.length > 0) {")
        html_lines.append("                const latestDay = sortedDays[0];")
        html_lines.append("                const predictedDate = predictedNextSession.date;")
        html_lines.append("                ")
        html_lines.append("                if (predictedDate !== latestDay) {")
        html_lines.append("                    // Прогноз на следующий день")
        html_lines.append("                    for (let h = predictedNextSession.hour; h >= 0; h--) {")
        html_lines.append("                        const hourUtc = predictedDate + 'T' + h.toString().padStart(2, '0') + ':00:00Z';")
        html_lines.append("                        const localTime = formatLocalDateTime(hourUtc);")
        html_lines.append("                        ")
        html_lines.append("                        let cssClass = 'session-rest';")
        html_lines.append("                        let sessionDisplay = '-';")
        html_lines.append("                        ")
        html_lines.append("                        if (h === predictedNextSession.hour) {")
        html_lines.append("                            cssClass = 'predicted-next-session';")
        html_lines.append("                            sessionDisplay = 'ПРОГНОЗ: Следующая сессия';")
        html_lines.append("                        }")
        html_lines.append("                        ")
        html_lines.append("                        tableHtml += `<tr class='${cssClass}'>`;")
        html_lines.append("                        tableHtml += `<td>${localTime.date}</td>`;")
        html_lines.append("                        tableHtml += `<td>${localTime.time}</td>`;")
        html_lines.append("                        tableHtml += `<td>0</td>`;")
        html_lines.append("                        tableHtml += `<td>${sessionDisplay}</td>`;")
        html_lines.append("                        tableHtml += `</tr>`;")
        html_lines.append("                    }")
        html_lines.append("                }")
        html_lines.append("            }")
        html_lines.append("            ")
        html_lines.append("            // Обрабатываем каждый день")
        html_lines.append("            sortedDays.forEach((day, dayIndex) => {")
        html_lines.append("                const dayData = dayGroups[day];")
        html_lines.append("                const stats = dayStats[day];")
        html_lines.append("                ")
        html_lines.append("                // Заголовок дня со статистикой")
        html_lines.append("                const firstRowOfDay = dayData.find(row => formatLocalDateTime(row.datetime_utc).date);")
        html_lines.append("                const localDate = firstRowOfDay ? formatLocalDateTime(firstRowOfDay.datetime_utc).date : day;")
        html_lines.append("                ")
        html_lines.append("                tableHtml += `<tr class='date-header'>`;")
        html_lines.append("                tableHtml += `<td colspan='4'>── ${localDate} ── Запросов: ${stats.requests}, Сессий: ${stats.sessions.size} ──</td>`;")
        html_lines.append("                tableHtml += `</tr>`;")
        html_lines.append("                ")
        html_lines.append("                // Строки для каждого часа")
        html_lines.append("                dayData.forEach(row => {")
        html_lines.append("                    const localTime = formatLocalDateTime(row.datetime_utc);")
        html_lines.append("                    let cssClass = row.session_num > 0 ? 'session-active' : 'session-rest';")
        html_lines.append("                    let sessionDisplay = row.session_num > 0 ? row.session_num : '-';")
        html_lines.append("                    ")
        html_lines.append("                    // Проверяем прогноз для текущего часа")
        html_lines.append("                    if (predictedNextSession && dayIndex === 0 && ")
        html_lines.append("                        row.date === predictedNextSession.date && ")
        html_lines.append("                        row.hour === predictedNextSession.hour && ")
        html_lines.append("                        row.session_num === 0) {")
        html_lines.append("                        cssClass = 'predicted-next-session';")
        html_lines.append("                        sessionDisplay = 'ПРОГНОЗ: Следующая сессия';")
        html_lines.append("                    }")
        html_lines.append("                    ")
        html_lines.append("                    tableHtml += `<tr class='${cssClass}'>`;")
        html_lines.append("                    tableHtml += `<td>${localTime.date}</td>`;")
        html_lines.append("                    tableHtml += `<td>${localTime.time}</td>`;")
        html_lines.append("                    tableHtml += `<td>${row.queries}</td>`;")
        html_lines.append("                    tableHtml += `<td>${sessionDisplay}</td>`;")
        html_lines.append("                    tableHtml += `</tr>`;")
        html_lines.append("                });")
        html_lines.append("            });")
        html_lines.append("            ")
        html_lines.append("            tbody.innerHTML = tableHtml;")
        html_lines.append("            document.getElementById('dataTable').classList.remove('hidden');")
        html_lines.append("        }")
        html_lines.append("        ")
        html_lines.append("        function updateTimestamp() {")
        html_lines.append("            if (reportData) {")
        html_lines.append("                const updateTime = formatLocalDateTime(reportData.generated_at_utc);")
        html_lines.append("                document.getElementById('updateTimeText').textContent = `Обновлено: ${updateTime.date} ${updateTime.time}`;")
        html_lines.append("                document.getElementById('timezoneInfo').textContent = `(${userTimezone})`;")
        html_lines.append("            }")
        html_lines.append("        }")
        html_lines.append("        ")
        html_lines.append("        function loadReport() {")
        html_lines.append("            fetch('report.json')")
        html_lines.append("                .then(response => {")
        html_lines.append("                    if (!response.ok) {")
        html_lines.append("                        throw new Error('Ошибка загрузки: ' + response.status);")
        html_lines.append("                    }")
        html_lines.append("                    return response.json();")
        html_lines.append("                })")
        html_lines.append("                .then(data => {")
        html_lines.append("                    reportData = data;")
        html_lines.append("                    hideLoading();")
        html_lines.append("                    ")
        html_lines.append("                    // Обновляем заголовок")
        html_lines.append("                    document.getElementById('reportTitle').textContent = `Отчет по запросам к ${data.target_domain}`;")
        html_lines.append("                    ")
        html_lines.append("                    // Обновляем время")
        html_lines.append("                    updateTimestamp();")
        html_lines.append("                    ")
        html_lines.append("                    // Рендерим статистику и таблицу")
        html_lines.append("                    renderStats(data.summary);")
        html_lines.append("                    renderTable(data.table_data, data.predicted_next_session);")
        html_lines.append("                })")
        html_lines.append("                .catch(error => {")
        html_lines.append("                    console.error('Ошибка загрузки отчета:', error);")
        html_lines.append("                    showError();")
        html_lines.append("                });")
        html_lines.append("        }")
        html_lines.append("        ")
        html_lines.append("        // Загружаем отчет при загрузке страницы")
        html_lines.append("        document.addEventListener('DOMContentLoaded', loadReport);")
        html_lines.append("        ")
        html_lines.append("        // Обновление каждые 15 минут")
        html_lines.append("        setInterval(function() { location.reload(); }, 15 * 60 * 1000);")
        html_lines.append("        ")
        html_lines.append("        // Обновляем время каждую минуту")
        html_lines.append("        setInterval(updateTimestamp, 60 * 1000);")
        html_lines.append("    </script>")
        html_lines.append("</body>")
        html_lines.append("</html>")
        
        return "\n".join(html_lines)
    
    def generate_json_report(self) -> dict:
        """Генерация JSON отчета с данными в UTC"""
        # Загружаем все данные с анализом сессий
        daily_stats = self.load_all_data_with_sessions()
        total_requests = 0
        all_hourly = Counter()
        session_stats = []
        
        # Подсчитываем общую статистику
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
        
        # Формируем общую статистику
        summary_stats = {
            'total_requests': total_requests,
            'total_days': len(json_files),
            'peak_hour': None,
            'peak_hour_count': 0,
            'max_sessions_per_day': 0,
            'avg_sessions_per_day': 0,
            'sessions_this_month': 0
        }
        
        if all_hourly:
            peak_hour_data = all_hourly.most_common(1)[0]
            summary_stats['peak_hour'] = peak_hour_data[0]
            summary_stats['peak_hour_count'] = peak_hour_data[1]
        
        if session_stats:
            summary_stats['max_sessions_per_day'] = max(session_stats)
            summary_stats['avg_sessions_per_day'] = round(sum(session_stats) / len(session_stats), 1)
            
            # Подсчет сессий за последний месяц
            today = datetime.now().date()
            if today.day >= self.month_start_day:
                month_start = today.replace(day=self.month_start_day)
            else:
                if today.month == 1:
                    month_start = today.replace(year=today.year-1, month=12, day=self.month_start_day)
                else:
                    month_start = today.replace(month=today.month-1, day=self.month_start_day)
            
            month_sessions_set = set()
            for day, stats in daily_stats.items():
                day_date = datetime.strptime(day, '%Y-%m-%d').date()
                if day_date >= month_start:
                    sessions = stats['sessions']
                    for hour, session_num in sessions.items():
                        if session_num > 0:
                            month_sessions_set.add(session_num)
            summary_stats['sessions_this_month'] = len(month_sessions_set)
        
        # Генерируем данные таблицы
        table_data = []
        for day in sorted(daily_stats.keys(), reverse=True):
            stats = daily_stats[day]
            hourly = stats['hourly']
            sessions = stats['sessions']
            
            # Добавляем все 24 часа для каждого дня (в обратном порядке 23:00-00:00)
            for hour in range(23, -1, -1):
                queries = hourly.get(str(hour), 0)
                session_num = sessions.get(hour, 0)
                
                # Создаем UTC datetime для данного часа, конвертируя из местного времени
                day_date = datetime.strptime(day, "%Y-%m-%d").date()
                dt_utc = self.convert_local_to_utc(day_date, hour)
                
                table_data.append({
                    'date': day,
                    'hour': hour,
                    'datetime_utc': dt_utc.isoformat().replace('+00:00', 'Z'),  # ISO format в UTC
                    'queries': queries,
                    'session_num': session_num
                })
        
        # Находим прогнозируемое время следующей сессии
        predicted_next_session = None
        if table_data:
            # Ищем последнюю активную сессию
            sorted_days = sorted(daily_stats.keys(), reverse=True)
            if sorted_days:
                latest_day = sorted_days[0]
                latest_day_stats = daily_stats[latest_day]
                
                # Находим активные сессии в последнем дне
                active_sessions = []
                sessions = latest_day_stats['sessions']
                hourly = latest_day_stats['hourly']
                
                for hour in range(24):
                    session_num = sessions.get(hour, 0)
                    queries = hourly.get(str(hour), 0)
                    if session_num > 0 and queries > 0:
                        active_sessions.append((hour, session_num))
                
                if active_sessions:
                    # Сортируем по часам и берем последнюю активность
                    active_sessions.sort()
                    last_active_hour, last_session_num = active_sessions[-1]
                    
                    # Находим начало этой сессии
                    session_start_hour = None
                    for hour in range(24):
                        if sessions.get(hour, 0) == last_session_num:
                            if session_start_hour is None or hour < session_start_hour:
                                session_start_hour = hour
                    
                    # Прогнозируем начало следующей сессии (через 5 часов)
                    if session_start_hour is not None:
                        next_session_raw_hour = session_start_hour + 5
                        
                        if next_session_raw_hour >= 24:
                            # Следующая сессия на следующий день
                            predicted_hour = next_session_raw_hour % 24
                            latest_date = datetime.strptime(latest_day, '%Y-%m-%d').date()
                            next_date = latest_date + timedelta(days=1)
                            predicted_date = next_date.strftime('%Y-%m-%d')
                        else:
                            # Следующая сессия в том же дне
                            predicted_hour = next_session_raw_hour
                            predicted_date = latest_day
                        
                        # Создаем UTC datetime для прогноза
                        pred_day_date = datetime.strptime(predicted_date, "%Y-%m-%d").date()
                        pred_dt_utc = self.convert_local_to_utc(pred_day_date, predicted_hour)
                        
                        predicted_next_session = {
                            'date': predicted_date,
                            'hour': predicted_hour,
                            'datetime_utc': pred_dt_utc.isoformat().replace('+00:00', 'Z')
                        }
        
        # Формируем итоговый JSON
        report_data = {
            'generated_at_utc': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            'target_domain': self.target_domain,
            'month_start_day': self.month_start_day,
            'summary': summary_stats,
            'predicted_next_session': predicted_next_session,
            'table_data': table_data
        }
        
        return report_data
    
    def upload_report(self, report_file: Path, csv_file: Path = None, json_file: Path = None):
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
            
            # Загружаем JSON файл если он указан
            if json_file and json_file.exists():
                json_path = f"{upload_path_abs}/report.json"
                try:
                    sftp.put(str(json_file), json_path)
                    print(f"JSON отчет успешно загружен как: {json_path}")
                except Exception as e:
                    print(f"Ошибка: Не удалось загрузить JSON файл через SFTP: {e}")
            
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
        
        # Генерация и сохранение JSON отчета
        print("Генерация JSON отчета...")
        json_data = self.generate_json_report()
        json_file = self.data_dir / "report.json"
        
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False)
        
        print(f"JSON отчет сохранен в {json_file}")
        
        # Генерация и сохранение HTML отчета
        print("Генерация HTML отчета...")
        html_content = self.generate_html_report()
        html_file = self.data_dir / "report.html"
        
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"HTML отчет сохранен в {html_file}")
        
        # Загрузка отчета на сервер (если запрошено)
        if upload_report:
            self.upload_report(report_file, csv_file, json_file)
        
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
    parser.add_argument('--no-upload', action='store_true', help='Не загружать отчет на веб-сервер (отключить загрузку)')
    parser.add_argument('--upload-host', default=env_vars.get('PRIVOXY_UPLOAD_HOST', 'your-server.com'), 
                       help='Хост для загрузки отчета')
    parser.add_argument('--upload-user', default=env_vars.get('PRIVOXY_UPLOAD_USER'), 
                       help='Пользователь для загрузки отчета')
    parser.add_argument('--upload-path', default=env_vars.get('PRIVOXY_UPLOAD_PATH', '~/public_html/reports'), 
                       help='Путь для загрузки отчета')
    
    args = parser.parse_args()
    
    # Определяем параметры загрузки
    upload_enabled = args.upload and not args.no_upload
    upload_host = args.upload_host if upload_enabled else None
    upload_user = args.upload_user if upload_enabled else None
    upload_path = args.upload_path if upload_enabled else None
    
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
        analyzer.run_analysis(upload_report=upload_enabled)
        # Подсчитываем количество JSON файлов для краткой статистики
        json_files = list(analyzer.data_dir.glob("*.json"))
        print(f"Анализ завершен. Обработано дней: {len(json_files)}")
        print("Отчет сохранен в data/report.md")
        if upload_enabled:
            print("Отчет загружен на веб-сервер")
        else:
            print("Загрузка на веб-сервер отключена")
    except Exception as e:
        print(f"Ошибка: {e}")


if __name__ == "__main__":
    main()