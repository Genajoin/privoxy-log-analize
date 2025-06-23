#!/usr/bin/env python3
"""
Тестовый скрипт для проверки алгоритма анализа сессий
"""

import json
from pathlib import Path
from datetime import datetime, timedelta
from main import PrivoxyLogAnalyzer

def test_session_analysis():
    """Тестируем анализ сессий на загруженных данных"""
    
    # Создаем экземпляр анализатора
    analyzer = PrivoxyLogAnalyzer()
    
    # Загружаем данные из существующих JSON файлов
    daily_stats = {}
    data_dir = Path("data")
    
    for json_file in data_dir.glob("*.json"):
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
            day = data['date']
            daily_stats[day] = {
                'requests': data['total_requests'],
                'hourly': data['hourly_distribution']
            }
    
    print(f"Загружено {len(daily_stats)} дней данных")
    
    # Анализируем сессии
    daily_stats = analyzer.analyze_sessions(daily_stats)
    
    # Выводим результат для нескольких дней
    for day in sorted(daily_stats.keys())[-3:]:  # последние 3 дня
        print(f"\n=== {day} ===")
        stats = daily_stats[day]
        
        for hour in range(24):
            queries = stats['hourly'].get(str(hour), 0)
            session = stats['sessions'][hour]
            
            if queries > 0 or session > 0:
                print(f"{hour:02d}:00 - queries: {queries:3d}, session: {session}")

if __name__ == "__main__":
    test_session_analysis()