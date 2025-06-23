#!/usr/bin/env python3
"""
Простой тест алгоритма анализа сессий без внешних зависимостей
"""

import json
from pathlib import Path
from datetime import datetime, timedelta
from collections import Counter

def analyze_sessions(daily_stats):
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
        
        print(f"\nСессия {session_num}: с {session_start} до {session_end}")
        
        # Отмечаем все активные часы в текущем 5-часовом окне
        j = i
        session_has_activity = False
        while j < len(time_points) and time_points[j][0] < session_end:
            dt, day, hour, count = time_points[j]
            daily_stats[day]['sessions'][hour] = session_num
            print(f"  {dt} (день {day}, час {hour}) -> сессия {session_num}")
            session_has_activity = True
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

def test_session_analysis():
    """Тестируем анализ сессий на загруженных данных"""
    
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
    daily_stats = analyze_sessions(daily_stats)
    
    # Выводим результат для нескольких дней
    print("\nРезультат анализа сессий:")
    print("=" * 50)
    
    for day in sorted(daily_stats.keys())[-3:]:  # последние 3 дня
        print(f"\n=== {day} ===")
        stats = daily_stats[day]
        
        for hour in range(24):
            queries = stats['hourly'].get(str(hour), 0)
            session = stats['sessions'][hour]
            
            if queries > 0 or session > 0:
                print(f"{hour:02d}:00 - queries: {queries:3d}, session: {session}")
    
    # Также создадим несколько строк CSV для проверки
    print("\nПример CSV данных:")
    print("date,time,queries,session_num")
    
    for day in sorted(daily_stats.keys())[-1:]:  # только последний день
        stats = daily_stats[day]
        for hour in range(24):
            queries = stats['hourly'].get(str(hour), 0)
            session = stats['sessions'][hour]
            time_str = f"{hour:02d}:00"
            print(f"{day},{time_str},{queries},{session}")

if __name__ == "__main__":
    test_session_analysis()