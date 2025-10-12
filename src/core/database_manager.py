"""
مدير قاعدة البيانات لأداة Al-Sayyad
يدير قاعدة بيانات التوقيعات وسجلات المسح
"""

import sqlite3
import os
from datetime import datetime
from typing import List, Dict, Optional


class DatabaseManager:
    """مدير قاعدة البيانات الرئيسي لأداة Al-Sayyad"""
    
    def __init__(self, db_path: str = "data/signatures.db"):
        """
        تهيئة مدير قاعدة البيانات
        
        Args:
            db_path (str): مسار قاعدة البيانات
        """
        self.db_path = db_path
        self._ensure_db_directory()
        self._initialize_database()
    
    def _ensure_db_directory(self):
        """التأكد من وجود مجلد قاعدة البيانات"""
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir)
    
    def _initialize_database(self):
        """تهيئة جداول قاعدة البيانات"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # جدول التوقيعات
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS signatures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hash_value TEXT UNIQUE NOT NULL,
                    malware_name TEXT NOT NULL,
                    threat_level INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # جدول سجلات المسح
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT NOT NULL,
                    scan_result TEXT NOT NULL,
                    threat_detected BOOLEAN DEFAULT FALSE,
                    scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # جدول الملفات المحجورة
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS quarantine (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    original_path TEXT NOT NULL,
                    quarantine_path TEXT NOT NULL,
                    threat_name TEXT NOT NULL,
                    quarantine_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            self._populate_sample_signatures()
    
    def _populate_sample_signatures(self):
        """إضافة توقيعات عينة للاختبار"""
        sample_signatures = [
            ("d41d8cd98f00b204e9800998ecf8427e", "Test.Malware.A", 3),
            ("5d41402abc4b2a76b9719d911017c592", "Trojan.Generic", 5),
            ("098f6bcd4621d373cade4e832627b4f6", "Virus.TestVirus", 4),
            ("e3b0c44298fc1c149afbf4c8996fb924", "Adware.Sample", 2),
            ("adc83b19e793491b1c6ea0fd8b46cd9f", "Spyware.Monitor", 4)
        ]
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            for hash_val, name, level in sample_signatures:
                cursor.execute('''
                    INSERT OR IGNORE INTO signatures (hash_value, malware_name, threat_level)
                    VALUES (?, ?, ?)
                ''', (hash_val, name, level))
            conn.commit()
    
    def add_signature(self, hash_value: str, malware_name: str, threat_level: int = 1) -> bool:
        """
        إضافة توقيع جديد لقاعدة البيانات
        
        Args:
            hash_value (str): قيمة التجزئة
            malware_name (str): اسم البرنامج الضار
            threat_level (int): مستوى التهديد (1-5)
            
        Returns:
            bool: True إذا تمت الإضافة بنجاح
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO signatures (hash_value, malware_name, threat_level)
                    VALUES (?, ?, ?)
                ''', (hash_value, malware_name, threat_level))
                conn.commit()
                return True
        except sqlite3.IntegrityError:
            return False
    
    def check_signature(self, hash_value: str) -> Optional[Dict]:
        """
        فحص توقيع في قاعدة البيانات
        
        Args:
            hash_value (str): قيمة التجزئة للفحص
            
        Returns:
            Dict أو None: معلومات التهديد إذا وُجد
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT malware_name, threat_level FROM signatures
                WHERE hash_value = ?
            ''', (hash_value,))
            
            result = cursor.fetchone()
            if result:
                return {
                    'malware_name': result[0],
                    'threat_level': result[1]
                }
            return None
    
    def log_scan_result(self, file_path: str, scan_result: str, threat_detected: bool = False):
        """
        تسجيل نتيجة المسح
        
        Args:
            file_path (str): مسار الملف
            scan_result (str): نتيجة المسح
            threat_detected (bool): هل تم اكتشاف تهديد
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO scan_logs (file_path, scan_result, threat_detected)
                VALUES (?, ?, ?)
            ''', (file_path, scan_result, threat_detected))
            conn.commit()
    
    def add_to_quarantine(self, original_path: str, quarantine_path: str, threat_name: str):
        """
        إضافة ملف للحجر الصحي
        
        Args:
            original_path (str): المسار الأصلي للملف
            quarantine_path (str): مسار الحجر الصحي
            threat_name (str): اسم التهديد
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO quarantine (original_path, quarantine_path, threat_name)
                VALUES (?, ?, ?)
            ''', (original_path, quarantine_path, threat_name))
            conn.commit()
    
    def get_scan_statistics(self) -> Dict:
        """
        الحصول على إحصائيات المسح
        
        Returns:
            Dict: إحصائيات المسح
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # إجمالي عمليات المسح
            cursor.execute('SELECT COUNT(*) FROM scan_logs')
            total_scans = cursor.fetchone()[0]
            
            # التهديدات المكتشفة
            cursor.execute('SELECT COUNT(*) FROM scan_logs WHERE threat_detected = TRUE')
            threats_detected = cursor.fetchone()[0]
            
            # الملفات المحجورة
            cursor.execute('SELECT COUNT(*) FROM quarantine')
            quarantined_files = cursor.fetchone()[0]
            
            # إجمالي التوقيعات
            cursor.execute('SELECT COUNT(*) FROM signatures')
            total_signatures = cursor.fetchone()[0]
            
            return {
                'total_scans': total_scans,
                'threats_detected': threats_detected,
                'quarantined_files': quarantined_files,
                'total_signatures': total_signatures
            }
    
    def get_recent_threats(self, limit: int = 10) -> List[Dict]:
        """
        الحصول على التهديدات الأخيرة
        
        Args:
            limit (int): عدد النتائج المطلوبة
            
        Returns:
            List[Dict]: قائمة بالتهديدات الأخيرة
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT file_path, scan_result, scan_time
                FROM scan_logs
                WHERE threat_detected = TRUE
                ORDER BY scan_time DESC
                LIMIT ?
            ''', (limit,))
            
            results = cursor.fetchall()
            return [
                {
                    'file_path': row[0],
                    'threat_name': row[1],
                    'detection_time': row[2]
                }
                for row in results
            ]
    
    def get_quarantined_files(self) -> List[Dict]:
        """
        الحصول على قائمة الملفات المحجورة
        
        Returns:
            List[Dict]: قائمة الملفات المحجورة
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT original_path, quarantine_path, threat_name, quarantine_time
                FROM quarantine
                ORDER BY quarantine_time DESC
            ''')
            
            results = cursor.fetchall()
            return [
                {
                    'original_path': row[0],
                    'quarantine_path': row[1],
                    'threat_name': row[2],
                    'quarantine_time': row[3]
                }
                for row in results
            ]
