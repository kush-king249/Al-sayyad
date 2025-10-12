"""
مراقب الوقت الفعلي لأداة Al-Sayyad
يراقب تغييرات نظام الملفات في الوقت الفعلي
"""

import os
import threading
import time
from typing import Callable, List, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

from .scanner import AntivirusScanner
from .database_manager import DatabaseManager


class RealTimeEventHandler(FileSystemEventHandler):
    """معالج أحداث نظام الملفات"""
    
    def __init__(self, scanner: AntivirusScanner, callback: Optional[Callable] = None):
        """
        تهيئة معالج الأحداث
        
        Args:
            scanner (AntivirusScanner): محرك المسح
            callback (Callable): دالة callback للإشعارات
        """
        super().__init__()
        self.scanner = scanner
        self.callback = callback
        self.monitored_extensions = ['.exe', '.dll', '.bat', '.cmd', '.scr', '.com', '.pif', '.vbs', '.js']
        self.scan_queue = []
        self.scan_lock = threading.Lock()
        
        # بدء thread لمعالجة طابور المسح
        self.scan_thread = threading.Thread(target=self._process_scan_queue, daemon=True)
        self.scan_thread.start()
    
    def on_created(self, event: FileSystemEvent):
        """معالجة إنشاء ملف جديد"""
        if not event.is_directory:
            self._queue_file_for_scan(event.src_path, "تم إنشاء ملف جديد")
    
    def on_modified(self, event: FileSystemEvent):
        """معالجة تعديل ملف"""
        if not event.is_directory:
            self._queue_file_for_scan(event.src_path, "تم تعديل ملف")
    
    def on_moved(self, event: FileSystemEvent):
        """معالجة نقل ملف"""
        if not event.is_directory:
            self._queue_file_for_scan(event.dest_path, "تم نقل ملف")
    
    def _queue_file_for_scan(self, file_path: str, event_type: str):
        """
        إضافة ملف لطابور المسح
        
        Args:
            file_path (str): مسار الملف
            event_type (str): نوع الحدث
        """
        try:
            # فحص امتداد الملف
            file_ext = os.path.splitext(file_path)[1].lower()
            if file_ext not in self.monitored_extensions:
                return
            
            # التأكد من وجود الملف
            if not os.path.exists(file_path):
                return
            
            with self.scan_lock:
                # تجنب المسح المتكرر لنفس الملف
                if file_path not in [item['path'] for item in self.scan_queue]:
                    self.scan_queue.append({
                        'path': file_path,
                        'event_type': event_type,
                        'timestamp': time.time()
                    })
        
        except Exception as e:
            print(f"خطأ في إضافة الملف للطابور: {e}")
    
    def _process_scan_queue(self):
        """معالجة طابور المسح"""
        while True:
            try:
                with self.scan_lock:
                    if self.scan_queue:
                        item = self.scan_queue.pop(0)
                    else:
                        item = None
                
                if item:
                    self._scan_file_real_time(item)
                else:
                    time.sleep(1)  # انتظار قصير إذا لم توجد ملفات للمسح
            
            except Exception as e:
                print(f"خطأ في معالجة طابور المسح: {e}")
                time.sleep(5)
    
    def _scan_file_real_time(self, item: dict):
        """
        فحص ملف في الوقت الفعلي
        
        Args:
            item (dict): معلومات الملف والحدث
        """
        try:
            file_path = item['path']
            event_type = item['event_type']
            
            # انتظار قصير للتأكد من اكتمال كتابة الملف
            time.sleep(0.5)
            
            # فحص الملف
            scan_result = self.scanner.scan_file(file_path)
            
            # إشعار المستخدم إذا تم اكتشاف تهديد
            if scan_result['is_threat']:
                threat_info = {
                    'file_path': file_path,
                    'threat_name': scan_result['threat_name'],
                    'threat_level': scan_result['threat_level'],
                    'event_type': event_type,
                    'action_taken': scan_result.get('action_taken', 'لم يتم اتخاذ إجراء')
                }
                
                if self.callback:
                    self.callback(threat_info)
                
                print(f"تهديد مكتشف: {threat_info}")
        
        except Exception as e:
            print(f"خطأ في فحص الملف {item['path']}: {e}")


class RealTimeMonitor:
    """مراقب الوقت الفعلي"""
    
    def __init__(self, scanner: AntivirusScanner, db_manager: DatabaseManager):
        """
        تهيئة مراقب الوقت الفعلي
        
        Args:
            scanner (AntivirusScanner): محرك المسح
            db_manager (DatabaseManager): مدير قاعدة البيانات
        """
        self.scanner = scanner
        self.db_manager = db_manager
        self.observer = Observer()
        self.event_handler = None
        self.is_monitoring = False
        self.monitored_paths = []
        self.threat_callback = None
    
    def set_threat_callback(self, callback: Callable):
        """
        تعيين دالة callback للتهديدات
        
        Args:
            callback (Callable): دالة معالجة التهديدات
        """
        self.threat_callback = callback
    
    def add_monitored_path(self, path: str, recursive: bool = True):
        """
        إضافة مسار للمراقبة
        
        Args:
            path (str): المسار للمراقبة
            recursive (bool): مراقبة المجلدات الفرعية
        """
        if os.path.exists(path) and path not in self.monitored_paths:
            self.monitored_paths.append({
                'path': path,
                'recursive': recursive
            })
    
    def remove_monitored_path(self, path: str):
        """
        إزالة مسار من المراقبة
        
        Args:
            path (str): المسار لإزالته
        """
        self.monitored_paths = [p for p in self.monitored_paths if p['path'] != path]
    
    def start_monitoring(self):
        """بدء المراقبة في الوقت الفعلي"""
        if self.is_monitoring:
            return
        
        try:
            # إنشاء معالج الأحداث
            self.event_handler = RealTimeEventHandler(
                self.scanner,
                self.threat_callback
            )
            
            # إضافة المسارات الافتراضية للمراقبة
            self._add_default_paths()
            
            # بدء مراقبة المسارات
            for path_info in self.monitored_paths:
                if os.path.exists(path_info['path']):
                    self.observer.schedule(
                        self.event_handler,
                        path_info['path'],
                        recursive=path_info['recursive']
                    )
            
            self.observer.start()
            self.is_monitoring = True
            print("تم بدء المراقبة في الوقت الفعلي")
        
        except Exception as e:
            print(f"خطأ في بدء المراقبة: {e}")
    
    def stop_monitoring(self):
        """إيقاف المراقبة في الوقت الفعلي"""
        if not self.is_monitoring:
            return
        
        try:
            self.observer.stop()
            self.observer.join()
            self.is_monitoring = False
            print("تم إيقاف المراقبة في الوقت الفعلي")
        
        except Exception as e:
            print(f"خطأ في إيقاف المراقبة: {e}")
    
    def _add_default_paths(self):
        """إضافة المسارات الافتراضية للمراقبة"""
        default_paths = [
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Documents"),
        ]
        
        # إضافة مسارات Windows إذا كان النظام Windows
        if os.name == 'nt':
            default_paths.extend([
                "C:\\Windows\\Temp",
                "C:\\Users\\Public",
                os.path.expanduser("~/AppData/Roaming"),
                os.path.expanduser("~/AppData/Local/Temp")
            ])
        else:
            default_paths.extend([
                "/tmp",
                "/var/tmp"
            ])
        
        for path in default_paths:
            if os.path.exists(path):
                self.add_monitored_path(path, recursive=True)
    
    def get_monitoring_status(self) -> dict:
        """
        الحصول على حالة المراقبة
        
        Returns:
            dict: معلومات حالة المراقبة
        """
        return {
            'is_monitoring': self.is_monitoring,
            'monitored_paths_count': len(self.monitored_paths),
            'monitored_paths': [p['path'] for p in self.monitored_paths]
        }
    
    def get_monitoring_statistics(self) -> dict:
        """
        الحصول على إحصائيات المراقبة
        
        Returns:
            dict: إحصائيات المراقبة
        """
        stats = self.db_manager.get_scan_statistics()
        
        # إضافة معلومات المراقبة
        stats.update({
            'real_time_monitoring': self.is_monitoring,
            'monitored_paths': len(self.monitored_paths)
        })
        
        return stats
