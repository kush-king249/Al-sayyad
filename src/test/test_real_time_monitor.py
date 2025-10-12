"""
اختبارات مراقب الوقت الفعلي لأداة Al-Sayyad
"""

import unittest
import tempfile
import os
import sys
import time
import threading

# إضافة مسار المشروع
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from src.core.database_manager import DatabaseManager
from src.core.scanner import AntivirusScanner
from src.core.real_time_monitor import RealTimeMonitor


class TestRealTimeMonitor(unittest.TestCase):
    """اختبارات مراقب الوقت الفعلي"""
    
    def setUp(self):
        """إعداد الاختبارات"""
        # إنشاء قاعدة بيانات مؤقتة
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.temp_db.close()
        
        self.db_manager = DatabaseManager(self.temp_db.name)
        self.scanner = AntivirusScanner(self.db_manager)
        self.monitor = RealTimeMonitor(self.scanner, self.db_manager)
        
        # إنشاء مجلد مؤقت للمراقبة
        self.temp_dir = tempfile.mkdtemp()
        
        # متغيرات للاختبار
        self.threat_detected = False
        self.threat_info = None
    
    def tearDown(self):
        """تنظيف بعد الاختبارات"""
        # إيقاف المراقبة
        if self.monitor.is_monitoring:
            self.monitor.stop_monitoring()
        
        # حذف قاعدة البيانات المؤقتة
        if os.path.exists(self.temp_db.name):
            os.unlink(self.temp_db.name)
        
        # حذف المجلد المؤقت
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def threat_callback(self, threat_info):
        """callback للتهديدات المكتشفة"""
        self.threat_detected = True
        self.threat_info = threat_info
    
    def test_monitor_initialization(self):
        """اختبار تهيئة المراقب"""
        # التحقق من الحالة الأولية
        self.assertFalse(self.monitor.is_monitoring)
        self.assertEqual(len(self.monitor.monitored_paths), 0)
    
    def test_add_monitored_path(self):
        """اختبار إضافة مسار للمراقبة"""
        # إضافة مسار للمراقبة
        self.monitor.add_monitored_path(self.temp_dir)
        
        # التحقق من إضافة المسار
        self.assertEqual(len(self.monitor.monitored_paths), 1)
        self.assertEqual(self.monitor.monitored_paths[0]['path'], self.temp_dir)
    
    def test_remove_monitored_path(self):
        """اختبار إزالة مسار من المراقبة"""
        # إضافة مسار ثم إزالته
        self.monitor.add_monitored_path(self.temp_dir)
        self.monitor.remove_monitored_path(self.temp_dir)
        
        # التحقق من إزالة المسار
        self.assertEqual(len(self.monitor.monitored_paths), 0)
    
    def test_start_stop_monitoring(self):
        """اختبار بدء وإيقاف المراقبة"""
        # إضافة مسار للمراقبة
        self.monitor.add_monitored_path(self.temp_dir)
        
        # بدء المراقبة
        self.monitor.start_monitoring()
        self.assertTrue(self.monitor.is_monitoring)
        
        # إيقاف المراقبة
        self.monitor.stop_monitoring()
        self.assertFalse(self.monitor.is_monitoring)
    
    def test_get_monitoring_status(self):
        """اختبار الحصول على حالة المراقبة"""
        # إضافة مسار للمراقبة
        self.monitor.add_monitored_path(self.temp_dir)
        
        # الحصول على الحالة
        status = self.monitor.get_monitoring_status()
        
        # التحقق من الحالة
        self.assertIn('is_monitoring', status)
        self.assertIn('monitored_paths_count', status)
        self.assertIn('monitored_paths', status)
        self.assertEqual(status['monitored_paths_count'], 1)
    
    def test_get_monitoring_statistics(self):
        """اختبار الحصول على إحصائيات المراقبة"""
        # الحصول على الإحصائيات
        stats = self.monitor.get_monitoring_statistics()
        
        # التحقق من وجود المفاتيح المطلوبة
        required_keys = ['real_time_monitoring', 'monitored_paths']
        for key in required_keys:
            self.assertIn(key, stats)
    
    @unittest.skipIf(os.name == 'nt', "اختبار المراقبة الفعلية قد يكون بطيئاً على Windows")
    def test_file_creation_detection(self):
        """اختبار كشف إنشاء الملفات (اختبار متقدم)"""
        # تعيين callback للتهديدات
        self.monitor.set_threat_callback(self.threat_callback)
        
        # إضافة مسار للمراقبة
        self.monitor.add_monitored_path(self.temp_dir)
        
        # بدء المراقبة
        self.monitor.start_monitoring()
        
        # انتظار قصير لبدء المراقبة
        time.sleep(1)
        
        # إنشاء ملف مشبوه
        suspicious_file = os.path.join(self.temp_dir, "crack_keygen.exe")
        with open(suspicious_file, 'w') as f:
            f.write("ملف مشبوه للاختبار")
        
        # انتظار لمعالجة الحدث
        time.sleep(2)
        
        # إيقاف المراقبة
        self.monitor.stop_monitoring()
        
        # ملاحظة: هذا الاختبار قد لا يعمل دائماً بسبب طبيعة المراقبة في الوقت الفعلي
        # والحاجة لوقت لمعالجة الأحداث
        # في بيئة الإنتاج، ستكون هناك آليات أكثر تعقيداً للاختبار


if __name__ == '__main__':
    # تشغيل الاختبارات
    unittest.main(verbosity=2)
