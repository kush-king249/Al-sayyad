"""
اختبارات وحدة المسح لأداة Al-Sayyad
"""

import unittest
import tempfile
import os
import sys

# إضافة مسار المشروع
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from src.core.database_manager import DatabaseManager
from src.core.scanner import AntivirusScanner
from src.utils.file_operations import FileOperations


class TestAntivirusScanner(unittest.TestCase):
    """اختبارات محرك المسح"""
    
    def setUp(self):
        """إعداد الاختبارات"""
        # إنشاء قاعدة بيانات مؤقتة
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.temp_db.close()
        
        self.db_manager = DatabaseManager(self.temp_db.name)
        self.scanner = AntivirusScanner(self.db_manager)
        
        # إنشاء مجلد مؤقت للاختبار
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """تنظيف بعد الاختبارات"""
        # حذف قاعدة البيانات المؤقتة
        if os.path.exists(self.temp_db.name):
            os.unlink(self.temp_db.name)
        
        # حذف المجلد المؤقت
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_scan_clean_file(self):
        """اختبار فحص ملف نظيف"""
        # إنشاء ملف نظيف
        clean_file = os.path.join(self.temp_dir, "clean_file.txt")
        with open(clean_file, 'w') as f:
            f.write("هذا ملف نظيف للاختبار")
        
        # فحص الملف
        result = self.scanner.scan_file(clean_file)
        
        # التحقق من النتيجة
        self.assertFalse(result['is_threat'])
        self.assertIsNone(result['threat_name'])
        self.assertEqual(result['threat_level'], 0)
    
    def test_scan_suspicious_file(self):
        """اختبار فحص ملف مشبوه"""
        # إنشاء ملف مشبوه
        suspicious_file = os.path.join(self.temp_dir, "crack_keygen.exe")
        with open(suspicious_file, 'w') as f:
            f.write("ملف مشبوه للاختبار")
        
        # فحص الملف
        result = self.scanner.scan_file(suspicious_file)
        
        # التحقق من النتيجة (قد يكون مشبوهاً بناءً على الاسم والامتداد)
        # النتيجة تعتمد على المنطق السلوكي في المسح
        self.assertIsNotNone(result['scan_method'])
    
    def test_signature_detection(self):
        """اختبار كشف التوقيعات"""
        # إضافة توقيع للاختبار
        test_hash = "test_hash_123"
        self.db_manager.add_signature(test_hash, "Test.Malware", 3)
        
        # محاكاة ملف بنفس التوقيع (هذا مجرد اختبار للمنطق)
        # في الواقع، سيتم حساب التجزئة الفعلية
        signature_info = self.db_manager.check_signature(test_hash)
        
        # التحقق من النتيجة
        self.assertIsNotNone(signature_info)
        self.assertEqual(signature_info['malware_name'], "Test.Malware")
        self.assertEqual(signature_info['threat_level'], 3)
    
    def test_quick_scan(self):
        """اختبار المسح السريع"""
        # تشغيل المسح السريع
        result = self.scanner.quick_scan()
        
        # التحقق من النتيجة
        self.assertIsNotNone(result)
        self.assertGreaterEqual(result.scanned_files, 0)
        self.assertGreaterEqual(result.threats_found, 0)
        self.assertIn(result.status, ["مكتمل", "تم الإلغاء"])


class TestFileOperations(unittest.TestCase):
    """اختبارات عمليات الملفات"""
    
    def setUp(self):
        """إعداد الاختبارات"""
        self.temp_dir = tempfile.mkdtemp()
        self.file_ops = FileOperations()
    
    def tearDown(self):
        """تنظيف بعد الاختبارات"""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_calculate_file_hash(self):
        """اختبار حساب تجزئة الملف"""
        # إنشاء ملف للاختبار
        test_file = os.path.join(self.temp_dir, "test_file.txt")
        test_content = "محتوى الاختبار"
        
        with open(test_file, 'w', encoding='utf-8') as f:
            f.write(test_content)
        
        # حساب التجزئة
        file_hash = self.file_ops.calculate_file_hash(test_file, 'sha256')
        
        # التحقق من النتيجة
        self.assertIsNotNone(file_hash)
        self.assertEqual(len(file_hash), 64)  # SHA-256 hash length
    
    def test_get_file_info(self):
        """اختبار الحصول على معلومات الملف"""
        # إنشاء ملف للاختبار
        test_file = os.path.join(self.temp_dir, "test_file.txt")
        with open(test_file, 'w') as f:
            f.write("اختبار")
        
        # الحصول على معلومات الملف
        file_info = self.file_ops.get_file_info(test_file)
        
        # التحقق من النتيجة
        self.assertIn('size', file_info)
        self.assertIn('created', file_info)
        self.assertIn('modified', file_info)
        self.assertIn('extension', file_info)
        self.assertEqual(file_info['extension'], '.txt')
    
    def test_quarantine_file(self):
        """اختبار نقل ملف للحجر الصحي"""
        # إنشاء ملف للاختبار
        test_file = os.path.join(self.temp_dir, "malicious_file.exe")
        with open(test_file, 'w') as f:
            f.write("ملف ضار وهمي")
        
        # إنشاء مجلد الحجر الصحي
        quarantine_dir = os.path.join(self.temp_dir, "quarantine")
        
        # نقل الملف للحجر الصحي
        quarantine_path = self.file_ops.quarantine_file(test_file, quarantine_dir)
        
        # التحقق من النتيجة
        self.assertIsNotNone(quarantine_path)
        self.assertTrue(os.path.exists(quarantine_path))
        self.assertFalse(os.path.exists(test_file))  # الملف الأصلي يجب أن يكون قد نُقل


class TestDatabaseManager(unittest.TestCase):
    """اختبارات مدير قاعدة البيانات"""
    
    def setUp(self):
        """إعداد الاختبارات"""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.temp_db.close()
        self.db_manager = DatabaseManager(self.temp_db.name)
    
    def tearDown(self):
        """تنظيف بعد الاختبارات"""
        if os.path.exists(self.temp_db.name):
            os.unlink(self.temp_db.name)
    
    def test_add_signature(self):
        """اختبار إضافة توقيع"""
        # إضافة توقيع جديد
        success = self.db_manager.add_signature("test_hash", "Test.Virus", 4)
        
        # التحقق من النتيجة
        self.assertTrue(success)
        
        # التحقق من وجود التوقيع
        signature_info = self.db_manager.check_signature("test_hash")
        self.assertIsNotNone(signature_info)
        self.assertEqual(signature_info['malware_name'], "Test.Virus")
        self.assertEqual(signature_info['threat_level'], 4)
    
    def test_log_scan_result(self):
        """اختبار تسجيل نتيجة المسح"""
        # تسجيل نتيجة مسح
        self.db_manager.log_scan_result("/path/to/file.exe", "Trojan.Test", True)
        
        # الحصول على الإحصائيات
        stats = self.db_manager.get_scan_statistics()
        
        # التحقق من النتيجة
        self.assertGreater(stats['total_scans'], 0)
        self.assertGreater(stats['threats_detected'], 0)
    
    def test_get_scan_statistics(self):
        """اختبار الحصول على إحصائيات المسح"""
        # الحصول على الإحصائيات
        stats = self.db_manager.get_scan_statistics()
        
        # التحقق من وجود المفاتيح المطلوبة
        required_keys = ['total_scans', 'threats_detected', 'quarantined_files', 'total_signatures']
        for key in required_keys:
            self.assertIn(key, stats)
            self.assertIsInstance(stats[key], int)


if __name__ == '__main__':
    # تشغيل الاختبارات
    unittest.main(verbosity=2)
