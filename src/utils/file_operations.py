"""
عمليات الملفات لأداة Al-Sayyad
يتضمن التجزئة، النسخ، الحذف، والحجر الصحي
"""

import os
import hashlib
import shutil
from typing import Optional, List
from datetime import datetime


class FileOperations:
    """فئة عمليات الملفات"""
    
    @staticmethod
    def calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> Optional[str]:
        """
        حساب تجزئة الملف
        
        Args:
            file_path (str): مسار الملف
            algorithm (str): خوارزمية التجزئة (md5, sha1, sha256)
            
        Returns:
            str أو None: قيمة التجزئة أو None في حالة الخطأ
        """
        try:
            hash_obj = hashlib.new(algorithm)
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except (IOError, OSError, ValueError) as e:
            print(f"خطأ في حساب التجزئة للملف {file_path}: {e}")
            return None
    
    @staticmethod
    def get_file_info(file_path: str) -> dict:
        """
        الحصول على معلومات الملف
        
        Args:
            file_path (str): مسار الملف
            
        Returns:
            dict: معلومات الملف
        """
        try:
            stat = os.stat(file_path)
            return {
                'size': stat.st_size,
                'created': datetime.fromtimestamp(stat.st_ctime),
                'modified': datetime.fromtimestamp(stat.st_mtime),
                'accessed': datetime.fromtimestamp(stat.st_atime),
                'extension': os.path.splitext(file_path)[1].lower()
            }
        except (IOError, OSError) as e:
            print(f"خطأ في الحصول على معلومات الملف {file_path}: {e}")
            return {}
    
    @staticmethod
    def quarantine_file(file_path: str, quarantine_dir: str) -> Optional[str]:
        """
        نقل ملف إلى الحجر الصحي
        
        Args:
            file_path (str): مسار الملف الأصلي
            quarantine_dir (str): مجلد الحجر الصحي
            
        Returns:
            str أو None: مسار الملف في الحجر الصحي أو None في حالة الخطأ
        """
        try:
            # إنشاء مجلد الحجر الصحي إذا لم يكن موجوداً
            os.makedirs(quarantine_dir, exist_ok=True)
            
            # إنشاء اسم فريد للملف المحجور
            filename = os.path.basename(file_path)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_filename = f"{timestamp}_{filename}.quarantined"
            quarantine_path = os.path.join(quarantine_dir, quarantine_filename)
            
            # نسخ الملف إلى الحجر الصحي
            shutil.move(file_path, quarantine_path)
            
            return quarantine_path
        except (IOError, OSError) as e:
            print(f"خطأ في نقل الملف إلى الحجر الصحي {file_path}: {e}")
            return None
    
    @staticmethod
    def restore_from_quarantine(quarantine_path: str, original_path: str) -> bool:
        """
        استعادة ملف من الحجر الصحي
        
        Args:
            quarantine_path (str): مسار الملف في الحجر الصحي
            original_path (str): المسار الأصلي للاستعادة
            
        Returns:
            bool: True إذا تمت الاستعادة بنجاح
        """
        try:
            # التأكد من وجود المجلد الهدف
            os.makedirs(os.path.dirname(original_path), exist_ok=True)
            
            # نقل الملف من الحجر الصحي إلى المسار الأصلي
            shutil.move(quarantine_path, original_path)
            return True
        except (IOError, OSError) as e:
            print(f"خطأ في استعادة الملف من الحجر الصحي: {e}")
            return False
    
    @staticmethod
    def delete_quarantined_file(quarantine_path: str) -> bool:
        """
        حذف ملف من الحجر الصحي نهائياً
        
        Args:
            quarantine_path (str): مسار الملف في الحجر الصحي
            
        Returns:
            bool: True إذا تم الحذف بنجاح
        """
        try:
            os.remove(quarantine_path)
            return True
        except (IOError, OSError) as e:
            print(f"خطأ في حذف الملف من الحجر الصحي: {e}")
            return False
    
    @staticmethod
    def scan_directory(directory_path: str, extensions: List[str] = None) -> List[str]:
        """
        مسح مجلد والحصول على قائمة الملفات
        
        Args:
            directory_path (str): مسار المجلد
            extensions (List[str]): قائمة امتدادات الملفات للفحص (اختياري)
            
        Returns:
            List[str]: قائمة مسارات الملفات
        """
        files = []
        
        # امتدادات افتراضية للفحص
        if extensions is None:
            extensions = ['.exe', '.dll', '.bat', '.cmd', '.scr', '.com', '.pif', '.vbs', '.js']
        
        try:
            for root, dirs, filenames in os.walk(directory_path):
                for filename in filenames:
                    file_path = os.path.join(root, filename)
                    file_ext = os.path.splitext(filename)[1].lower()
                    
                    # فحص جميع الملفات إذا لم تُحدد امتدادات
                    if not extensions or file_ext in extensions:
                        files.append(file_path)
        except (IOError, OSError) as e:
            print(f"خطأ في مسح المجلد {directory_path}: {e}")
        
        return files
    
    @staticmethod
    def is_safe_to_scan(file_path: str) -> bool:
        """
        التحقق من أمان فحص الملف
        
        Args:
            file_path (str): مسار الملف
            
        Returns:
            bool: True إذا كان آمناً للفحص
        """
        try:
            # تجنب فحص ملفات النظام الحرجة
            system_paths = [
                'windows/system32',
                'windows/syswow64',
                'program files/windows defender',
                'program files (x86)/windows defender'
            ]
            
            file_path_lower = file_path.lower()
            for sys_path in system_paths:
                if sys_path in file_path_lower:
                    return False
            
            # التحقق من حجم الملف (تجنب الملفات الكبيرة جداً)
            file_size = os.path.getsize(file_path)
            max_size = 100 * 1024 * 1024  # 100 MB
            
            return file_size <= max_size
        except (IOError, OSError):
            return False
    
    @staticmethod
    def get_directory_size(directory_path: str) -> int:
        """
        حساب حجم المجلد
        
        Args:
            directory_path (str): مسار المجلد
            
        Returns:
            int: حجم المجلد بالبايت
        """
        total_size = 0
        try:
            for root, dirs, files in os.walk(directory_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        total_size += os.path.getsize(file_path)
                    except (IOError, OSError):
                        continue
        except (IOError, OSError):
            pass
        
        return total_size
