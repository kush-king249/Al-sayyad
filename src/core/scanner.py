"""
محرك المسح الرئيسي لأداة Al-Sayyad
يجمع بين المسح القائم على التوقيعات والمسح السلوكي
"""

import os
import threading
from typing import List, Dict, Optional, Callable
from datetime import datetime

from ..utils.file_operations import FileOperations
from ..utils.system_analyzer import SystemAnalyzer
from .database_manager import DatabaseManager


class ScanResult:
    """فئة نتيجة المسح"""
    
    def __init__(self):
        self.scanned_files = 0
        self.threats_found = 0
        self.quarantined_files = 0
        self.scan_time = 0
        self.threats = []
        self.errors = []
        self.status = "مكتمل"


class AntivirusScanner:
    """محرك المسح الرئيسي"""
    
    def __init__(self, db_manager: DatabaseManager, quarantine_dir: str = "data/quarantine"):
        """
        تهيئة محرك المسح
        
        Args:
            db_manager (DatabaseManager): مدير قاعدة البيانات
            quarantine_dir (str): مجلد الحجر الصحي
        """
        self.db_manager = db_manager
        self.quarantine_dir = quarantine_dir
        self.file_ops = FileOperations()
        self.system_analyzer = SystemAnalyzer()
        self.is_scanning = False
        self.scan_cancelled = False
        self.progress_callback = None
        
        # إنشاء مجلد الحجر الصحي
        os.makedirs(quarantine_dir, exist_ok=True)
    
    def set_progress_callback(self, callback: Callable[[int, str], None]):
        """
        تعيين دالة callback لتحديث التقدم
        
        Args:
            callback: دالة تستقبل النسبة المئوية والرسالة
        """
        self.progress_callback = callback
    
    def _update_progress(self, percentage: int, message: str):
        """تحديث التقدم"""
        if self.progress_callback:
            self.progress_callback(percentage, message)
    
    def scan_file(self, file_path: str) -> Dict:
        """
        فحص ملف واحد
        
        Args:
            file_path (str): مسار الملف
            
        Returns:
            Dict: نتيجة فحص الملف
        """
        result = {
            'file_path': file_path,
            'is_threat': False,
            'threat_name': None,
            'threat_level': 0,
            'scan_method': None,
            'action_taken': None
        }
        
        try:
            # التحقق من أمان فحص الملف
            if not self.file_ops.is_safe_to_scan(file_path):
                result['scan_method'] = 'تم تخطي الملف (غير آمن للفحص)'
                return result
            
            # المسح القائم على التوقيعات
            signature_result = self._signature_scan(file_path)
            if signature_result['is_threat']:
                result.update(signature_result)
                result['scan_method'] = 'مسح التوقيعات'
                return result
            
            # المسح السلوكي
            heuristic_result = self._heuristic_scan(file_path)
            if heuristic_result['is_threat']:
                result.update(heuristic_result)
                result['scan_method'] = 'المسح السلوكي'
                return result
            
            result['scan_method'] = 'نظيف'
            
        except Exception as e:
            result['scan_method'] = f'خطأ في الفحص: {str(e)}'
        
        return result
    
    def _signature_scan(self, file_path: str) -> Dict:
        """
        المسح القائم على التوقيعات
        
        Args:
            file_path (str): مسار الملف
            
        Returns:
            Dict: نتيجة المسح
        """
        result = {
            'is_threat': False,
            'threat_name': None,
            'threat_level': 0
        }
        
        try:
            # حساب تجزئة الملف
            file_hash = self.file_ops.calculate_file_hash(file_path, 'sha256')
            if not file_hash:
                return result
            
            # فحص التوقيع في قاعدة البيانات
            signature_info = self.db_manager.check_signature(file_hash)
            if signature_info:
                result['is_threat'] = True
                result['threat_name'] = signature_info['malware_name']
                result['threat_level'] = signature_info['threat_level']
        
        except Exception as e:
            print(f"خطأ في المسح القائم على التوقيعات: {e}")
        
        return result
    
    def _heuristic_scan(self, file_path: str) -> Dict:
        """
        المسح السلوكي والاستدلالي
        
        Args:
            file_path (str): مسار الملف
            
        Returns:
            Dict: نتيجة المسح
        """
        result = {
            'is_threat': False,
            'threat_name': None,
            'threat_level': 0
        }
        
        try:
            file_info = self.file_ops.get_file_info(file_path)
            filename = os.path.basename(file_path).lower()
            extension = file_info.get('extension', '').lower()
            
            suspicion_score = 0
            suspicion_reasons = []
            
            # فحص الامتداد المشبوه
            suspicious_extensions = ['.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js']
            if extension in suspicious_extensions:
                suspicion_score += 2
                suspicion_reasons.append(f"امتداد مشبوه: {extension}")
            
            # فحص الاسم المشبوه
            suspicious_names = [
                'crack', 'keygen', 'patch', 'hack', 'cheat', 'trojan',
                'virus', 'malware', 'backdoor', 'keylogger', 'rootkit'
            ]
            
            for sus_name in suspicious_names:
                if sus_name in filename:
                    suspicion_score += 3
                    suspicion_reasons.append(f"اسم مشبوه: {sus_name}")
                    break
            
            # فحص الحجم المشبوه
            file_size = file_info.get('size', 0)
            if extension == '.exe' and file_size < 10000:  # ملف تنفيذي صغير جداً
                suspicion_score += 2
                suspicion_reasons.append("حجم ملف تنفيذي صغير جداً")
            
            # فحص التاريخ المشبوه
            if file_info.get('created'):
                created_time = file_info['created']
                now = datetime.now()
                if (now - created_time).days < 1:  # ملف تم إنشاؤه حديثاً
                    suspicion_score += 1
                    suspicion_reasons.append("ملف تم إنشاؤه حديثاً")
            
            # تحديد مستوى التهديد بناءً على نقاط الشك
            if suspicion_score >= 5:
                result['is_threat'] = True
                result['threat_name'] = f"مشبوه.سلوكي ({', '.join(suspicion_reasons)})"
                result['threat_level'] = min(suspicion_score, 5)
            
        except Exception as e:
            print(f"خطأ في المسح السلوكي: {e}")
        
        return result
    
    def scan_directory(self, directory_path: str, recursive: bool = True) -> ScanResult:
        """
        فحص مجلد
        
        Args:
            directory_path (str): مسار المجلد
            recursive (bool): فحص المجلدات الفرعية
            
        Returns:
            ScanResult: نتيجة المسح
        """
        scan_result = ScanResult()
        start_time = datetime.now()
        
        try:
            self.is_scanning = True
            self.scan_cancelled = False
            
            # الحصول على قائمة الملفات
            if recursive:
                files = self.file_ops.scan_directory(directory_path)
            else:
                files = [os.path.join(directory_path, f) for f in os.listdir(directory_path)
                        if os.path.isfile(os.path.join(directory_path, f))]
            
            total_files = len(files)
            self._update_progress(0, f"بدء فحص {total_files} ملف...")
            
            for i, file_path in enumerate(files):
                if self.scan_cancelled:
                    scan_result.status = "تم الإلغاء"
                    break
                
                try:
                    # تحديث التقدم
                    progress = int((i / total_files) * 100)
                    self._update_progress(progress, f"فحص: {os.path.basename(file_path)}")
                    
                    # فحص الملف
                    file_result = self.scan_file(file_path)
                    scan_result.scanned_files += 1
                    
                    # تسجيل النتيجة
                    self.db_manager.log_scan_result(
                        file_path,
                        file_result.get('threat_name', 'نظيف'),
                        file_result['is_threat']
                    )
                    
                    # معالجة التهديد
                    if file_result['is_threat']:
                        scan_result.threats_found += 1
                        scan_result.threats.append(file_result)
                        
                        # نقل إلى الحجر الصحي
                        quarantine_path = self.file_ops.quarantine_file(
                            file_path, self.quarantine_dir
                        )
                        
                        if quarantine_path:
                            scan_result.quarantined_files += 1
                            file_result['action_taken'] = 'تم النقل للحجر الصحي'
                            
                            # تسجيل في قاعدة البيانات
                            self.db_manager.add_to_quarantine(
                                file_path,
                                quarantine_path,
                                file_result['threat_name']
                            )
                        else:
                            file_result['action_taken'] = 'فشل في النقل للحجر الصحي'
                
                except Exception as e:
                    scan_result.errors.append(f"خطأ في فحص {file_path}: {str(e)}")
            
            # حساب وقت المسح
            end_time = datetime.now()
            scan_result.scan_time = (end_time - start_time).total_seconds()
            
            self._update_progress(100, "اكتمل المسح")
            
        except Exception as e:
            scan_result.status = f"خطأ: {str(e)}"
            scan_result.errors.append(str(e))
        
        finally:
            self.is_scanning = False
        
        return scan_result
    
    def quick_scan(self) -> ScanResult:
        """
        مسح سريع للمجلدات المهمة
        
        Returns:
            ScanResult: نتيجة المسح السريع
        """
        # مجلدات المسح السريع
        quick_scan_dirs = [
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Documents"),
            "C:\\Windows\\Temp" if os.name == 'nt' else "/tmp",
        ]
        
        # فلترة المجلدات الموجودة فقط
        existing_dirs = [d for d in quick_scan_dirs if os.path.exists(d)]
        
        combined_result = ScanResult()
        start_time = datetime.now()
        
        for directory in existing_dirs:
            if self.scan_cancelled:
                break
            
            dir_result = self.scan_directory(directory, recursive=False)
            
            # دمج النتائج
            combined_result.scanned_files += dir_result.scanned_files
            combined_result.threats_found += dir_result.threats_found
            combined_result.quarantined_files += dir_result.quarantined_files
            combined_result.threats.extend(dir_result.threats)
            combined_result.errors.extend(dir_result.errors)
        
        end_time = datetime.now()
        combined_result.scan_time = (end_time - start_time).total_seconds()
        
        return combined_result
    
    def cancel_scan(self):
        """إلغاء المسح الحالي"""
        self.scan_cancelled = True
    
    def scan_running_processes(self) -> List[Dict]:
        """
        فحص العمليات الجارية
        
        Returns:
            List[Dict]: قائمة العمليات المشبوهة
        """
        return self.system_analyzer.analyze_running_processes()
    
    def scan_network_connections(self) -> List[Dict]:
        """
        فحص الاتصالات الشبكية
        
        Returns:
            List[Dict]: قائمة الاتصالات المشبوهة
        """
        return self.system_analyzer.analyze_network_connections()
