"""
محلل النظام لأداة Al-Sayyad
يحلل سلوك النظام والعمليات للكشف عن التهديدات
"""

import psutil
import os
from typing import List, Dict, Optional
from datetime import datetime


class SystemAnalyzer:
    """محلل النظام والعمليات"""
    
    def __init__(self):
        """تهيئة محلل النظام"""
        self.suspicious_processes = []
        self.suspicious_network_connections = []
    
    def analyze_running_processes(self) -> List[Dict]:
        """
        تحليل العمليات الجارية
        
        Returns:
            List[Dict]: قائمة العمليات المشبوهة
        """
        suspicious_processes = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'cpu_percent', 'memory_percent']):
                try:
                    proc_info = proc.info
                    
                    # فحص العمليات المشبوهة
                    if self._is_suspicious_process(proc_info):
                        suspicious_processes.append({
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'exe': proc_info['exe'],
                            'cmdline': ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else '',
                            'cpu_percent': proc_info['cpu_percent'],
                            'memory_percent': proc_info['memory_percent'],
                            'suspicion_reason': self._get_suspicion_reason(proc_info)
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception as e:
            print(f"خطأ في تحليل العمليات: {e}")
        
        return suspicious_processes
    
    def _is_suspicious_process(self, proc_info: Dict) -> bool:
        """
        فحص ما إذا كانت العملية مشبوهة
        
        Args:
            proc_info (Dict): معلومات العملية
            
        Returns:
            bool: True إذا كانت العملية مشبوهة
        """
        name = proc_info.get('name', '').lower()
        exe = proc_info.get('exe', '').lower() if proc_info.get('exe') else ''
        cmdline = ' '.join(proc_info.get('cmdline', [])).lower()
        
        # أسماء عمليات مشبوهة
        suspicious_names = [
            'keylogger', 'trojan', 'virus', 'malware', 'backdoor',
            'rootkit', 'spyware', 'adware', 'ransomware', 'miner'
        ]
        
        # مسارات مشبوهة
        suspicious_paths = [
            'temp', 'appdata\\roaming', 'programdata', '%temp%'
        ]
        
        # أوامر مشبوهة
        suspicious_commands = [
            'powershell -enc', 'cmd /c', 'wscript', 'cscript',
            'regsvr32', 'rundll32', 'certutil -decode'
        ]
        
        # فحص الاسم
        for sus_name in suspicious_names:
            if sus_name in name:
                return True
        
        # فحص المسار
        for sus_path in suspicious_paths:
            if sus_path in exe:
                return True
        
        # فحص الأوامر
        for sus_cmd in suspicious_commands:
            if sus_cmd in cmdline:
                return True
        
        # فحص استهلاك الموارد العالي
        cpu_percent = proc_info.get('cpu_percent', 0)
        memory_percent = proc_info.get('memory_percent', 0)
        
        if cpu_percent > 80 or memory_percent > 50:
            return True
        
        return False
    
    def _get_suspicion_reason(self, proc_info: Dict) -> str:
        """
        الحصول على سبب الشك في العملية
        
        Args:
            proc_info (Dict): معلومات العملية
            
        Returns:
            str: سبب الشك
        """
        reasons = []
        
        name = proc_info.get('name', '').lower()
        exe = proc_info.get('exe', '').lower() if proc_info.get('exe') else ''
        cmdline = ' '.join(proc_info.get('cmdline', [])).lower()
        cpu_percent = proc_info.get('cpu_percent', 0)
        memory_percent = proc_info.get('memory_percent', 0)
        
        if any(sus in name for sus in ['keylogger', 'trojan', 'virus', 'malware']):
            reasons.append("اسم مشبوه")
        
        if any(sus in exe for sus in ['temp', 'appdata']):
            reasons.append("مسار مشبوه")
        
        if any(sus in cmdline for sus in ['powershell -enc', 'cmd /c']):
            reasons.append("أوامر مشبوهة")
        
        if cpu_percent > 80:
            reasons.append("استهلاك عالي للمعالج")
        
        if memory_percent > 50:
            reasons.append("استهلاك عالي للذاكرة")
        
        return ", ".join(reasons) if reasons else "نشاط غير طبيعي"
    
    def analyze_network_connections(self) -> List[Dict]:
        """
        تحليل الاتصالات الشبكية
        
        Returns:
            List[Dict]: قائمة الاتصالات المشبوهة
        """
        suspicious_connections = []
        
        try:
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if self._is_suspicious_connection(conn):
                    try:
                        proc = psutil.Process(conn.pid) if conn.pid else None
                        proc_name = proc.name() if proc else "غير معروف"
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_name = "غير معروف"
                    
                    suspicious_connections.append({
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "غير معروف",
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "غير معروف",
                        'status': conn.status,
                        'pid': conn.pid,
                        'process_name': proc_name,
                        'suspicion_reason': self._get_connection_suspicion_reason(conn)
                    })
        except Exception as e:
            print(f"خطأ في تحليل الاتصالات الشبكية: {e}")
        
        return suspicious_connections
    
    def _is_suspicious_connection(self, conn) -> bool:
        """
        فحص ما إذا كان الاتصال مشبوهاً
        
        Args:
            conn: معلومات الاتصال
            
        Returns:
            bool: True إذا كان الاتصال مشبوهاً
        """
        if not conn.raddr:
            return False
        
        # منافذ مشبوهة
        suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337]
        
        # عناوين IP مشبوهة (أمثلة)
        suspicious_ips = ['0.0.0.0', '127.0.0.1']
        
        remote_port = conn.raddr.port
        remote_ip = conn.raddr.ip
        
        # فحص المنافذ المشبوهة
        if remote_port in suspicious_ports:
            return True
        
        # فحص عناوين IP المشبوهة
        if remote_ip in suspicious_ips:
            return True
        
        # فحص الاتصالات الخارجية على منافذ غير شائعة
        if remote_port > 49152 and not remote_ip.startswith('192.168.'):
            return True
        
        return False
    
    def _get_connection_suspicion_reason(self, conn) -> str:
        """
        الحصول على سبب الشك في الاتصال
        
        Args:
            conn: معلومات الاتصال
            
        Returns:
            str: سبب الشك
        """
        if not conn.raddr:
            return "اتصال محلي"
        
        remote_port = conn.raddr.port
        remote_ip = conn.raddr.ip
        
        if remote_port in [4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337]:
            return "منفذ مشبوه"
        
        if remote_ip in ['0.0.0.0', '127.0.0.1']:
            return "عنوان IP مشبوه"
        
        if remote_port > 49152:
            return "منفذ غير شائع"
        
        return "نشاط شبكي غير طبيعي"
    
    def get_system_info(self) -> Dict:
        """
        الحصول على معلومات النظام
        
        Returns:
            Dict: معلومات النظام
        """
        try:
            return {
                'cpu_count': psutil.cpu_count(),
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory_total': psutil.virtual_memory().total,
                'memory_available': psutil.virtual_memory().available,
                'memory_percent': psutil.virtual_memory().percent,
                'disk_usage': {
                    'total': psutil.disk_usage('/').total,
                    'used': psutil.disk_usage('/').used,
                    'free': psutil.disk_usage('/').free,
                    'percent': psutil.disk_usage('/').percent
                },
                'boot_time': datetime.fromtimestamp(psutil.boot_time()),
                'process_count': len(psutil.pids())
            }
        except Exception as e:
            print(f"خطأ في الحصول على معلومات النظام: {e}")
            return {}
    
    def monitor_file_access(self, file_path: str) -> Dict:
        """
        مراقبة الوصول للملف
        
        Args:
            file_path (str): مسار الملف
            
        Returns:
            Dict: معلومات الوصول للملف
        """
        try:
            processes_accessing = []
            
            for proc in psutil.process_iter(['pid', 'name', 'open_files']):
                try:
                    if proc.info['open_files']:
                        for file_info in proc.info['open_files']:
                            if file_info.path == file_path:
                                processes_accessing.append({
                                    'pid': proc.info['pid'],
                                    'name': proc.info['name'],
                                    'mode': file_info.mode
                                })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            return {
                'file_path': file_path,
                'accessing_processes': processes_accessing,
                'access_count': len(processes_accessing)
            }
        except Exception as e:
            print(f"خطأ في مراقبة الوصول للملف: {e}")
            return {}
