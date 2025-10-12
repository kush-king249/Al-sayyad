"""
النافذة الرئيسية لأداة Al-Sayyad
"""

import sys
import os
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
import threading

from .ui_elements import StatusIndicator, ThreatChart, QuickActionButton, NotificationPanel, StatisticsWidget
from ..core.database_manager import DatabaseManager
from ..core.scanner import AntivirusScanner
from ..core.real_time_monitor import RealTimeMonitor
from ..core.updater import SignatureUpdater


class ScanProgressDialog(QDialog):
    """نافذة تقدم المسح"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("جاري المسح...")
        self.setFixedSize(400, 150)
        self.setModal(True)
        
        layout = QVBoxLayout(self)
        
        # شريط التقدم
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        layout.addWidget(self.progress_bar)
        
        # رسالة التقدم
        self.progress_label = QLabel("بدء المسح...")
        self.progress_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.progress_label)
        
        # زر الإلغاء
        self.cancel_button = QPushButton("إلغاء")
        self.cancel_button.clicked.connect(self.reject)
        layout.addWidget(self.cancel_button)
    
    def update_progress(self, percentage: int, message: str):
        """تحديث التقدم"""
        self.progress_bar.setValue(percentage)
        self.progress_label.setText(message)


class ScanResultDialog(QDialog):
    """نافذة نتائج المسح"""
    
    def __init__(self, scan_result, parent=None):
        super().__init__(parent)
        self.scan_result = scan_result
        self.setWindowTitle("نتائج المسح")
        self.setFixedSize(600, 400)
        self.setup_ui()
    
    def setup_ui(self):
        """إعداد واجهة نتائج المسح"""
        layout = QVBoxLayout(self)
        
        # ملخص النتائج
        summary_group = QGroupBox("ملخص النتائج")
        summary_layout = QGridLayout(summary_group)
        
        summary_layout.addWidget(QLabel("الملفات الممسوحة:"), 0, 0)
        summary_layout.addWidget(QLabel(str(self.scan_result.scanned_files)), 0, 1)
        
        summary_layout.addWidget(QLabel("التهديدات المكتشفة:"), 1, 0)
        summary_layout.addWidget(QLabel(str(self.scan_result.threats_found)), 1, 1)
        
        summary_layout.addWidget(QLabel("الملفات المحجورة:"), 2, 0)
        summary_layout.addWidget(QLabel(str(self.scan_result.quarantined_files)), 2, 1)
        
        summary_layout.addWidget(QLabel("وقت المسح:"), 3, 0)
        summary_layout.addWidget(QLabel(f"{self.scan_result.scan_time:.2f} ثانية"), 3, 1)
        
        layout.addWidget(summary_group)
        
        # قائمة التهديدات
        if self.scan_result.threats:
            threats_group = QGroupBox("التهديدات المكتشفة")
            threats_layout = QVBoxLayout(threats_group)
            
            threats_table = QTableWidget()
            threats_table.setColumnCount(4)
            threats_table.setHorizontalHeaderLabels(["الملف", "التهديد", "المستوى", "الإجراء"])
            threats_table.setRowCount(len(self.scan_result.threats))
            
            for i, threat in enumerate(self.scan_result.threats):
                threats_table.setItem(i, 0, QTableWidgetItem(os.path.basename(threat['file_path'])))
                threats_table.setItem(i, 1, QTableWidgetItem(threat['threat_name']))
                threats_table.setItem(i, 2, QTableWidgetItem(str(threat['threat_level'])))
                threats_table.setItem(i, 3, QTableWidgetItem(threat.get('action_taken', 'لا يوجد')))
            
            threats_table.resizeColumnsToContents()
            threats_layout.addWidget(threats_table)
            layout.addWidget(threats_group)
        
        # أزرار الإجراءات
        buttons_layout = QHBoxLayout()
        
        close_button = QPushButton("إغلاق")
        close_button.clicked.connect(self.accept)
        buttons_layout.addWidget(close_button)
        
        if self.scan_result.quarantined_files > 0:
            quarantine_button = QPushButton("عرض الحجر الصحي")
            quarantine_button.clicked.connect(self.show_quarantine)
            buttons_layout.addWidget(quarantine_button)
        
        layout.addLayout(buttons_layout)
    
    def show_quarantine(self):
        """عرض نافذة الحجر الصحي"""
        # سيتم تنفيذها لاحقاً
        QMessageBox.information(self, "الحجر الصحي", "سيتم إضافة نافذة الحجر الصحي قريباً")


class MainWindow(QMainWindow):
    """النافذة الرئيسية للتطبيق"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Al-Sayyad - أداة مكافحة الفيروسات المتقدمة")
        self.setGeometry(100, 100, 1200, 800)
        self.setMinimumSize(1000, 700)
        
        # تهيئة المكونات الأساسية
        self.db_manager = DatabaseManager()
        self.scanner = AntivirusScanner(self.db_manager)
        self.real_time_monitor = RealTimeMonitor(self.scanner, self.db_manager)
        self.updater = SignatureUpdater(self.db_manager)
        
        # إعداد callbacks
        self.scanner.set_progress_callback(self.update_scan_progress)
        self.real_time_monitor.set_threat_callback(self.handle_real_time_threat)
        self.updater.set_update_callback(self.update_progress_callback)
        
        # متغيرات الحالة
        self.scan_progress_dialog = None
        self.current_scan_thread = None
        
        self.setup_ui()
        self.setup_menu_bar()
        self.setup_status_bar()
        
        # بدء المراقبة في الوقت الفعلي
        self.real_time_monitor.start_monitoring()
        
        # تطبيق التنسيق العربي
        self.apply_arabic_styling()
    
    def setup_ui(self):
        """إعداد واجهة المستخدم الرئيسية"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # التخطيط الرئيسي
        main_layout = QVBoxLayout(central_widget)
        
        # شريط العنوان مع اسم المؤلف
        header_layout = QHBoxLayout()
        
        title_label = QLabel("Al-Sayyad")
        title_label.setFont(QFont("Arial", 24, QFont.Bold))
        title_label.setStyleSheet("color: #2c3e50; margin: 10px;")
        header_layout.addWidget(title_label)
        
        author_label = QLabel("by Hassan")
        author_label.setFont(QFont("Arial", 12))
        author_label.setStyleSheet("color: #7f8c8d; margin: 10px;")
        header_layout.addWidget(author_label)
        
        header_layout.addStretch()
        main_layout.addLayout(header_layout)
        
        # التخطيط الأفقي للمحتوى الرئيسي
        content_layout = QHBoxLayout()
        
        # العمود الأيسر - مؤشر الحالة والإجراءات
        left_column = QVBoxLayout()
        
        # مؤشر حالة الحماية
        protection_group = QGroupBox("حالة الحماية")
        protection_layout = QVBoxLayout(protection_group)
        
        self.status_indicator = StatusIndicator()
        protection_layout.addWidget(self.status_indicator, alignment=Qt.AlignCenter)
        
        left_column.addWidget(protection_group)
        
        # أزرار الإجراءات السريعة
        actions_group = QGroupBox("الإجراءات السريعة")
        actions_layout = QGridLayout(actions_group)
        
        self.quick_scan_btn = QuickActionButton("مسح سريع", "🔍", "#3498db")
        self.quick_scan_btn.clicked.connect(self.start_quick_scan)
        actions_layout.addWidget(self.quick_scan_btn, 0, 0)
        
        self.full_scan_btn = QuickActionButton("مسح كامل", "🔎", "#e74c3c")
        self.full_scan_btn.clicked.connect(self.start_full_scan)
        actions_layout.addWidget(self.full_scan_btn, 0, 1)
        
        self.update_btn = QuickActionButton("تحديث", "⬇", "#2ecc71")
        self.update_btn.clicked.connect(self.start_update)
        actions_layout.addWidget(self.update_btn, 1, 0)
        
        self.quarantine_btn = QuickActionButton("الحجر الصحي", "🛡", "#f39c12")
        self.quarantine_btn.clicked.connect(self.show_quarantine)
        actions_layout.addWidget(self.quarantine_btn, 1, 1)
        
        left_column.addWidget(actions_group)
        
        # الإحصائيات
        stats_group = QGroupBox("الإحصائيات")
        stats_layout = QVBoxLayout(stats_group)
        
        self.statistics_widget = StatisticsWidget()
        stats_layout.addWidget(self.statistics_widget)
        
        left_column.addWidget(stats_group)
        
        content_layout.addLayout(left_column, 1)
        
        # العمود الأيمن - الرسوم البيانية والإشعارات
        right_column = QVBoxLayout()
        
        # الرسم البياني للتهديدات
        chart_group = QGroupBox("مراقبة التهديدات")
        chart_layout = QVBoxLayout(chart_group)
        
        self.threat_chart = ThreatChart()
        chart_layout.addWidget(self.threat_chart)
        
        right_column.addWidget(chart_group)
        
        # لوحة الإشعارات
        notifications_group = QGroupBox("الإشعارات")
        notifications_layout = QVBoxLayout(notifications_group)
        
        self.notification_panel = NotificationPanel()
        notifications_layout.addWidget(self.notification_panel)
        
        right_column.addWidget(notifications_group)
        
        content_layout.addLayout(right_column, 1)
        
        main_layout.addLayout(content_layout)
    
    def setup_menu_bar(self):
        """إعداد شريط القوائم"""
        menubar = self.menuBar()
        
        # قائمة الملف
        file_menu = menubar.addMenu('ملف')
        
        scan_action = QAction('مسح مجلد...', self)
        scan_action.triggered.connect(self.scan_custom_directory)
        file_menu.addAction(scan_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction('خروج', self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # قائمة الأدوات
        tools_menu = menubar.addMenu('أدوات')
        
        settings_action = QAction('الإعدادات', self)
        settings_action.triggered.connect(self.show_settings)
        tools_menu.addAction(settings_action)
        
        logs_action = QAction('سجلات المسح', self)
        logs_action.triggered.connect(self.show_scan_logs)
        tools_menu.addAction(logs_action)
        
        # قائمة المساعدة
        help_menu = menubar.addMenu('مساعدة')
        
        about_action = QAction('حول البرنامج', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def setup_status_bar(self):
        """إعداد شريط الحالة"""
        self.status_bar = self.statusBar()
        
        # حالة المراقبة في الوقت الفعلي
        self.monitoring_status = QLabel("المراقبة في الوقت الفعلي: نشطة")
        self.monitoring_status.setStyleSheet("color: #2ecc71; font-weight: bold;")
        self.status_bar.addPermanentWidget(self.monitoring_status)
        
        # آخر تحديث
        self.last_update_status = QLabel("آخر تحديث: اليوم")
        self.status_bar.addPermanentWidget(self.last_update_status)
    
    def apply_arabic_styling(self):
        """تطبيق التنسيق العربي"""
        # تعيين اتجاه النص للعربية
        self.setLayoutDirection(Qt.RightToLeft)
        
        # تطبيق تنسيق عام
        self.setStyleSheet("""
            QMainWindow {
                background-color: #ecf0f1;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #bdc3c7;
                border-radius: 10px;
                margin-top: 10px;
                padding-top: 10px;
                background-color: white;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                background-color: white;
            }
            QPushButton {
                font-weight: bold;
                border-radius: 5px;
                padding: 5px;
            }
            QTableWidget {
                gridline-color: #bdc3c7;
                background-color: white;
            }
            QHeaderView::section {
                background-color: #34495e;
                color: white;
                padding: 5px;
                font-weight: bold;
            }
        """)
    
    def start_quick_scan(self):
        """بدء المسح السريع"""
        self.start_scan_thread(self.scanner.quick_scan, "المسح السريع")
    
    def start_full_scan(self):
        """بدء المسح الكامل"""
        # اختيار مجلد للمسح الكامل
        directory = QFileDialog.getExistingDirectory(self, "اختر مجلد للمسح الكامل")
        if directory:
            scan_func = lambda: self.scanner.scan_directory(directory, recursive=True)
            self.start_scan_thread(scan_func, "المسح الكامل")
    
    def scan_custom_directory(self):
        """مسح مجلد مخصص"""
        directory = QFileDialog.getExistingDirectory(self, "اختر مجلد للمسح")
        if directory:
            scan_func = lambda: self.scanner.scan_directory(directory, recursive=True)
            self.start_scan_thread(scan_func, f"مسح المجلد: {os.path.basename(directory)}")
    
    def start_scan_thread(self, scan_function, scan_type):
        """بدء thread للمسح"""
        if self.current_scan_thread and self.current_scan_thread.is_alive():
            QMessageBox.warning(self, "تحذير", "يوجد مسح قيد التشغيل بالفعل")
            return
        
        # إنشاء نافذة التقدم
        self.scan_progress_dialog = ScanProgressDialog(self)
        self.scan_progress_dialog.setWindowTitle(f"جاري {scan_type}...")
        
        # بدء thread المسح
        self.current_scan_thread = threading.Thread(
            target=self.run_scan,
            args=(scan_function, scan_type)
        )
        self.current_scan_thread.daemon = True
        self.current_scan_thread.start()
        
        # عرض نافذة التقدم
        if self.scan_progress_dialog.exec_() == QDialog.Rejected:
            self.scanner.cancel_scan()
    
    def run_scan(self, scan_function, scan_type):
        """تشغيل المسح في thread منفصل"""
        try:
            result = scan_function()
            
            # إغلاق نافذة التقدم
            QTimer.singleShot(0, self.scan_progress_dialog.accept)
            
            # عرض النتائج
            QTimer.singleShot(100, lambda: self.show_scan_results(result, scan_type))
            
            # إضافة إشعار
            if result.threats_found > 0:
                QTimer.singleShot(200, lambda: self.notification_panel.add_notification(
                    "threat", f"تم اكتشاف {result.threats_found} تهديد في {scan_type}"
                ))
            else:
                QTimer.singleShot(200, lambda: self.notification_panel.add_notification(
                    "scan", f"اكتمل {scan_type} - لم يتم العثور على تهديدات"
                ))
        
        except Exception as e:
            QTimer.singleShot(0, self.scan_progress_dialog.reject)
            QTimer.singleShot(100, lambda: QMessageBox.critical(
                self, "خطأ في المسح", f"حدث خطأ أثناء المسح: {str(e)}"
            ))
    
    def update_scan_progress(self, percentage: int, message: str):
        """تحديث تقدم المسح"""
        if self.scan_progress_dialog:
            QTimer.singleShot(0, lambda: self.scan_progress_dialog.update_progress(percentage, message))
    
    def show_scan_results(self, scan_result, scan_type):
        """عرض نتائج المسح"""
        dialog = ScanResultDialog(scan_result, self)
        dialog.exec_()
    
    def start_update(self):
        """بدء تحديث قاعدة البيانات"""
        # فحص التحديثات أولاً
        update_info = self.updater.check_for_updates()
        
        if update_info.get('updates_available'):
            reply = QMessageBox.question(
                self, "تحديثات متاحة",
                f"يوجد {update_info.get('new_signatures', 0)} توقيع جديد متاح.\n"
                f"حجم التحديث: {update_info.get('update_size', 'غير معروف')}\n\n"
                "هل تريد تحميل التحديثات؟",
                QMessageBox.Yes | QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                # بدء التحديث في thread منفصل
                update_thread = threading.Thread(target=self.run_update)
                update_thread.daemon = True
                update_thread.start()
        else:
            QMessageBox.information(self, "التحديثات", "قاعدة البيانات محدثة بالفعل")
    
    def run_update(self):
        """تشغيل التحديث"""
        success = self.updater.download_updates()
        
        if success:
            QTimer.singleShot(0, lambda: self.notification_panel.add_notification(
                "update", "تم تحديث قاعدة بيانات التوقيعات بنجاح"
            ))
            QTimer.singleShot(100, lambda: QMessageBox.information(
                self, "التحديث", "تم تحديث قاعدة البيانات بنجاح"
            ))
        else:
            QTimer.singleShot(0, lambda: QMessageBox.critical(
                self, "خطأ في التحديث", "فشل في تحديث قاعدة البيانات"
            ))
    
    def update_progress_callback(self, message: str, percentage: int):
        """callback لتحديث التقدم"""
        # يمكن إضافة شريط تقدم للتحديث هنا
        pass
    
    def show_quarantine(self):
        """عرض نافذة الحجر الصحي"""
        quarantined_files = self.db_manager.get_quarantined_files()
        
        if not quarantined_files:
            QMessageBox.information(self, "الحجر الصحي", "لا توجد ملفات في الحجر الصحي")
            return
        
        # إنشاء نافذة الحجر الصحي
        dialog = QDialog(self)
        dialog.setWindowTitle("الحجر الصحي")
        dialog.setFixedSize(700, 400)
        
        layout = QVBoxLayout(dialog)
        
        # جدول الملفات المحجورة
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["الملف الأصلي", "التهديد", "تاريخ الحجر", "الإجراءات"])
        table.setRowCount(len(quarantined_files))
        
        for i, file_info in enumerate(quarantined_files):
            table.setItem(i, 0, QTableWidgetItem(os.path.basename(file_info['original_path'])))
            table.setItem(i, 1, QTableWidgetItem(file_info['threat_name']))
            table.setItem(i, 2, QTableWidgetItem(file_info['quarantine_time']))
            
            # أزرار الإجراءات
            actions_widget = QWidget()
            actions_layout = QHBoxLayout(actions_widget)
            
            restore_btn = QPushButton("استعادة")
            delete_btn = QPushButton("حذف")
            
            actions_layout.addWidget(restore_btn)
            actions_layout.addWidget(delete_btn)
            
            table.setCellWidget(i, 3, actions_widget)
        
        table.resizeColumnsToContents()
        layout.addWidget(table)
        
        # زر الإغلاق
        close_btn = QPushButton("إغلاق")
        close_btn.clicked.connect(dialog.accept)
        layout.addWidget(close_btn)
        
        dialog.exec_()
    
    def handle_real_time_threat(self, threat_info):
        """معالجة التهديدات في الوقت الفعلي"""
        QTimer.singleShot(0, lambda: self.notification_panel.add_notification(
            "threat", f"تهديد في الوقت الفعلي: {threat_info['threat_name']}"
        ))
        
        # تحديث الرسم البياني
        QTimer.singleShot(0, lambda: self.threat_chart.add_threat_data(1))
    
    def show_settings(self):
        """عرض نافذة الإعدادات"""
        QMessageBox.information(self, "الإعدادات", "سيتم إضافة نافذة الإعدادات قريباً")
    
    def show_scan_logs(self):
        """عرض سجلات المسح"""
        QMessageBox.information(self, "سجلات المسح", "سيتم إضافة نافذة سجلات المسح قريباً")
    
    def show_about(self):
        """عرض معلومات البرنامج"""
        about_text = """
        <h2>Al-Sayyad</h2>
        <p><b>أداة مكافحة الفيروسات المتقدمة</b></p>
        <p>by Hassan Mohamed Hassan Ahmed</p>
        <br>
        <p>الإصدار: 1.0.0</p>
        <p>تاريخ الإصدار: 2024</p>
        <br>
        <p>أداة شاملة لمكافحة الفيروسات تجمع بين:</p>
        <ul>
        <li>المسح القائم على التوقيعات</li>
        <li>المسح السلوكي والاستدلالي</li>
        <li>المراقبة في الوقت الفعلي</li>
        <li>واجهة مستخدم عربية احترافية</li>
        </ul>
        """
        
        QMessageBox.about(self, "حول Al-Sayyad", about_text)
    
    def closeEvent(self, event):
        """معالجة إغلاق التطبيق"""
        # إيقاف المراقبة في الوقت الفعلي
        self.real_time_monitor.stop_monitoring()
        
        # إلغاء أي مسح قيد التشغيل
        if self.current_scan_thread and self.current_scan_thread.is_alive():
            self.scanner.cancel_scan()
        
        event.accept()
