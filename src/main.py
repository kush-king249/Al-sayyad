#!/usr/bin/env python3
"""
Al-Sayyad - أداة مكافحة الفيروسات المتقدمة
نقطة الدخول الرئيسية للتطبيق

المؤلف: Hassan Mohamed Hassan Ahmed
GitHub: kush-king249
"""

import sys
import os
from PyQt5.QtWidgets import QApplication, QMessageBox, QSplashScreen
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QPixmap, QPainter, QFont, QColor

# إضافة مسار المشروع إلى sys.path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from src.gui.main_window import MainWindow


class SplashScreen(QSplashScreen):
    """شاشة البداية للتطبيق"""
    
    def __init__(self):
        # إنشاء صورة شاشة البداية
        pixmap = QPixmap(400, 300)
        pixmap.fill(QColor(52, 73, 94))  # لون خلفية داكن
        
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # رسم العنوان
        painter.setPen(QColor(255, 255, 255))
        title_font = QFont("Arial", 28, QFont.Bold)
        painter.setFont(title_font)
        painter.drawText(pixmap.rect(), Qt.AlignCenter, "Al-Sayyad")
        
        # رسم العنوان الفرعي
        subtitle_font = QFont("Arial", 12)
        painter.setFont(subtitle_font)
        painter.drawText(50, 180, "أداة مكافحة الفيروسات المتقدمة")
        
        # رسم اسم المؤلف
        author_font = QFont("Arial", 10)
        painter.setFont(author_font)
        painter.setPen(QColor(189, 195, 199))
        painter.drawText(50, 200, "by Hassan Mohamed Hassan Ahmed")
        
        # رسم معلومات التحميل
        painter.drawText(50, 250, "جاري التحميل...")
        
        painter.end()
        
        super().__init__(pixmap)
        self.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.FramelessWindowHint)
        
        # إعداد مؤقت لإغلاق شاشة البداية
        self.timer = QTimer()
        self.timer.timeout.connect(self.close)
        self.timer.start(3000)  # 3 ثوان


def check_dependencies():
    """فحص المكتبات المطلوبة"""
    required_modules = [
        'PyQt5',
        'watchdog',
        'psutil',
        'pyqtgraph'
    ]
    
    missing_modules = []
    
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing_modules.append(module)
    
    if missing_modules:
        error_msg = f"""
        المكتبات التالية مطلوبة ولكنها غير مثبتة:
        {', '.join(missing_modules)}
        
        يرجى تثبيتها باستخدام:
        pip install {' '.join(missing_modules)}
        """
        return False, error_msg
    
    return True, ""


def setup_application():
    """إعداد التطبيق"""
    app = QApplication(sys.argv)
    
    # إعداد معلومات التطبيق
    app.setApplicationName("Al-Sayyad")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("Hassan Mohamed Hassan Ahmed")
    app.setOrganizationDomain("github.com/kush-king249")
    
    # إعداد الخط الافتراضي للعربية
    font = QFont("Arial", 10)
    app.setFont(font)
    
    return app


def main():
    """الدالة الرئيسية"""
    try:
        # فحص المكتبات المطلوبة
        deps_ok, error_msg = check_dependencies()
        if not deps_ok:
            print(error_msg)
            sys.exit(1)
        
        # إعداد التطبيق
        app = setup_application()
        
        # عرض شاشة البداية
        splash = SplashScreen()
        splash.show()
        
        # معالجة الأحداث لعرض شاشة البداية
        app.processEvents()
        
        # إنشاء النافذة الرئيسية
        try:
            main_window = MainWindow()
            
            # إغلاق شاشة البداية وعرض النافذة الرئيسية
            def show_main_window():
                splash.close()
                main_window.show()
            
            QTimer.singleShot(3000, show_main_window)
            
            # بدء حلقة الأحداث
            sys.exit(app.exec_())
            
        except Exception as e:
            splash.close()
            QMessageBox.critical(
                None, 
                "خطأ في بدء التطبيق",
                f"حدث خطأ أثناء بدء التطبيق:\n{str(e)}\n\n"
                "يرجى التأكد من تثبيت جميع المكتبات المطلوبة."
            )
            sys.exit(1)
    
    except KeyboardInterrupt:
        print("\nتم إيقاف التطبيق بواسطة المستخدم")
        sys.exit(0)
    
    except Exception as e:
        print(f"خطأ غير متوقع: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
