"""
عناصر واجهة المستخدم المخصصة لأداة Al-Sayyad
"""

from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
import pyqtgraph as pg
from datetime import datetime, timedelta
import random


class StatusIndicator(QWidget):
    """مؤشر حالة الحماية"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.protected = True
        self.setFixedSize(200, 200)
        
    def set_protection_status(self, protected: bool):
        """تعيين حالة الحماية"""
        self.protected = protected
        self.update()
    
    def paintEvent(self, event):
        """رسم مؤشر الحالة"""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # تحديد اللون بناءً على حالة الحماية
        if self.protected:
            color = QColor(46, 204, 113)  # أخضر
            text = "محمي"
            icon = "✓"
        else:
            color = QColor(231, 76, 60)   # أحمر
            text = "غير محمي"
            icon = "⚠"
        
        # رسم الدائرة الخارجية
        painter.setBrush(QBrush(color))
        painter.setPen(QPen(color.darker(120), 3))
        painter.drawEllipse(10, 10, 180, 180)
        
        # رسم الدائرة الداخلية
        inner_color = color.lighter(120)
        painter.setBrush(QBrush(inner_color))
        painter.setPen(QPen(inner_color, 2))
        painter.drawEllipse(30, 30, 140, 140)
        
        # رسم الأيقونة
        painter.setPen(QPen(Qt.white, 2))
        font = QFont("Arial", 36, QFont.Bold)
        painter.setFont(font)
        painter.drawText(QRect(0, 60, 200, 50), Qt.AlignCenter, icon)
        
        # رسم النص
        font = QFont("Arial", 14, QFont.Bold)
        painter.setFont(font)
        painter.drawText(QRect(0, 120, 200, 30), Qt.AlignCenter, text)


class ThreatChart(QWidget):
    """رسم بياني للتهديدات"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.threat_data = []
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_chart)
        self.update_timer.start(5000)  # تحديث كل 5 ثوان
        
    def setup_ui(self):
        """إعداد واجهة الرسم البياني"""
        layout = QVBoxLayout(self)
        
        # عنوان الرسم البياني
        title = QLabel("نشاط التهديدات - آخر 24 ساعة")
        title.setFont(QFont("Arial", 12, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        
        # الرسم البياني
        self.plot_widget = pg.PlotWidget()
        self.plot_widget.setBackground('white')
        self.plot_widget.setLabel('left', 'عدد التهديدات')
        self.plot_widget.setLabel('bottom', 'الوقت')
        self.plot_widget.showGrid(x=True, y=True)
        
        # تخصيص الألوان
        self.plot_widget.getAxis('left').setPen(pg.mkPen(color='black'))
        self.plot_widget.getAxis('bottom').setPen(pg.mkPen(color='black'))
        
        layout.addWidget(self.plot_widget)
        
        # إنشاء بيانات أولية
        self.generate_sample_data()
        self.update_chart()
    
    def generate_sample_data(self):
        """إنشاء بيانات عينة للرسم البياني"""
        now = datetime.now()
        self.threat_data = []
        
        for i in range(24):  # آخر 24 ساعة
            time_point = now - timedelta(hours=23-i)
            threat_count = random.randint(0, 10)  # عدد عشوائي من التهديدات
            self.threat_data.append({
                'time': time_point,
                'threats': threat_count
            })
    
    def update_chart(self):
        """تحديث الرسم البياني"""
        if not self.threat_data:
            return
        
        # تحضير البيانات للرسم
        x_data = list(range(len(self.threat_data)))
        y_data = [item['threats'] for item in self.threat_data]
        
        # مسح الرسم السابق
        self.plot_widget.clear()
        
        # رسم الخط
        pen = pg.mkPen(color=(231, 76, 60), width=3)
        self.plot_widget.plot(x_data, y_data, pen=pen, symbol='o', symbolBrush=(231, 76, 60))
        
        # تحديث تسميات المحور السيني
        x_labels = []
        for i, item in enumerate(self.threat_data):
            if i % 4 == 0:  # عرض كل 4 ساعات
                x_labels.append((i, item['time'].strftime('%H:%M')))
        
        if x_labels:
            self.plot_widget.getAxis('bottom').setTicks([x_labels])
    
    def add_threat_data(self, threat_count: int):
        """إضافة بيانات تهديد جديدة"""
        now = datetime.now()
        
        # إضافة البيانات الجديدة
        self.threat_data.append({
            'time': now,
            'threats': threat_count
        })
        
        # الاحتفاظ بآخر 24 نقطة فقط
        if len(self.threat_data) > 24:
            self.threat_data.pop(0)
        
        self.update_chart()


class QuickActionButton(QPushButton):
    """زر إجراء سريع مخصص"""
    
    def __init__(self, text: str, icon_text: str, color: str, parent=None):
        super().__init__(parent)
        self.setText(text)
        self.icon_text = icon_text
        self.color = color
        self.setup_style()
        
    def setup_style(self):
        """إعداد تنسيق الزر"""
        self.setFixedSize(150, 80)
        self.setFont(QFont("Arial", 10, QFont.Bold))
        
        style = f"""
        QPushButton {{
            background-color: {self.color};
            border: none;
            border-radius: 10px;
            color: white;
            padding: 10px;
        }}
        QPushButton:hover {{
            background-color: {self._darken_color(self.color)};
        }}
        QPushButton:pressed {{
            background-color: {self._darken_color(self.color, 0.8)};
        }}
        """
        self.setStyleSheet(style)
    
    def _darken_color(self, color: str, factor: float = 0.9) -> str:
        """تغميق اللون"""
        color = QColor(color)
        return color.darker(int(100/factor)).name()
    
    def paintEvent(self, event):
        """رسم الزر مع الأيقونة"""
        super().paintEvent(event)
        
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # رسم الأيقونة
        painter.setPen(QPen(Qt.white, 2))
        font = QFont("Arial", 20, QFont.Bold)
        painter.setFont(font)
        painter.drawText(QRect(0, 10, self.width(), 30), Qt.AlignCenter, self.icon_text)


class NotificationPanel(QWidget):
    """لوحة الإشعارات"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.notifications = []
        
    def setup_ui(self):
        """إعداد واجهة لوحة الإشعارات"""
        layout = QVBoxLayout(self)
        
        # عنوان اللوحة
        title = QLabel("الإشعارات الأخيرة")
        title.setFont(QFont("Arial", 12, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        
        # منطقة التمرير للإشعارات
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setMaximumHeight(200)
        
        self.notifications_widget = QWidget()
        self.notifications_layout = QVBoxLayout(self.notifications_widget)
        self.notifications_layout.setAlignment(Qt.AlignTop)
        
        scroll_area.setWidget(self.notifications_widget)
        layout.addWidget(scroll_area)
        
        # إضافة إشعارات عينة
        self.add_sample_notifications()
    
    def add_sample_notifications(self):
        """إضافة إشعارات عينة"""
        sample_notifications = [
            {"type": "threat", "message": "تم اكتشاف تهديد: Trojan.Win32.Agent", "time": "منذ 5 دقائق"},
            {"type": "scan", "message": "اكتمل المسح السريع - لم يتم العثور على تهديدات", "time": "منذ 15 دقيقة"},
            {"type": "update", "message": "تم تحديث قاعدة بيانات التوقيعات", "time": "منذ ساعة"},
            {"type": "info", "message": "تم بدء المراقبة في الوقت الفعلي", "time": "منذ ساعتين"}
        ]
        
        for notification in sample_notifications:
            self.add_notification(notification["type"], notification["message"], notification["time"])
    
    def add_notification(self, notification_type: str, message: str, time_str: str = None):
        """إضافة إشعار جديد"""
        if time_str is None:
            time_str = datetime.now().strftime("%H:%M")
        
        notification_widget = self.create_notification_widget(notification_type, message, time_str)
        self.notifications_layout.insertWidget(0, notification_widget)  # إضافة في الأعلى
        
        # الاحتفاظ بآخر 10 إشعارات فقط
        if self.notifications_layout.count() > 10:
            item = self.notifications_layout.takeAt(10)
            if item.widget():
                item.widget().deleteLater()
    
    def create_notification_widget(self, notification_type: str, message: str, time_str: str) -> QWidget:
        """إنشاء عنصر إشعار"""
        widget = QFrame()
        widget.setFrameStyle(QFrame.Box)
        widget.setMaximumHeight(60)
        
        layout = QHBoxLayout(widget)
        
        # أيقونة الإشعار
        icon_label = QLabel()
        icon_label.setFixedSize(30, 30)
        icon_label.setAlignment(Qt.AlignCenter)
        
        # تحديد الأيقونة واللون بناءً على نوع الإشعار
        if notification_type == "threat":
            icon_label.setText("⚠")
            icon_label.setStyleSheet("background-color: #e74c3c; color: white; border-radius: 15px; font-size: 16px; font-weight: bold;")
        elif notification_type == "scan":
            icon_label.setText("🔍")
            icon_label.setStyleSheet("background-color: #3498db; color: white; border-radius: 15px; font-size: 16px;")
        elif notification_type == "update":
            icon_label.setText("⬇")
            icon_label.setStyleSheet("background-color: #2ecc71; color: white; border-radius: 15px; font-size: 16px; font-weight: bold;")
        else:
            icon_label.setText("ℹ")
            icon_label.setStyleSheet("background-color: #95a5a6; color: white; border-radius: 15px; font-size: 16px; font-weight: bold;")
        
        layout.addWidget(icon_label)
        
        # نص الإشعار
        message_label = QLabel(message)
        message_label.setWordWrap(True)
        message_label.setFont(QFont("Arial", 9))
        layout.addWidget(message_label, 1)
        
        # وقت الإشعار
        time_label = QLabel(time_str)
        time_label.setFont(QFont("Arial", 8))
        time_label.setStyleSheet("color: #7f8c8d;")
        layout.addWidget(time_label)
        
        return widget


class StatisticsWidget(QWidget):
    """عنصر الإحصائيات"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        """إعداد واجهة الإحصائيات"""
        layout = QGridLayout(self)
        
        # إحصائيات عينة
        stats = [
            ("الملفات الممسوحة", "1,234", "#3498db"),
            ("التهديدات المكتشفة", "12", "#e74c3c"),
            ("الملفات المحجورة", "8", "#f39c12"),
            ("آخر تحديث", "اليوم", "#2ecc71")
        ]
        
        for i, (title, value, color) in enumerate(stats):
            stat_widget = self.create_stat_widget(title, value, color)
            row = i // 2
            col = i % 2
            layout.addWidget(stat_widget, row, col)
    
    def create_stat_widget(self, title: str, value: str, color: str) -> QWidget:
        """إنشاء عنصر إحصائية واحدة"""
        widget = QFrame()
        widget.setFrameStyle(QFrame.Box)
        widget.setStyleSheet(f"border: 2px solid {color}; border-radius: 10px; padding: 10px;")
        
        layout = QVBoxLayout(widget)
        
        # القيمة
        value_label = QLabel(value)
        value_label.setFont(QFont("Arial", 18, QFont.Bold))
        value_label.setAlignment(Qt.AlignCenter)
        value_label.setStyleSheet(f"color: {color}; border: none;")
        layout.addWidget(value_label)
        
        # العنوان
        title_label = QLabel(title)
        title_label.setFont(QFont("Arial", 10))
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("color: #2c3e50; border: none;")
        layout.addWidget(title_label)
        
        return widget
    
    def update_statistics(self, stats: dict):
        """تحديث الإحصائيات"""
        # في التطبيق الحقيقي، سيتم تحديث القيم من البيانات الفعلية
        pass
