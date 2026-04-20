import sys
import pefile
import math
from PyQt6.QtWidgets import (QApplication, QMainWindow, QLabel, QTextEdit, 
                             QVBoxLayout, QWidget, QTableWidget, QTableWidgetItem, QHeaderView)
from PyQt6.QtCore import Qt

class PEAnalyzerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("UIT Malware Analysis - PE Structure Tool")
        self.setFixedSize(800, 600)
        self.setAcceptDrops(True) # Kích hoạt tính năng nhận file kéo thả

        # Giao diện chính
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)

        # Khu vực hướng dẫn
        self.label = QLabel("KÉO VÀ THẢ FILE .EXE HOẶC .DLL VÀO ĐÂY")
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.label.setStyleSheet("""
            QLabel {
                border: 2px dashed #aaa;
                border-radius: 10px;
                font-size: 16px;
                color: #555;
                background-color: #f9f9f9;
            }
        """)
        self.layout.addWidget(self.label, 1)

        # Bảng hiển thị Section (DSA: Linked List/Array Output)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Section Name", "Raw Size", "Virtual Size", "Entropy"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.layout.addWidget(self.table, 2)

        # Khu vực log thông tin API
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setPlaceholderText("Thông tin chi tiết và API sẽ hiển thị ở đây...")
        self.layout.addWidget(self.log_output, 2)

    # --- XỬ LÝ KÉO THẢ ---
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event):
        files = [u.toLocalFile() for u in event.mimeData().urls()]
        if files:
            file_path = files[0]
            if file_path.lower().endswith(('.exe', '.dll', '.sys')):
                self.analyze_pe(file_path)
            else:
                self.log_output.setText("[-] Định dạng file không hỗ trợ!")

    # --- LOGIC PHÂN TÍCH (DSA TRỌNG TÂM) ---
    def calculate_entropy(self, data):
        if not data: return 0.0
        occurences = [0] * 256
        for byte in data: occurences[byte] += 1
        entropy = 0
        for x in occurences:
            if x > 0:
                p_x = float(x) / len(data)
                entropy -= p_x * math.log(p_x, 2)
        return entropy

    def analyze_pe(self, file_path):
        try:
            pe = pefile.PE(file_path)
            self.label.setText(f"Đang phân tích: {file_path.split('/')[-1]}")
            self.log_output.clear()
            
            # 1. Thông tin Header
            info = f"Entry Point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}\n"
            info += f"Image Base: {hex(pe.OPTIONAL_HEADER.ImageBase)}\n"
            info += "-"*30 + "\n"
            
            # 2. Xử lý Section & Entropy (Có thể áp dụng QuickSort ở đây)
            sections_data = []
            for section in pe.sections:
                name = section.Name.decode().strip('\x00')
                entropy = self.calculate_entropy(section.get_data())
                sections_data.append((name, section.SizeOfRawData, section.Misc_VirtualSize, entropy))

            # Hiển thị lên bảng
            self.table.setRowCount(0)
            for row_data in sections_data:
                row_idx = self.table.rowCount()
                self.table.insertRow(row_idx)
                for i, val in enumerate(row_data):
                    item = QTableWidgetItem(str(val) if i < 3 else f"{val:.4f}")
                    # Cảnh báo Entropy cao (DSA logic)
                    if i == 3 and val > 7.0:
                        item.setForeground(Qt.GlobalColor.red)
                        item.setText(f"{val:.4f} [!]")
                    self.table.setItem(row_idx, i, item)

            # 3. Import API (Cần áp dụng Hash Table tra cứu mã độc ở đây)
            info += "Imported DLLs & APIs:\n"
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    info += f"+ {entry.dll.decode()}\n"
            
            self.log_output.setText(info)

        except Exception as e:
            self.log_output.setText(f"[-] Lỗi phân tích: {str(e)}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PEAnalyzerApp()
    window.show()
    sys.exit(app.exec())
