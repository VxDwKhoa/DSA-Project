import sys
import pefile
import math
from PyQt6.QtWidgets import (QApplication, QMainWindow, QLabel, QTextEdit, 
                             QVBoxLayout, QWidget, QTableWidget, QTableWidgetItem, QHeaderView)
from PyQt6.QtCore import Qt


class PEAnalyzerApp(QMainWindow):
    """
    Lớp điều khiển giao diện chính của ứng dụng phân tích tệp thực thi PE.

    Chức năng:
    - Khởi tạo GUI bằng PyQt6
    - Hỗ trợ kéo thả file PE
    - Phân tích cấu trúc PE và hiển thị kết quả
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle("UIT Malware Analysis - PE Structure Tool")
        self.setFixedSize(800, 600)
        self.setAcceptDrops(True)

        # Giao diện chính
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)

        # Label hướng dẫn
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

        # Bảng Section
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Section Name", "Raw Size", "Virtual Size", "Entropy"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.layout.addWidget(self.table, 2)

        # Log output
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setPlaceholderText("Thông tin chi tiết và API sẽ hiển thị ở đây...")
        self.layout.addWidget(self.log_output, 2)

    # ---------------- DSA: QUICK SORT ----------------
    def quick_sort_sections(self, arr):
        """
        Sắp xếp section theo entropy giảm dần bằng Quick Sort.

        Độ phức tạp:
        - Trung bình: O(n log n)
        - Tệ nhất: O(n^2)

        Args:
            arr (list): [(name, raw_size, virtual_size, entropy)]

        Returns:
            list: danh sách đã sắp xếp
        """
        if len(arr) <= 1:
            return arr

        pivot = arr[len(arr) // 2][3]

        left = [x for x in arr if x[3] > pivot]
        middle = [x for x in arr if x[3] == pivot]
        right = [x for x in arr if x[3] < pivot]

        return self.quick_sort_sections(left) + middle + self.quick_sort_sections(right)

    # ---------------- ENTROPY ----------------
    def calculate_entropy(self, data):
        """
        Tính Shannon Entropy.

        - Sử dụng mảng tần suất 256 phần tử
        - Độ phức tạp: O(n)

        Args:
            data (bytes)

        Returns:
            float
        """
        if not data:
            return 0.0

        occurences = [0] * 256
        for byte in data:
            occurences[byte] += 1

        entropy = 0
        for x in occurences:
            if x > 0:
                p_x = float(x) / len(data)
                entropy -= p_x * math.log(p_x, 2)

        return entropy

    # ---------------- DRAG & DROP ----------------
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event):
        """
        Xử lý kéo thả file.
        """
        files = [u.toLocalFile() for u in event.mimeData().urls()]
        if files:
            file_path = files[0]
            if file_path.lower().endswith(('.exe', '.dll', '.sys')):
                self.analyze_pe(file_path)
            else:
                self.log_output.setText("[-] Định dạng file không hỗ trợ!")

    # ---------------- MAIN ANALYSIS ----------------
    def analyze_pe(self, file_path):
        """
        Phân tích cấu trúc PE.
        """
        try:
            pe = pefile.PE(file_path)
            self.label.setText(f"Đang phân tích: {file_path.split('/')[-1]}")
            self.log_output.clear()

            # Header info
            info = f"Entry Point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}\n"
            info += f"Image Base: {hex(pe.OPTIONAL_HEADER.ImageBase)}\n"
            info += "-" * 30 + "\n"

            # Section + Entropy
            sections_data = []
            for section in pe.sections:
                name = section.Name.decode().strip('\x00')
                entropy = self.calculate_entropy(section.get_data())
                sections_data.append((name, section.SizeOfRawData, section.Misc_VirtualSize, entropy))

            #QUICK SORT
            sections_data = self.quick_sort_sections(sections_data)

            # Hiển thị bảng
            self.table.setRowCount(0)
            for row_data in sections_data:
                row_idx = self.table.rowCount()
                self.table.insertRow(row_idx)

                for i, val in enumerate(row_data):
                    item = QTableWidgetItem(str(val) if i < 3 else f"{val:.4f}")

                    # cảnh báo entropy cao
                    if i == 3 and val > 7.0:
                        item.setForeground(Qt.GlobalColor.red)
                        item.setText(f"{val:.4f} [!]")

                    self.table.setItem(row_idx, i, item)

            # Import DLL
            info += "Imported DLLs:\n"
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
