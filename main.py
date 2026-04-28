import sys
from PyQt6.QtWidgets import (QApplication, QMainWindow, QLabel, QTextEdit, 
                             QVBoxLayout, QWidget, QTreeWidget, QTreeWidgetItem, 
                             QHeaderView, QPushButton)
from PyQt6.QtCore import Qt
from dsa_logic import APIHashTable, boyer_moore_search, Stack 
from pe_engine import get_pe_info, detect_malware_behavior 

class PEAnalyzerApp(QMainWindow):
    """
    Lớp chính điều khiển giao diện người dùng (GUI) cho công cụ phân tích mã độc.
    Sử dụng PyQt6 để tạo trải nghiệm tương tác kéo-thả file.
    """
    def __init__(self):
        super().__init__()
        self.setWindowTitle("UIT Malware Analysis - PE Tool")
        self.setFixedSize(900, 750)
        self.setAcceptDrops(True) # Kích hoạt tính năng kéo thả file
        
        # --- Khởi tạo các Cấu trúc dữ liệu (DSA) ---
        self.api_checker = APIHashTable()  # Bảng băm tra cứu API
        self.history_stack = Stack()       # Ngăn xếp lưu lịch sử file (LIFO)
        self.current_file = None
        
        self.init_ui()

    def init_ui(self):
        """Khởi tạo cấu trúc các thành phần trên giao diện (Layout, Buttons, Tree, Log)."""
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)
        
        # Vùng kéo thả file
        self.label = QLabel("KÉO THẢ FILE VÀO ĐÂY ĐỂ PHÂN TÍCH")
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.label.setStyleSheet("""
            border: 2px dashed #aaa; 
            border-radius: 10px; 
            padding: 20px; 
            font-weight: bold;
            background-color: #f0f0f0;
        """)
        self.layout.addWidget(self.label, 1)

        # Nút Back điều khiển bởi Stack
        self.btn_back = QPushButton("⬅ Quay lại file trước đó (Stack Pop)")
        self.btn_back.setStyleSheet("padding: 8px; font-weight: bold;")
        self.btn_back.clicked.connect(self.go_back)
        self.layout.addWidget(self.btn_back)

        # Thành phần Cây (Tree Widget) - Biểu diễn cấu trúc phân cấp của PE
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Thành phần cấu trúc PE", "Chi tiết / Cảnh báo độc hại"])
        self.tree.header().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.layout.addWidget(self.tree, 5)

        # Cửa sổ Log hiển thị trạng thái hệ thống
        self.log_output = QTextEdit()
        self.log_output.setFixedHeight(80)
        self.log_output.setReadOnly(True)
        self.log_output.setPlaceholderText("Hệ thống log...")
        self.layout.addWidget(self.log_output, 1)

    def dragEnterEvent(self, event):
        """Xử lý sự kiện khi file được kéo vào vùng ứng dụng."""
        if event.mimeData().hasUrls(): event.accept()
        else: event.ignore()

    def dropEvent(self, event):
        """Xử lý sự kiện khi file được thả vào ứng dụng."""
        file_path = event.mimeData().urls()[0].toLocalFile()
        self.process_new_file(file_path)

    def process_new_file(self, file_path):
        """
        Quản lý luồng dữ liệu khi có file mới: Lưu file cũ vào Stack trước khi phân tích.
        Args:
            file_path (str): Đường dẫn file mới.
        """
        if self.current_file and self.current_file != file_path:
            self.history_stack.push(self.current_file) # DSA: Push vào Stack
        
        self.analyze_pe(file_path)

    def analyze_pe(self, file_path):
        """
        Hàm trung tâm điều phối việc phân tích và hiển thị kết quả lên cấu trúc Cây (Tree Traversal).
        Tích hợp hiển thị kết quả chẩn đoán từ Graph và các thuật toán DSA.
        """
        try:
            self.current_file = file_path
            self.tree.clear() # Xóa kết quả cũ để nạp file mới
            
            # 1. Gọi Engine xử lý dữ liệu nhị phân PE
            headers, sections, imports, strings, _ = get_pe_info(file_path)
            
            # 2. Nhận kết quả chẩn đoán từ bộ lọc Expert System (Heuristics + Graph)
            status, findings, total_risk = detect_malware_behavior(headers, sections, imports, strings)
            
            # --- HIỂN THỊ LÊN TREE (DSA: Tree Data Structure) ---
            
            # Nhánh 0: ĐÁNH GIÁ BẢO MẬT (Security Assessment)
            assessment_node = QTreeWidgetItem(self.tree, ["🛡️ ĐÁNH GIÁ BẢO MẬT", f"Mức độ: {status}"])
            assessment_node.setExpanded(True) # Luôn mở nhánh kết luận đầu tiên
            
            # Phân loại màu sắc dựa trên Risk Score tổng hợp (Đồng bộ ngưỡng 3-7 với Engine)
            if total_risk >= 7:
                assessment_node.setForeground(0, Qt.GlobalColor.red)
                assessment_node.setText(1, f"🔴 {status} (Score: {total_risk})")
            elif total_risk >= 3:
                assessment_node.setForeground(0, Qt.GlobalColor.yellow)
                assessment_node.setText(1, f"🟡 {status} (Score: {total_risk})")
            else:
                assessment_node.setForeground(0, Qt.GlobalColor.green)
                assessment_node.setText(1, f"🟢 {status}")

            # Hiển thị chi tiết các Rule bị vi phạm
            for f in findings:
                finding_item = QTreeWidgetItem(assessment_node, ["Phát hiện:", f])
                # Highlight đặc biệt cho các phát hiện từ Graph để gây ấn tượng
                if "Graph" in f:
                    finding_item.setForeground(1, Qt.GlobalColor.magenta) # Màu tím cho sự sáng tạo Graph
                else:
                    finding_item.setForeground(1, Qt.GlobalColor.red if total_risk >= 7 else Qt.GlobalColor.darkYellow)

            # Nhánh 1: PE Headers (Metadata)
            h_node = QTreeWidgetItem(self.tree, ["PE Headers", "Thông tin cơ bản"])
            for k, v in headers.items():
                QTreeWidgetItem(h_node, [k, str(v)])

            # Nhánh 2: Sections (Sắp xếp bởi Quick Sort theo Entropy)
            s_root = QTreeWidgetItem(self.tree, ["Sections (Sorted by Quick Sort)", f"{len(sections)} vùng"])
            for name, raw, virt, entropy in sections:
                s_node = QTreeWidgetItem(s_root, [name, f"Entropy: {entropy:.4f}"])
                if entropy > 7.0:
                    s_node.setForeground(0, Qt.GlobalColor.red)
                    QTreeWidgetItem(s_node, ["CẢNH BÁO", "Dữ liệu có độ hỗn loạn cao -> Nghi ngờ Encrypted/Packed"])

            # Nhánh 3: Import Table (Tra cứu API qua Hash Table O(1))
            i_root = QTreeWidgetItem(self.tree, ["Import Table (Hash Table Lookup)", "Hành vi hệ thống"])
            for dll, apis in imports.items():
                dll_node = QTreeWidgetItem(i_root, [dll, ""])
                for api in apis:
                    danger = self.api_checker.search(api) # DSA: Tra cứu bảng băm
                    item = QTreeWidgetItem(dll_node, [api, danger if danger else "Bình thường"])
                    if danger:
                        item.setForeground(0, Qt.GlobalColor.red)
                        item.setText(1, f"[!] {danger}")

            # Nhánh 4: Suspicious Strings (Quét bằng Boyer-Moore)
            str_root = QTreeWidgetItem(self.tree, ["Strings (Linked List + Boyer-Moore)", "Dấu hiệu IOCs"])
            patterns = ["http", "powershell", "cmd.exe", ".exe", "C:\\", "kernel32"]
            found_any = False
            for s in strings: # Duyệt qua danh sách trích xuất từ Linked List
                for p in patterns:
                    if boyer_moore_search(s.lower(), p): 
                        item = QTreeWidgetItem(str_root, [f"Mẫu khớp: {p}", s])
                        item.setForeground(0, Qt.GlobalColor.darkYellow)
                        found_any = True
                        break
            
            if not found_any:
                QTreeWidgetItem(str_root, ["Không có dấu hiệu nghi vấn", ""])

            self.log_output.setText(f"[+] Phân tích hoàn tất: {file_path}")
            # Tự động ghi log về số lượng API đã xây dựng đồ thị
            self.log_output.append(f"[*] Đồ thị quan hệ API đã được xây dựng để kiểm tra cụm hành vi.")

        except Exception as e:
            self.log_output.setText(f"[-] Lỗi phân tích: {str(e)}")
    def go_back(self):
        """
        Tính năng quay lại file trước đó: Pop phần tử khỏi Stack (LIFO).
        Đây là ứng dụng thực tế của cấu trúc dữ liệu Ngăn xếp.
        """
        prev_file = self.history_stack.pop() # Lấy phần tử trên cùng của Stack
        if prev_file:
            self.current_file = None  # Reset trạng thái file hiện tại
            self.analyze_pe(prev_file)
            self.log_output.setText(f"[+] Đã quay lại file trước đó: {prev_file}")
        else:
            self.log_output.setText("[!] Hết lịch sử để quay lại (Stack trống).")
    
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PEAnalyzerApp()
    window.show()
    sys.exit(app.exec())
