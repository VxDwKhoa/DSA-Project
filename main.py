import sys
import os
import joblib
import numpy as np
import tensorflow as tf
from PyQt6.QtWidgets import (QApplication, QMainWindow, QLabel, QTextEdit, 
                             QVBoxLayout, QWidget, QTreeWidget, QTreeWidgetItem, 
                             QHeaderView, QPushButton)
from PyQt6.QtCore import Qt
from dsa_logic import BangBamPEimport, timkiemchuoinhanh, Stack 
# Sử dụng hàm get_pe_info đã được nâng cấp để trích xuất song song AI Input
from pe_engine import get_pe_info 

class PEAnalyzerApp(QMainWindow):
    """
    Lớp giao diện chính của ứng dụng Phân tích Mã độc PE.
    
    Ứng dụng kết hợp sức mạnh của các cấu trúc dữ liệu tự cài đặt (DSA) 
    và mô hình Deep Learning Multi-View để phân tích và chẩn đoán tệp thực thi.
    
    Các tính năng chính:
    - Phân tích tĩnh (Static Analysis) cấu trúc file PE.
    - Dự đoán loại mã độc bằng AI (CNN + DNN).
    - Quản lý lịch sử bằng Stack và tra cứu API bằng Hash Table.
    """
    def __init__(self):
        """
        Khởi tạo cửa sổ chính, cấu trúc dữ liệu và nạp tài nguyên AI.
        Thiết lập các tham số cơ bản cho giao diện người dùng.
        """
        super().__init__()
        self.setWindowTitle("UIT Malware Analysis - AI & DSA Hybrid Tool")
        self.setFixedSize(950, 800)
        self.setAcceptDrops(True)
        
        # --- 1. Khởi tạo Cấu trúc dữ liệu (DSA) ---
        self.api_checker = BangBamPEimport()  
        self.history_stack = Stack()       
        self.current_file = None
        
        # --- 2. Nạp model deep learning
        self.load_ai_resources()
        
        self.init_ui()

    def load_ai_resources(self):
        """
        Nạp mô hình deep learning từ bộ nhớ cục bộ.
        
        Bao gồm:
        - Mô hình Keras (.h5): Bộ não dự đoán chính.
        - Scaler (.pkl): Chuẩn hóa các đặc trưng Header.
        - TF-IDF (.pkl): Chuyển đổi danh sách API thành vector số học.
        """
        base_path = "D:\DSA project 3"
        try:
            self.model = tf.keras.models.load_model(os.path.join(base_path, "malware_multi_view_model.h5"))
            self.scaler = joblib.load(os.path.join(base_path, "scaler.pkl"))
            self.tfidf = joblib.load(os.path.join(base_path, "tfidf.pkl"))
            # Mặc định thứ tự nhãn đã fix khi train[cite: 4]
            self.class_names = ['Benign', 'Locker', 'Mediyes', 'Winwebsec', 'Zbot', 'Zeroaccess']
            print(">>> AI Resources Loaded Successfully!")
        except Exception as e:
            print(f">>> Error loading AI resources: {e}")
            self.model = None

    def init_ui(self):
        """
        Khởi tạo và sắp xếp các thành phần giao diện người dùng (Widgets).
        Thiết lập bố cục (Layout) và phong cách (Style) cho ứng dụng.
        """
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)
        
        self.label = QLabel("KÉO THẢ FILE .EXE VÀO ĐÂY ĐỂ PHÂN TÍCH")
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.label.setStyleSheet("border: 2px dashed #aaa; border-radius: 10px; padding: 20px; background-color: #f0f0f0; font-weight: bold;")
        self.layout.addWidget(self.label, 1)

        self.btn_back = QPushButton("Quay lại file trước đó ")
        self.btn_back.clicked.connect(self.go_back)
        self.layout.addWidget(self.btn_back)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Thành phần cấu trúc PE", "Chi tiết Phân tích / Dự đoán"])
        self.tree.header().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.layout.addWidget(self.tree, 6)

        self.log_output = QTextEdit()
        self.log_output.setFixedHeight(100)
        self.log_output.setReadOnly(True)
        self.layout.addWidget(self.log_output, 1)

    def dragEnterEvent(self, event):
        """
        Xử lý sự kiện khi người dùng kéo tệp tin vào vùng ứng dụng.
        Kiểm tra xem dữ liệu kéo vào có chứa liên kết tệp tin (URLs) hay không.
        """
        if event.mimeData().hasUrls(): event.accept()
        else: event.ignore()

    def dropEvent(self, event):
        """
        Xử lý sự kiện khi người dùng thả tệp tin vào ứng dụng.
        Trích xuất đường dẫn tệp tin và kiểm tra định dạng tệp thực thi (.exe, .dll).
        """
        file_path = event.mimeData().urls()[0].toLocalFile()
        if file_path.lower().endswith(('.exe', '.dll')):
            self.process_new_file(file_path)

    def process_new_file(self, file_path):
        """
        Quản lý luồng công việc khi một tệp mới được yêu cầu phân tích.
        Lưu trữ tệp cũ vào Ngăn xếp lịch sử trước khi tiến hành phân tích tệp mới.

        Args:
            file_path (str): Đường dẫn đến tệp tin mới.
        """
        if self.current_file and self.current_file != file_path:
            self.history_stack.push(self.current_file) 
        self.analyze_pe(file_path)

    def analyze_pe(self, file_path):
        """
        Luồng xử lý trung tâm khi phân tích một file mới.
        
        Quy trình thực hiện:
        1. Gọi PE Engine để trích xuất dữ liệu DSA và AI Input.
        2. Đưa dữ liệu qua mô hình Multi-View để lấy kết quả chẩn đoán.
        3. Cập nhật dữ liệu lên Tree Widget (Cấu trúc cây).
        4. Áp dụng thuật toán tìm kiếm (Boyer-Moore) và tra cứu (Hash Table) 
           để gắn nhãn các dấu hiệu nghi ngờ.
        
        Args:
            file_path (str): Đường dẫn tuyệt đối đến file cần phân tích.
        """
        try:
            self.current_file = file_path
            self.tree.clear()
            
            # 1. Gọi Engine trích xuất (Kết hợp DSA và AI Preprocessing)[cite: 2, 4]
            # Lưu ý: get_pe_info lúc này trả về dict chứa ai_input
            data = get_pe_info(file_path, self.scaler, self.tfidf)
            headers, sections, imports, strings = data["dsa_data"]
            X_cnn, X_dnn = data["ai_input"]

            # 2. Dự đoán bằng Deep Learning Multi-View[cite: 4]
            ai_prediction_text = "N/A"
            confidence = 0
            if self.model:
                preds = self.model.predict([X_cnn, X_dnn])
                idx = np.argmax(preds)
                ai_prediction_text = self.class_names[idx]
                confidence = preds[0][idx] * 100

            # --- HIỂN THỊ LÊN TREE (DSA: Tree Data Structure) ---
            
            # Nhánh 0: KẾT QUẢ DỰ ĐOÁN AI (New Feature)
            ai_node = QTreeWidgetItem(self.tree, ["Dự đoán", f"Kết quả: {ai_prediction_text}"])
            ai_node.setExpanded(True)
            color = Qt.GlobalColor.green if ai_prediction_text == 'Benign' else Qt.GlobalColor.red
            ai_node.setForeground(1, color)
            QTreeWidgetItem(ai_node, ["Độ tin cậy", f"{confidence:.2f}%"])

            # Nhánh 1: PE Headers
            h_node = QTreeWidgetItem(self.tree, ["📦 PE Headers", "Thông tin cơ bản"])
            for k, v in headers.items():
                QTreeWidgetItem(h_node, [k, str(v)])

            # Nhánh 2: Sections (Sắp xếp bởi Quick Sort)[cite: 1]
            s_root = QTreeWidgetItem(self.tree, ["📊 Sections (Sorted by Entropy)", f"{len(sections)} vùng"])
            for name, raw, virt, entropy in sections:
                s_node = QTreeWidgetItem(s_root, [name, f"Entropy: {entropy:.4f}"])
                if entropy > 7.0:
                    s_node.setForeground(0, Qt.GlobalColor.red)
                    QTreeWidgetItem(s_node, ["Cảnh báo", "Nghi ngờ dữ liệu bị nén/mã hóa"])

            # Nhánh 3: Import Table (Tra cứu Hash Table)[cite: 1]
            i_root = QTreeWidgetItem(self.tree, ["🔌 Import Table (Hash Table Lookup)", "Hành vi API"])
            for dll, apis in imports.items():
                dll_node = QTreeWidgetItem(i_root, [dll, ""])
                for api in apis:
                    danger = self.api_checker.search(api)
                    item = QTreeWidgetItem(dll_node, [api, danger if danger else "Bình thường"])
                    if danger:
                        item.setForeground(0, Qt.GlobalColor.red)
                        item.setText(1, f"⚠️ {danger}")

            # Nhánh 4: Suspicious Strings (Boyer-Moore Search)[cite: 1]
            str_root = QTreeWidgetItem(self.tree, ["🔍 Suspicious Strings (Boyer-Moore Scan)", "Dấu hiệu IOCs"])
            patterns = ["http", "powershell", "cmd.exe", ".exe", "C:\\", "kernel32"]
            for s in strings:
                for p in patterns:
                    if timkiemchuoinhanh(s.lower(), p): 
                        QTreeWidgetItem(str_root, [f"Khớp mẫu: {p}", s]).setForeground(0, Qt.GlobalColor.darkYellow)
                        break

            self.log_output.setText(f"[+] Phân tích hoàn tất: {os.path.basename(file_path)}")
            self.log_output.append(f"[*] Deep Learning kết luận: {ai_prediction_text} ({confidence:.2f}%)")

        except Exception as e:
            self.log_output.setText(f"[-] Lỗi hệ thống: {str(e)}")

    def go_back(self):
        """
        Triển khai tính năng Hoàn tác (Undo) dựa trên cấu trúc dữ liệu Stack.
        
        Lấy đường dẫn file gần nhất từ ngăn xếp lịch sử (LIFO) và 
        thực hiện phân tích lại để quay lại trạng thái trước đó.
        """
        prev_file = self.history_stack.pop() 
        if prev_file:
            self.current_file = None  
            self.analyze_pe(prev_file)
            self.log_output.append(f"[+] Đã quay lại file: {prev_file}")
        else:
            self.log_output.append("[!] Stack lịch sử trống.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PEAnalyzerApp()
    window.show()
    sys.exit(app.exec())
