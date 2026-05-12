import math

class BangBamPEimport:
    """
    Bảng băm (Hash Table) dùng để lưu trữ và tra cứu danh sách các API nhạy cảm.
    Sử dụng phương pháp Separate Chaining để xử lý xung đột.
    """
    def __init__(self, size=100):
        """
        Khởi tạo bảng băm với kích thước mặc định.
        Args:
            size (int): Kích thước của mảng băm.
        """
        self.size = size
        self.table = [[] for _ in range(self.size)]
        self.hamkhanghi()

    def bam(self, key):
        """
        Hàm băm dựa trên tổng giá trị ASCII của các ký tự trong chuỗi.
        Args:
            key (str): Tên API cần băm.
        Returns:
            int: Chỉ số (index) trong bảng băm.
        """
        return sum(ord(char) for char in key) % self.size

    def hamkhanghi(self):
        """Nạp danh sách các API thường bị mã độc lợi dụng vào bảng băm."""
        hamnhaycam = {
            "CreateRemoteThread": "Tiêm mã (Code Injection)",
            "WriteProcessMemory": "Ghi bộ nhớ tiến trình",
            "VirtualAllocEx": "Cấp phát bộ nhớ từ xa",
            "GetProcAddress": "Tìm nạp địa chỉ hàm động",
            "URLDownloadToFile": "Tải file độc hại",
            "ShellExecuteA": "Thực thi lệnh hệ thống"
        }
        for api, desc in hamnhaycam.items():
            self.insert(api, desc)

    def insert(self, apiname, description):
        """
        Thêm một API mới vào bảng băm.
        Args:
            apiname (str): Tên API.
            description (str): Mô tả hành vi độc hại liên quan.
        """
        bam_key = self.bam(apiname)
        self.table[bam_key].append((apiname, description))

    def search(self, apiname):
        """
        Tra cứu API trong bảng băm với độ phức tạp trung bình O(1).
        Args:
            apiname (str): Tên API cần kiểm tra.
        Returns:
            str/None: Mô tả hành vi nếu tìm thấy, ngược lại trả về None.
        """
        bam_key = self.bam(apiname)
        for item in self.table[bam_key]:
            if item[0] == apiname:
                return item[1]
        return None

def quicksortsections(arr):
    """
    Giải thuật sắp xếp nhanh (Quick Sort) để sắp xếp các Section của file PE.
    Sắp xếp dựa trên chỉ số Entropy giảm dần.
    Args:
        arr (list): Danh sách các tuple chứa thông tin section (name, raw, virt, entropy).
    Returns:
        list: Danh sách đã được sắp xếp.
    """
    if len(arr) <= 1: return arr
    pivot = arr[len(arr) // 2][3]
    left = [x for x in arr if x[3] > pivot]
    middle = [x for x in arr if x[3] == pivot]
    right = [x for x in arr if x[3] < pivot]
    return quicksortsections(left) + middle + quicksortsections(right)

def tinhdohonloanentropy(dulieunhiphan):
    """
    Tính toán độ hỗn loạn (Shannon Entropy) để phát hiện tệp tin bị nén hoặc mã hóa.
    Mã độc thường có các phân vùng với Entropy > 7.0 do kỹ thuật Packing/Obfuscation.
    """
    if not dulieunhiphan: 
        return 0.0
        
    # Khoi tao bang dem tan suat cho 256 gia tri byte (0-255)
    solanxuathien = [0] * 256
    tongsobyte = len(dulieunhiphan)
    
    # Duyet qua tung byte trong khoi du lieu
    for byte in dulieunhiphan: 
        solanxuathien[byte] += 1
        
    entropyketqua = 0
    
    # Ap dung cong thuc Shannon Entropy
    for solan in solanxuathien:
        if solan > 0:
            # Tinh xac suat xuat hien cua byte do
            xacsuat = float(solan) / tongsobyte
            # Cong thuc: H(X) = -sum(p(x) * log2(p(x)))
            entropyketqua -= xacsuat * math.log(xacsuat, 2)
            
    return entropyketqua
class Node:
    """Nút (Node) cơ bản trong danh sách liên kết."""
    def __init__(self, data):
        self.data = data
        self.next = None

class Danhsachlienket:
    """
    Danh sách liên kết đơn (Linked List) dùng để quản lý danh sách chuỗi ký tự (Strings).
    Giúp tối ưu việc cấp phát bộ nhớ động khi trích xuất lượng lớn chuỗi từ file PE.
    """
    def __init__(self):
        self.head = None

    def append(self, data):
        """Thêm một phần tử vào cuối danh sách liên kết."""
        newnode = Node(data)
        if not self.head:
            self.head = newnode
            return
        last = self.head
        while last.next:
            last = last.next
        last.next = newnode

    def to_list(self):
        """Chuyển đổi Linked List sang Python List để hiển thị lên giao diện."""
        result = []
        curr = self.head
        while curr:
            result.append(curr.data)
            curr = curr.next
        return result

def timkiemchuoinhanh(vanban, mautim):
    """
    Giải thuật tìm kiếm chuỗi Boyer-Moore (Sử dụng bảng ký tự xấu).
    Dùng để quét dấu hiệu mã độc trong các chuỗi ký tự trích xuất từ file PE.
    """
    dodaimau = len(mautim)
    dodaivanban = len(vanban)
    
    # Nếu mẫu dài hơn văn bản thì chắc chắn không tìm thấy
    if dodaimau > dodaivanban: 
        return False

    # Khởi tạo bảng 'ký tự xấu' để biết cách nhảy cách quãng
    bangkytuxau = [-1] * 256
    for i in range(dodaimau):
        bangkytuxau[ord(mautim[i])] = i

    # s là độ dời của mẫu so với văn bản
    dodoi = 0
    while dodoi <= dodaivanban - dodaimau:
        # j là con trỏ duyệt ngược từ cuối mẫu lên đầu
        j = dodaimau - 1
        
        # So khớp từ phải sang trái
        while j >= 0 and mautim[j] == vanban[dodoi + j]:
            j -= 1
            
        # Nếu j < 0 nghĩa là tất cả ký tự trong mẫu đều khớp
        if j < 0:
            return True
        else:
            # Nếu không khớp, thực hiện nhảy dựa trên bảng ký tự xấu
            # j - bangkytuxau[...] giúp mẫu nhảy qua các đoạn không cần thiết
            dodoi += max(1, j - bangkytuxau[ord(vanban[dodoi + j])])
            
    return False
class Stack:
    """
    Ngăn xếp (Stack) dùng để lưu trữ lịch sử các file đã phân tích.
    Hỗ trợ tính năng "Quay lại" (Back) theo nguyên lý LIFO.
    """
    def __init__(self):
        self.items = []

    def push(self, item):
        """Đẩy đường dẫn file vào ngăn xếp."""
        self.items.append(item)

    def pop(self):
        """Lấy file gần nhất ra khỏi ngăn xếp."""
        if not self.stacktrong():
            return self.items.pop()
        return None

    def stacktrong(self):
        """Kiểm tra ngăn xếp có trống hay không."""
        return len(self.items) == 0

    def peek(self):
        """Xem phần tử trên cùng mà không xóa khỏi ngăn xếp."""
        if not self.stacktrong():
            return self.items[-1]
        return None

class DothiPEimport:
    """
    Đồ thị (Graph) biểu diễn mối quan hệ đồng xuất hiện giữa các API.
    Dùng để suy luận hành vi (Behavior Inference) dựa trên các cụm API liên quan.
    """
    def __init__(self):
        self.adj_list = {} # Adjacency List

    def themcanh(self, api1, api2):
        """Tạo cạnh giữa hai API nếu chúng xuất hiện cùng nhau trong một file."""
        if api1 not in self.adj_list: self.adj_list[api1] = set()
        if api2 not in self.adj_list: self.adj_list[api2] = set()
        self.adj_list[api1].add(api2)
        self.adj_list[api2].add(api1)

    def check_pattern(self, pattern_set, all_apis):
        """
        Kiểm tra độ tương quan của một nhóm API mục tiêu so với file đang phân tích.
        Args:
            pattern_set (set): Tập hợp các API đặc trưng cho một loại hành vi (vd: Injection).
            all_apis (set): Tất cả API tìm thấy trong file.
        Returns:
            float: Tỷ lệ khớp (từ 0.0 đến 1.0).
        """
        present_apis = [api for api in pattern_set if api in all_apis]
        return len(present_apis) / len(pattern_set) if pattern_set else 0