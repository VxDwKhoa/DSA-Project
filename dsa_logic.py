import math

class APIHashTable:
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
        self._load_blacklist()

    def _hash(self, key):
        """
        Hàm băm dựa trên tổng giá trị ASCII của các ký tự trong chuỗi.
        Args:
            key (str): Tên API cần băm.
        Returns:
            int: Chỉ số (index) trong bảng băm.
        """
        return sum(ord(char) for char in key) % self.size

    def _load_blacklist(self):
        """Nạp danh sách các API thường bị mã độc lợi dụng vào bảng băm."""
        sensitive_apis = {
            "CreateRemoteThread": "Tiêm mã (Code Injection)",
            "WriteProcessMemory": "Ghi bộ nhớ tiến trình",
            "VirtualAllocEx": "Cấp phát bộ nhớ từ xa",
            "GetProcAddress": "Tìm nạp địa chỉ hàm động",
            "URLDownloadToFile": "Tải file độc hại",
            "ShellExecuteA": "Thực thi lệnh hệ thống"
        }
        for api, desc in sensitive_apis.items():
            self.insert(api, desc)

    def insert(self, api_name, description):
        """
        Thêm một API mới vào bảng băm.
        Args:
            api_name (str): Tên API.
            description (str): Mô tả hành vi độc hại liên quan.
        """
        hash_key = self._hash(api_name)
        self.table[hash_key].append((api_name, description))

    def search(self, api_name):
        """
        Tra cứu API trong bảng băm với độ phức tạp trung bình O(1).
        Args:
            api_name (str): Tên API cần kiểm tra.
        Returns:
            str/None: Mô tả hành vi nếu tìm thấy, ngược lại trả về None.
        """
        hash_key = self._hash(api_name)
        for item in self.table[hash_key]:
            if item[0] == api_name:
                return item[1]
        return None

def quick_sort_sections(arr):
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
    return quick_sort_sections(left) + middle + quick_sort_sections(right)

def calculate_entropy(data):
    """
    Tính toán độ hỗn loạn (Shannon Entropy) của một khối dữ liệu.
    Dùng để phát hiện các phân vùng bị nén hoặc mã hóa (thường có entropy > 7.0).
    Args:
        data (bytes): Dữ liệu nhị phân cần tính toán.
    Returns:
        float: Giá trị Entropy (từ 0.0 đến 8.0).
    """
    if not data: return 0.0
    occurences = [0] * 256
    for byte in data: occurences[byte] += 1
    entropy = 0
    for x in occurences:
        if x > 0:
            p_x = float(x) / len(data)
            entropy -= p_x * math.log(p_x, 2)
    return entropy

class Node:
    """Nút (Node) cơ bản trong danh sách liên kết."""
    def __init__(self, data):
        self.data = data
        self.next = None

class LinkedList:
    """
    Danh sách liên kết đơn (Linked List) dùng để quản lý danh sách chuỗi ký tự (Strings).
    Giúp tối ưu việc cấp phát bộ nhớ động khi trích xuất lượng lớn chuỗi từ file PE.
    """
    def __init__(self):
        self.head = None

    def append(self, data):
        """Thêm một phần tử vào cuối danh sách liên kết."""
        new_node = Node(data)
        if not self.head:
            self.head = new_node
            return
        last = self.head
        while last.next:
            last = last.next
        last.next = new_node

    def to_list(self):
        """Chuyển đổi Linked List sang Python List để hiển thị lên giao diện."""
        result = []
        curr = self.head
        while curr:
            result.append(curr.data)
            curr = curr.next
        return result

def boyer_moore_search(text, pattern):
    """
    Giải thuật tìm kiếm chuỗi Boyer-Moore (Bad Character Heuristic).
    Dùng để quét các dấu hiệu mã độc (như http, cmd.exe) trong dữ liệu Strings.
    Args:
        text (str): Văn bản nguồn.
        pattern (str): Mẫu cần tìm kiếm.
    Returns:
        bool: True nếu tìm thấy mẫu, ngược lại False.
    """
    m = len(pattern)
    n = len(text)
    if m > n: return False

    bad_char = [-1] * 256
    for i in range(m):
        bad_char[ord(pattern[i])] = i

    s = 0
    while s <= n - m:
        j = m - 1
        while j >= 0 and pattern[j] == text[s + j]:
            j -= 1
        if j < 0:
            return True
        else:
            s += max(1, j - bad_char[ord(text[s + j])])
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
        if not self.is_empty():
            return self.items.pop()
        return None

    def is_empty(self):
        """Kiểm tra ngăn xếp có trống hay không."""
        return len(self.items) == 0

    def peek(self):
        """Xem phần tử trên cùng mà không xóa khỏi ngăn xếp."""
        if not self.is_empty():
            return self.items[-1]
        return None

class APIGraph:
    """
    Đồ thị (Graph) biểu diễn mối quan hệ đồng xuất hiện giữa các API.
    Dùng để suy luận hành vi (Behavior Inference) dựa trên các cụm API liên quan.
    """
    def __init__(self):
        self.adj_list = {} # Adjacency List

    def add_edge(self, api1, api2):
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