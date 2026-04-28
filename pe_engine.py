import pefile
import re
from dsa_logic import calculate_entropy, quick_sort_sections, LinkedList
from dsa_logic import APIGraph

def get_pe_info(file_path):
    """
    Hàm lõi thực hiện trích xuất và cấu trúc hóa thông tin từ tệp PE (Portable Executable).
    
    Quy trình xử lý:
    1. Sử dụng thư viện pefile để ánh xạ cấu trúc nhị phân của tệp.
    2. Trích xuất thông tin cơ bản từ Optional Header.
    3. Tính toán Entropy cho từng Section và sắp xếp chúng bằng Quick Sort.
    4. Duyệt qua Import Directory để lập danh sách các DLL và hàm API tương ứng.
    5. Sử dụng biểu thức chính quy (Regex) để tìm các chuỗi ASCII và lưu trữ vào Linked List.

    Args:
        file_path (str): Đường dẫn tuyệt đối đến tệp cần phân tích.

    Returns:
        tuple: Bộ 5 giá trị bao gồm:
            - headers (dict): Địa chỉ Entry Point và Image Base.
            - sorted_sections (list): Danh sách các phân vùng đã sắp xếp theo Entropy giảm dần.
            - imports (dict): Cấu trúc {Tên_DLL: [Danh_sách_API]}.
            - strings_list (list): Danh sách các chuỗi ký tự trích xuất được.
            - pe (pefile.PE): Đối tượng PE gốc để tham chiếu nếu cần.
    """
    pe = pefile.PE(file_path)
    
    # 1. Trích xuất Headers
    headers = {
        "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase)
    }
    
    # 2. Trích xuất và sắp xếp Sections (Sử dụng Quick Sort & Entropy)
    sections_list = []
    for section in pe.sections:
        name = section.Name.decode(errors='ignore').strip('\x00')
        entropy = calculate_entropy(section.get_data())
        sections_list.append((name, section.SizeOfRawData, section.Misc_VirtualSize, entropy))
    
    sorted_sections = quick_sort_sections(sections_list)
    
    # 3. Trích xuất Imports
    imports = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode(errors='ignore')
            api_list = []
            for imp in entry.imports:
                if imp.name:
                    api_list.append(imp.name.decode(errors='ignore'))
            imports[dll_name] = api_list

    # 4. Trích xuất Strings và lưu vào Linked List (DSA mục 1)
    strings_list_obj = LinkedList()
    # Lấy toàn bộ dữ liệu thô để tìm chuỗi ký tự (ASCII)
    raw_data = pe.get_memory_mapped_image()
    found_strings = re.findall(rb"[ -~]{4,20}", raw_data)
    
    for s in found_strings:
        strings_list_obj.append(s.decode(errors='ignore'))

    return headers, sorted_sections, imports, strings_list_obj.to_list(), pe

from dsa_logic import APIGraph

def detect_malware_behavior(headers, sections, imports, strings):
    """
    Hệ thống chuyên gia đánh giá mức độ độc hại dựa trên Heuristics và Đồ thị hành vi.
    """
    # --- KHỞI TẠO ---
    risk_score = 0
    findings = []
    all_apis = set()
    all_apis_list = []
    
    for dll in imports:
        for api in imports[dll]:
            all_apis.add(api)
            all_apis_list.append(api)

    # --- ỨNG DỤNG GRAPH: Behavior Correlation ---
    api_graph = APIGraph()
    
    # Xây dựng đồ thị: Kết nối các API xuất hiện kế tiếp nhau 
    # (Mô phỏng luồng gọi hàm tiềm năng)
    for i in range(len(all_apis_list) - 1):
        api_graph.add_edge(all_apis_list[i], all_apis_list[i+1])
    
    # Kiểm tra chuỗi hành vi đặc trưng bằng Graph Pattern Matching
    injection_pattern = {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}
    match_rate = api_graph.check_pattern(injection_pattern, all_apis)
    
    if match_rate > 0.6: 
        risk_score += 4
        findings.append(f"⚠️ Graph: Tìm thấy cụm hành vi tiêm mã (Khớp {match_rate*100:.0f}%)")

    # --- RULE 1: API cực độc (Dựa trên Hash Table Search kết quả từ main gửi qua) ---
    super_dangerous = {"CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", "EnumProcesses"}
    found_super = all_apis.intersection(super_dangerous)
    if found_super:
        risk_score += 5
        findings.append(f"⚠️ API cực độc: {', '.join(found_super)}")

    # --- RULE 2: Kỹ thuật giấu API (Entropy + Dynamic Resolving) ---
    high_entropy = any(s[3] > 6.5 for s in sections)
    if "GetProcAddress" in all_apis and high_entropy:
        risk_score += 4
        findings.append("⚠️ Kỹ thuật giấu API (Dynamic Resolving + High Entropy)")

    # --- RULE 3: Download & Execute ---
    net_apis = {"URLDownloadToFile", "InternetOpenA", "HttpSendRequestA", "WSAStartup"}
    exec_apis = {"WinExec", "ShellExecuteA", "CreateProcessA"}
    if all_apis.intersection(net_apis) and all_apis.intersection(exec_apis):
        risk_score += 4
        findings.append("⚠️ Chuỗi hành vi Downloader & Execute")

    # --- RULE 4: Quét String IOCs bằng Boyer-Moore kết quả ---
    ioc_patterns = ["http", "powershell", ".exe", "temp", "appdata", "startup"]
    found_iocs = 0
    for s in strings:
        if any(p in s.lower() for p in ioc_patterns):
            found_iocs += 1
    if found_iocs > 3:
        risk_score += 2
        findings.append("⚠️ Dấu vết IOCs trong chuỗi ký tự")

    # --- KẾT LUẬN ---
    if risk_score >= 7: status = "NGUY HIỂM CAO"
    elif risk_score >= 3: status = "CẢNH BÁO"
    else: status = "BÌNH THƯỜNG"

    return status, findings, risk_score