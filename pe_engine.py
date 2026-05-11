import pefile
import re
import numpy as np
import cv2
from dsa_logic import calculate_entropy, quick_sort_sections, LinkedList

def get_pe_info(file_path, scaler=None, tfidf=None):
    """
    Hàm lõi: Chuyển đổi tệp thực thi thành dữ liệu đầu vào cho mô hình Multi-View.
    - Nhánh 1 (CNN): Ảnh texture 32x32.
    - Nhánh 2 (DNN): Vector đặc trưng Header + API TF-IDF.
    """
    pe = pefile.PE(file_path)
    
    # --- 1. TRÍCH XUẤT THÔNG TIN CẤU TRÚC (Dành cho GUI Tree View) ---
    headers = {
        "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase)
    }
    
    # Ứng dụng DSA: Dùng Quick Sort & Entropy để sắp xếp các vùng nghi ngờ
    sections_list = []
    for section in pe.sections:
        name = section.Name.decode(errors='ignore').strip('\x00')
        entropy = calculate_entropy(section.get_data())
        sections_list.append((name, section.SizeOfRawData, section.Misc_VirtualSize, entropy))
    
    sorted_sections = quick_sort_sections(sections_list)
    
    # --- 2. TRÍCH XUẤT ĐẶC TRƯNG CHO DNN (DNN Input) ---
    all_apis_list = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    all_apis_list.append(imp.name.decode(errors='ignore'))

    X_dnn = None
    if scaler and tfidf:
        # Lấy đặc trưng PE Header tương ứng với lúc huấn luyện[cite: 4]
        target_sec = pe.sections[0] if len(pe.sections) > 0 else None
        header_raw = [
            len(pe.sections),
            pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            pe.OPTIONAL_HEADER.ImageBase,
            target_sec.SizeOfRawData if target_sec else 0,
            target_sec.Misc_VirtualSize if target_sec else 0,
            target_sec.get_entropy() if target_sec else 0
        ]
        
        # Scale đặc trưng tĩnh và thực hiện TF-IDF cho API[cite: 4]
        X_header_scaled = scaler.transform([header_raw])
        api_str = "|".join(all_apis_list[:100]) # Khớp format lúc train[cite: 4]
        X_api_tfidf = tfidf.transform([api_str]).toarray()
        X_dnn = np.hstack([X_header_scaled, X_api_tfidf])

    # --- 3. TRÍCH XUẤT TEXTURE ẢNH (CNN Input) ---
    # Chuyển đổi dữ liệu nhị phân thành ảnh grayscale 32x32[cite: 4]
    raw_data = pe.get_memory_mapped_image()
    raw_bytes = np.frombuffer(raw_data, dtype=np.uint8)
    if len(raw_bytes) > 0:
        side = int(len(raw_bytes)**0.5)
        temp_array = raw_bytes[:side*side].reshape((side, side))
        img_32x32 = cv2.resize(temp_array, (32, 32), interpolation=cv2.INTER_NEAREST)
        X_cnn = img_32x32.reshape(1, 32, 32, 1) / 255.0
    else:
        X_cnn = np.zeros((1, 32, 32, 1))
        img_32x32 = np.zeros((32, 32))

    # --- 4. TRÍCH XUẤT CHUỖI KÝ TỰ (Dùng Linked List) ---
    strings_list_obj = LinkedList()
    found_strings = re.findall(rb"[ -~]{4,20}", raw_data)
    for s in found_strings:
        strings_list_obj.append(s.decode(errors='ignore'))

    imports_dict = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode(errors='ignore')
            api_list = [imp.name.decode(errors='ignore') for imp in entry.imports if imp.name]
            imports_dict[dll_name] = api_list

    return {
        # Sửa dòng này để trả về 4 giá trị (headers, sorted_sections, imports_dict, strings)
        "dsa_data": (headers, sorted_sections, imports_dict, strings_list_obj.to_list()), 
        "ai_input": (X_cnn, X_dnn),
        "raw_img": img_32x32
    }
