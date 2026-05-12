import pefile
import re
import numpy as np
import cv2
from dsa_logic import tinhdohonloanentropy, quicksortsections, Danhsachlienket

def get_pe_info(file_path, scaler=None, tfidf=None):
    """
    Hàm xử lý trung tâm: Trích xuất đặc trưng đa luồng (Multi-View) từ file PE.
    
    Hàm này đóng vai trò là  kết nối các cấu trúc dữ liệu 
    với mô hình học máy. Dữ liệu đầu ra được chia làm hai phần: phục vụ 
    phân tích tĩnh và phục vụ dự đoán mã độc.

    Args:
        file_path (str): Đường dẫn đến tệp thực thi (.exe, .dll) cần phân tích.
        scaler (sklearn.preprocessing.StandardScaler, optional): Bộ chuẩn hóa đặc trưng tĩnh.
        tfidf (sklearn.feature_extraction.text.TfidfVectorizer, optional): Bộ trích xuất đặc trưng API.

    Returns:
        dict: Một dictionary chứa:
            - "dsa_data": Tuple chứa (Headers, Sorted_Sections, Imports, Strings_List).
            - "ai_input": Tuple chứa (X_cnn, X_dnn) đã được tiền xử lý và chuẩn hóa.
            - "raw_img": Mảng numpy chứa ảnh texture grayscale 32x32 để hiển thị GUI.
    """
    pe = pefile.PE(file_path)
    
    # --- 1. TRÍCH XUẤT THÔNG TIN CẤU TRÚC (Dành cho GUI Tree View) ---
    headers = {
        "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase)
    }
    
    # Dùng Quick Sort & Entropy để sắp xếp các vùng nghi ngờ
    sections_list = []
    for section in pe.sections:
        name = section.Name.decode(errors='ignore').strip('\x00')
        entropy = tinhdohonloanentropy(section.get_data())
        sections_list.append((name, section.SizeOfRawData, section.Misc_VirtualSize, entropy))
    
    sorted_sections = quicksortsections(sections_list)
    
    # 2. TRÍCH XUẤT ĐẶC TRƯNG CHO DNN (DNN Input)
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

    #3. TRÍCH XUẤT TEXTURE ẢNH (CNN Input)
    # Chuyển đổi dữ liệu nhị phân thành ảnh grayscale 32x32
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

    # 4. TRÍCH XUẤT CHUỖI KÝ TỰ (Dùng Linked List)
    strings_list_obj = Danhsachlienket()
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
        "dsa_data": (headers, sorted_sections, imports_dict, strings_list_obj.to_list()), 
        "ai_input": (X_cnn, X_dnn),
        "raw_img": img_32x32
    }
