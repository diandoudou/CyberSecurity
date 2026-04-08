import csv
import random
from tqdm import tqdm
from analyze_the_characteristics import extract_url_features

def merge_and_shuffle(file1, file2, output_file, max_rows=10000):
    # 读取第一个文件（最多1万行数据）
    with open(file1, 'r', encoding='utf-8') as f1:
        reader1 = csv.reader(f1)
        next(reader1)  # 跳过标题行
        data1 = [row for i, row in enumerate(reader1) if i < max_rows]
    
    # 读取第二个文件（最多1万行数据）
    with open(file2, 'r', encoding='utf-8') as f2:
        reader2 = csv.reader(f2)
        next(reader2)  # 跳过标题行
        data2 = [row for i, row in enumerate(reader2) if i < max_rows]
    
    # 合并数据
    merged_data = data1 + data2
    
    # 打乱数据顺序
    random.shuffle(merged_data)
    
    # 写入新文件(添加标题行)
    with open(output_file, 'w', newline='', encoding='utf-8') as out:
        writer = csv.writer(out)
        writer.writerow(['Attribute', 'url'])  # 写入标题行
        writer.writerows(merged_data)

def process_with_features(input_file, output_file):
    # 读取输入文件
    with open(input_file, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        header = next(reader)  # 读取标题行
        
        # 添加特征列标题
        feature_headers = [
            'url_length', 'has_ip', 'dot_count', 'protocol_http', 'protocol_https',
            'subdomain_count', 'domain_age', 'dns_valid', 'site_accessible',
            'has_iframe', 'has_obfuscated_script', 'whois_available',
            'whois_registrar', 'whois_registration_time', 'whois_expiration_time',
            'whois_name_server'
        ]
        
        # 打开输出文件并写入标题行
        with open(output_file, 'w', newline='', encoding='utf-8') as out_f:
            writer = csv.writer(out_f)
            writer.writerow(header + feature_headers)
            
            # 逐行处理并立即写入
            for row in tqdm(reader, desc="处理URL特征"):
                url = row[1]  # 假设URL在第二列
                features = extract_url_features(url)
                
                # 构建新行并立即写入
                new_row = row + [str(features.get(col, '')) for col in feature_headers]
                writer.writerow(new_row)
                out_f.flush()  # 确保立即写入磁盘

# 使用示例
process_with_features(
    'merged_shuffled_output.csv',
    'merged_with_features.csv'
)