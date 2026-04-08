import re
import requests
from datetime import datetime
import socket
import time

def get_whois_info(domain):
    """使用第三方API查询WHOIS信息"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0',
        'Referer': 'https://www.whoiscx.com/',
        'Sec-Ch-Ua': '"Microsoft Edge";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
        'Sec-Ch-Ua-Mobile': '?0',
        'Sec-Ch-Ua-Platform': '"Windows"',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
        'Origin': 'https://www.whoiscx.com',
        'Priority': 'u=1, i'
    }
    
    try:
        response = requests.get(
            f'https://api.uutool.cn/whois/info/?domain={domain}',
            headers=headers,
            timeout=10
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"WHOIS API查询失败: {str(e)}")
        return None

def extract_url_features(url):
    features = {}

    # Address bar-based features
    # URL length
    features['url_length'] = len(url)

    # IP address usage
    ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    features['has_ip'] = 1 if ip_pattern.search(url) else 0

    # Number of dots
    features['dot_count'] = url.count('.')

    # Protocol
    protocol = url.split('://')[0]
    features['protocol_http'] = 1 if protocol == 'http' else 0
    features['protocol_https'] = 1 if protocol == 'https' else 0

    # Number of subdomains
    domain_parts = url.split('://')[-1].split('/')[0].split('.')
    features['subdomain_count'] = len(domain_parts) - 2 if len(domain_parts) > 2 else 0

    # Domain-based features
    try:
        domain = url.split('://')[-1].split('/')[0]
        whois_data = get_whois_info(domain)
        time.sleep(1)
        
        if whois_data and whois_data.get('status') == 1:
            # Flatten the WHOIS data
            data = whois_data.get('data', {})
            info = data.get('info', {})
            summary = data.get('summary', {})
            
            # Add WHOIS information to features
            features['whois_available'] = data.get('available', 0)
            features['whois_registrar'] = info.get('registrar', '')
            features['whois_registration_time'] = info.get('registrationTime', '')
            features['whois_expiration_time'] = info.get('expirationTime', '')
            features['whois_name_server'] = ','.join(info.get('nameServer', []))
            
            # Domain age
            create_time = info.get('registrationTime') or summary.get('creation_date')
            if create_time:
                try:
                    if 'T' in create_time:
                        create_date = datetime.strptime(create_time.split('T')[0], '%Y-%m-%d')
                    else:
                        create_date = datetime.strptime(create_time, '%Y-%m-%d %H:%M:%S')
                    features['domain_age'] = (datetime.now() - create_date).days
                except ValueError:
                    features['domain_age'] = None
        else:
            features['domain_age'] = None

        # Validity of DNS record
        try:
            socket.gethostbyname(domain)
            features['dns_valid'] = 1
        except socket.gaierror:
            features['dns_valid'] = 0

        # Measurement of website traffic and WHOIS information
        try:
            response = requests.get(url, timeout=5)
            features['site_accessible'] = 1 if response.status_code == 200 else 0
        except requests.RequestException:
            features['site_accessible'] = 0

    except Exception as e:
        print(f"Error getting domain features: {e}")
        features.update({
            'whois_data': None,
            'domain_age': None,
            'dns_valid': None,
            'site_accessible': None
        })

    # HTML and JavaScript-based features
    try:
        response = requests.get(url, timeout=5)
        html_content = response.text

        # Presence of inline frames
        features['has_iframe'] = 1 if '<iframe' in html_content else 0
        # Obfuscated scripts
        features['has_obfuscated_script'] = 1 if ('eval(' in html_content or 'document.write(' in html_content) else 0
    except requests.RequestException:
        features['has_iframe'] = None
        features['has_obfuscated_script'] = None

    return features


# 示例使用
url = "https://cn.bing.com/search?q=wegame&qs=n&form=QBRE&sp=-1&lq=0&pq=wegame&sc=13-6&sk=&cvid=7B6B52941C56458BBC41223742D28F52"
features = extract_url_features(url)
for feature, value in features.items():
    print(f"{feature}: {value}")