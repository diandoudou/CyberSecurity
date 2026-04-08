import csv
import threading
import queue
from urllib.parse import urlparse

# 配置参数
MAX_WORKERS = 50  # 线程池大小
TIMEOUT = 5  # 请求超时时间
BATCH_SIZE = 1000  # 每批处理数量
INPUT_FILE = "outputgood.csv"  # 输入URL文件
OUTPUT_FILE = "good_output.csv"  # 输出合法URL文件

# 共享队列和锁
url_queue = queue.Queue()
lock = threading.Lock()
legit_urls = []


def is_legit(url):
    """检查URL是否为合法网站(非钓鱼网站)"""
    try:
        # 先检查是否已达到11万条限制
        with lock:
            if len(legit_urls) >= 110000:
                return False

        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return False

        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()

        # 1. 检测可疑域名特征
        phishing_keywords = ['login', 'verify', 'account', 'secure', 'banking',
                             'update', 'confirm', 'password', 'credential', 'auth',
                             'signin', 'authentication', 'wallet', 'payment']
        if any(keyword in domain or keyword in path or keyword in query for keyword in phishing_keywords):
            return False

        # 2. 检测域名仿冒
        legit_domains = ['google.com', 'facebook.com', 'amazon.com', 'apple.com']  # 常见正规域名列表
        for legit_domain in legit_domains:
            if legit_domain.replace('.', '') in domain.replace('.', ''):
                if domain != legit_domain:  # 相似但不完全相同
                    return False

        # 2. 检测域名仿冒
        if '//' in path or '..' in path:
            return False

        return True

    except Exception as e:
        print(f"Error processing URL {url}: {e}")
        return False


def worker():
    """工作线程函数"""
    while True:
        try:
            url = url_queue.get()
            if url is None:  # 结束信号
                break

            is_valid = is_legit(url)
            print(f"Checked URL: {url} - {'Valid' if is_valid else 'Invalid'}")

            if is_valid:
                with lock:
                    if len(legit_urls) < 110000:
                        legit_urls.append(url)
                        print(f"Found {len(legit_urls)} legit URLs: {url}")

        except Exception as e:
            print(f"Error in worker thread: {e}")
        finally:
            url_queue.task_done()


def process_urls():
    """主处理函数"""
    MAX_LEGIT_URLS = 110000  # 最大合法URL数量

    # 读取输入URL
    try:
        with open(INPUT_FILE, 'r') as f:
            reader = csv.reader(f)
            urls = [row[1].strip('"') for row in reader if len(row) > 1]
        print(f"Read {len(urls)} URLs from {INPUT_FILE}")
    except Exception as e:
        print(f"Error reading input file: {e}")
        return

    # 分批处理
    for i in range(0, len(urls), BATCH_SIZE):
        batch = urls[i:i + BATCH_SIZE]

        # 启动工作线程
        threads = []
        for _ in range(MAX_WORKERS):
            t = threading.Thread(target=worker)
            t.start()
            threads.append(t)

        # 添加任务到队列
        for url in batch:
            url_queue.put(url)
            # 检查是否达到最大数量
            with lock:
                if len(legit_urls) >= MAX_LEGIT_URLS:
                    break

        # 等待完成
        url_queue.join()

        # 停止工作线程
        for _ in range(MAX_WORKERS):
            url_queue.put(None)
        for t in threads:
            t.join()

        print(f"Processed {min(i + BATCH_SIZE, len(urls))}/{len(urls)} URLs, Found {len(legit_urls)} legit URLs")

        # 检查是否达到最大数量
        with lock:
            if len(legit_urls) >= MAX_LEGIT_URLS:
                print(f"Reached maximum {MAX_LEGIT_URLS} legit URLs, stopping...")
                break

    # 保存结果
    try:
        with open(OUTPUT_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            for url in legit_urls[:MAX_LEGIT_URLS]:  # 确保不超过最大数量
                writer.writerow([url])
        print(f"Saved {len(legit_urls)} legitimate URLs to {OUTPUT_FILE}")
    except Exception as e:
        print(f"Error writing output file: {e}")


if __name__ == "__main__":
    process_urls()
    print(f"Found {len(legit_urls)} legitimate URLs. Saved to {OUTPUT_FILE}")
