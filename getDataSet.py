import requests
#从 crawl获得数据
index_url = "https://data.commoncrawl.org/crawl-data/CC-MAIN-2024-43/warc.paths.gz"
#index_url = "https://data.commoncrawl.org/crawl-data/CC-MAIN-2024-43/warc.paths.gz"
response = requests.get(index_url)
with open('warc_paths.gz', 'wb') as f:
    f.write(response.content)