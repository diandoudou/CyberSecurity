# Phishing Website Detection System | 钓鱼网站检测系统

[English](#english-version) | [中文](#中文版本)

---

## 中文版本

### 项目简介

这是一个基于机器学习的**钓鱼网站检测系统**。通过分析URL和网站特征，使用随机森林算法对网站进行分类，区分合法网站和钓鱼网站。

### 主要功能

- **URL特征提取**：分析URL长度、IP地址使用、子域名、协议类型等特征
- **网站特征分析**：检测网站是否可访问、是否包含iframe、混淆脚本等
- **WHOIS信息查询**：获取域名注册信息进行风险评估
- **机器学习模型**：使用随机森林分类器进行训练和预测
- **图形化用户界面**：提供友好的GUI界面用于单个URL或批量检测
- **数据集处理**：包括数据清洗、合并、打乱等预处理功能

### 项目结构

```
Code/
├── train_model.py                    # 模型训练脚本
├── phishing_detector_ui.py          # 图形化用户界面
├── analyze_the_characteristics.py   # URL和网站特征提取
├── getBadURL.py                     # 获取恶意URL数据
├── getDataSet.py                    # 获取数据集
├── legit_url_filter.py              # 合法URL过滤器
├── loess_visualization.py           # LOESS可视化分析
├── merge_and_shuffle.py             # 数据合并和打乱
├── phishing_detection_model.joblib  # 训练好的模型文件
├── 1.2w.csv                         # 数据集
└── README.md                        # 项目说明文档
```

### 主要模块说明

| 文件名 | 功能描述 |
|--------|--------|
| `train_model.py` | 加载数据、特征处理、模型训练和评估 |
| `phishing_detector_ui.py` | Tkinter GUI界面，支持单个或批量URL检测 |
| `analyze_the_characteristics.py` | 提取URL特征、查询WHOIS信息、检测网站特性 |
| `getBadURL.py` | 从数据源爬取恶意URL |
| `getDataSet.py` | 获取并处理合法URL数据集 |
| `legit_url_filter.py` | 对合法URL进行过滤和清理 |
| `loess_visualization.py` | 进行LOESS回归可视化分析 |
| `merge_and_shuffle.py` | 合并不同来源数据并随机打乱 |

### 环境要求

- Python 3.7+
- pandas
- numpy
- scikit-learn
- requests
- tkinter (通常随Python一起安装)
- joblib

### 安装依赖

```bash
pip install pandas numpy scikit-learn requests joblib
```

### 使用方法

#### 1. 训练模型

```bash
python train_model.py
```

#### 2. 使用GUI检测钓鱼网站

```bash
python phishing_detector_ui.py
```

在打开的界面中：
- 输入单个URL并点击"检测"按钮进行分类
- 点击"选择文件"上传URL列表进行批量检测
- 查看分类结果（Phishing / Legit）和分类置信度

#### 3. 数据处理流程

```bash
python getDataSet.py           # 获取数据集
python getBadURL.py            # 获取恶意URL
python legit_url_filter.py     # 过滤合法URL
python merge_and_shuffle.py    # 合并和打乱数据
python train_model.py          # 训练模型
```

### 特征说明

系统提取的主要特征包括：

**URL特征：**
- `url_length`: URL长度
- `has_ip`: 是否使用IP地址
- `dot_count`: 点号数量
- `protocol_http`: 是否使用HTTP协议
- `protocol_https`: 是否使用HTTPS协议
- `subdomain_count`: 子域名数量

**网站特征：**
- `dns_valid`: DNS是否有效
- `site_accessible`: 网站是否可访问
- `has_iframe`: 是否包含iframe
- `has_obfuscated_script`: 是否包含混淆脚本
- `whois_available`: WHOIS信息是否可用

### 模型性能

使用随机森林分类器，通过交叉验证和测试集评估模型性能：
- 训练/测试集划分比例：80/20
- 交叉验证折数：5折
- 输出分类报告和混淆矩阵

### 常见问题

**Q: 运行时出现"Model loading failed"提示？**
A: 需要先运行`train_model.py`生成`phishing_detection_model.joblib`文件。

**Q: WHOIS查询失败？**
A: 某些域名可能无法查询，系统会自动处理异常。

**Q: 批量检测很慢？**
A: 系统需要验证每个URL的真实性，包括DNS查询和网站访问，建议使用较小的URL列表测试。

### 作者

Created by: 兜兜

### 许可证

本项目采用MIT许可证

---

## English Version

### Project Introduction

This is a **Phishing Website Detection System** based on machine learning. By analyzing URL and website features, it uses a Random Forest algorithm to classify websites and distinguish between legitimate sites and phishing sites.

### Main Features

- **URL Feature Extraction**: Analyze URL length, IP address usage, subdomains, protocol types, and other features
- **Website Feature Analysis**: Detect website accessibility, iframes, obfuscated scripts, etc.
- **WHOIS Information Query**: Retrieve domain registration information for risk assessment
- **Machine Learning Model**: Train and predict using Random Forest classifier
- **Graphical User Interface**: User-friendly GUI for single URL or batch detection
- **Dataset Processing**: Includes data cleaning, merging, and shuffling functions

### Project Structure

```
Code/
├── train_model.py                    # Model training script
├── phishing_detector_ui.py          # Graphical user interface
├── analyze_the_characteristics.py   # URL and website feature extraction
├── getBadURL.py                     # Fetch malicious URL data
├── getDataSet.py                    # Fetch dataset
├── legit_url_filter.py              # Legitimate URL filter
├── loess_visualization.py           # LOESS visualization analysis
├── merge_and_shuffle.py             # Data merging and shuffling
├── phishing_detection_model.joblib  # Trained model file
├── 1.2w.csv                         # Dataset
└── README.md                        # Project documentation
```

### Module Description

| Filename | Function |
|----------|----------|
| `train_model.py` | Load data, feature processing, model training and evaluation |
| `phishing_detector_ui.py` | Tkinter GUI interface for single or batch URL detection |
| `analyze_the_characteristics.py` | Extract URL features, query WHOIS information, detect website characteristics |
| `getBadURL.py` | Crawl malicious URLs from data sources |
| `getDataSet.py` | Fetch and process legitimate URL datasets |
| `legit_url_filter.py` | Filter and clean legitimate URLs |
| `loess_visualization.py` | LOESS regression visualization analysis |
| `merge_and_shuffle.py` | Merge different data sources and shuffle randomly |

### Requirements

- Python 3.7+
- pandas
- numpy
- scikit-learn
- requests
- tkinter (usually comes with Python)
- joblib

### Install Dependencies

```bash
pip install pandas numpy scikit-learn requests joblib
```

### Usage

#### 1. Train the Model

```bash
python train_model.py
```

#### 2. Use GUI for Phishing Detection

```bash
python phishing_detector_ui.py
```

In the opened interface:
- Enter a single URL and click the "Detect" button for classification
- Click "Select File" to upload a URL list for batch detection
- View classification results (Phishing / Legit) and confidence scores

#### 3. Data Processing Workflow

```bash
python getDataSet.py           # Fetch dataset
python getBadURL.py            # Fetch malicious URLs
python legit_url_filter.py     # Filter legitimate URLs
python merge_and_shuffle.py    # Merge and shuffle data
python train_model.py          # Train model
```

### Features Description

Main features extracted by the system:

**URL Features:**
- `url_length`: URL length
- `has_ip`: Whether IP address is used
- `dot_count`: Number of dots
- `protocol_http`: Whether HTTP protocol is used
- `protocol_https`: Whether HTTPS protocol is used
- `subdomain_count`: Number of subdomains

**Website Features:**
- `dns_valid`: Whether DNS is valid
- `site_accessible`: Whether the website is accessible
- `has_iframe`: Whether iframe is included
- `has_obfuscated_script`: Whether obfuscated script is included
- `whois_available`: Whether WHOIS information is available

### Model Performance

Using Random Forest classifier with cross-validation and test set evaluation:
- Train/Test split ratio: 80/20
- Cross-validation folds: 5
- Output classification report and confusion matrix

### FAQ

**Q: I see "Model loading failed" message when running the program?**
A: You need to run `train_model.py` first to generate the `phishing_detection_model.joblib` file.

**Q: WHOIS query failed?**
A: Some domains may not be queryable; the system will handle exceptions automatically.

**Q: Batch detection is slow?**
A: The system needs to verify the authenticity of each URL, including DNS queries and website access. It's recommended to test with smaller URL lists.

### Author

Created by: 兜兜

### License

This project is licensed under the MIT License
