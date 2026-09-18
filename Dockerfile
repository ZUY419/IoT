FROM python:3.11-slim-bookworm

# 設定環境變數，避免 Python 產生 .pyc 檔案，並讓輸出即時印出
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# 1. 安裝基礎探測與執行環境工具
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    iputils-ping \
    curl \
    perl \
    docker.io \
    whatweb \
    && rm -rf /var/lib/apt/lists/*

# 2. 這次真的換成 codeload 專用直鏈網址了，請不要變更它
RUN curl -sSL "https://github.com/sullo/nikto/archive/refs/tags/2.5.0.tar.gz" -o /tmp/nikto.tar.gz \
    && mkdir -p /opt/nikto \
    && tar -xzf /tmp/nikto.tar.gz -C /opt/nikto --strip-components=1 \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /usr/local/bin/nikto \
    && rm /tmp/nikto.tar.gz

# 3. 安裝 Python 套件
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip3 install --no-cache-dir packaging requests

# 4. 複製專案程式碼
COPY . .

CMD ["python", "main.py"]
# CMD ["tail", "-f", "/dev/null"]
