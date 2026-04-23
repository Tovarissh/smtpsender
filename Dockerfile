FROM python:3.11-slim

LABEL maintainer="smtpsender"
LABEL description="SMTP群发工具 Web控制台 v5.6.0"

WORKDIR /app

# 安装系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# 复制依赖文件并安装
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制项目文件（build context = smtpsender 目录）
COPY . /app/smtpsender/
RUN cp /app/smtpsender/web_server.py /app/web_server.py
RUN cp -r /app/smtpsender/static /app/static 2>/dev/null || true

# 创建输出目录
RUN mkdir -p /app/output /app/data

# 暴露端口
EXPOSE 8080

# 健康检查
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/api/status')" || exit 1

# 环境变量
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# 启动命令
CMD ["python3", "/app/web_server.py"]
