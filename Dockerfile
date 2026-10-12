FROM python:3.12-slim

# 仅装核心依赖（抖音通道）。其他平台适配器按需追加：
#   pip install playwright && playwright install chromium   # tiktok
#   pip install twikit                                      # x
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir curl_cffi cryptography certifi

COPY app ./app
COPY web ./web
COPY run.py .
RUN mkdir -p data

EXPOSE 8788
VOLUME ["/app/data"]

# 凭据不入镜像：data/ 目录挂载宿主机，账号通过 /api/accounts 从 0 添加
# （见 docs/harvest-douyin.md）。出代理在启动时传 --proxy。
CMD ["python", "run.py", "--host", "0.0.0.0", "--port", "8788"]
