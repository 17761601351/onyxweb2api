FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p /app/templates

# 使用 Zeabur 注入的 PORT 环境变量，默认 8080
ENV PORT=8080
EXPOSE 8080

CMD ["python", "main.py"]
