FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# 确保 templates 目录存在
RUN mkdir -p /app/templates

EXPOSE 7860

CMD ["python", "main.py"]