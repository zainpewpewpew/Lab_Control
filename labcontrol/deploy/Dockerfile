FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY server.py .
COPY web/ ./web/
RUN mkdir -p /app/state
EXPOSE 8443
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8443"]
