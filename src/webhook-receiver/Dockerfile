FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Azure Functions custom handler listens on this port
EXPOSE 80

CMD ["python", "-m", "uvicorn", "function_app:app", "--host", "0.0.0.0", "--port", "80"]
