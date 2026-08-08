FROM mcr.microsoft.com/azure-functions/python:4-python3.11

WORKDIR /home/site/wwwroot

COPY webhook-receiver/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY prsa_control ./prsa_control
COPY webhook-receiver/ ./
