FROM python:3.11-slim

# Variables recomendadas
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# 🔹 Dependencias del sistema
# gcc + libpq-dev → psycopg
# postgresql-client → pg_isready
RUN apt-get update \
    && apt-get install -y gcc libpq-dev postgresql-client \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Dependencias Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Código
COPY . .

EXPOSE 8000
