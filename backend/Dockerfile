FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libffi-dev libxml2 libxslt1.1 curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p /tmp/drr_reports

ENV PYTHONPATH=/app
ENV OUTPUT_DIR=/tmp/drr_reports

EXPOSE 8000
CMD ["uvicorn", "app.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
