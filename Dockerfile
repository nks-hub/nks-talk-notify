FROM python:3.12-slim

RUN useradd --create-home --uid 10001 notify
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN mkdir -p /data && chown notify:notify /data
USER notify

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3).status==200 else 1)"

ENTRYPOINT ["python", "-m", "app"]
