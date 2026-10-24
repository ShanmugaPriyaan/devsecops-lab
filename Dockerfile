# Current minimal base image, non-root user, health check
FROM python:3.12-slim
WORKDIR /app
COPY app/ /app/
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --system --no-create-home app \
    && chown app /app
USER app
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=3s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/')" || exit 1
CMD ["python", "app.py"]
