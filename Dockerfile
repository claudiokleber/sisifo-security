FROM python:3.12-slim
WORKDIR /app
COPY requirements-docker.lock ./
RUN pip install --no-cache-dir -r requirements-docker.lock
COPY pyproject.toml README.md ./
COPY sisifo ./sisifo
RUN pip install --no-cache-dir --no-deps .
ENV SISIFO_DATA_DIR=/data PYTHONUNBUFFERED=1
ENTRYPOINT ["sisifo"]
CMD ["--help"]
