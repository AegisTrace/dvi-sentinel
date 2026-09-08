FROM python:3.13-slim
WORKDIR /opt/dvi
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir . && useradd --create-home --uid 10001 dvi
USER 10001:10001
CMD ["dvi", "--help"]
