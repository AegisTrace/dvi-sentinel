FROM python:3.13.15-slim-bookworm@sha256:ed86c82274b3c69b52fb5820f358f0bd7df0b603332063cb5c6e32bd220c3e6e
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /opt/dvi
COPY requirements-container.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements-container.txt
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir --no-deps . \
    && pip check \
    && groupadd --gid 10001 dvi \
    && useradd --no-log-init --uid 10001 --gid 10001 --create-home dvi \
    && mkdir /runs \
    && chown dvi:dvi /runs
COPY examples ./examples
COPY benchmarks ./benchmarks
USER 10001:10001
CMD ["dvi", "doctor"]
