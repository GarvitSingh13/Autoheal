# Ubuntu-based image for every platform component and the lab simulator.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH

RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv python3-dev build-essential \
      libxml2-dev libxslt1-dev libffi-dev libssl-dev ca-certificates curl \
 && python3 -m venv $VIRTUAL_ENV \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY autoheal ./autoheal
COPY simulator ./simulator
RUN pip install --upgrade pip && pip install .

COPY config ./config
RUN useradd --system --home /app autoheal && mkdir -p /app/data && chown -R autoheal /app/data
USER autoheal

EXPOSE 8080 8300 8301-8306
ENTRYPOINT ["autoheal"]
CMD ["run", "all"]
