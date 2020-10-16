FROM ubuntu:xenial

# system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    python3-pip \
    python3-venv \
    python3-wheel \
    gettext \
    postgresql-client \
&& apt-get clean -y && rm -rf /var/lib/apt/lists/*

# Linux uid/gid handling.
ARG uid=1000
ARG gid=1000
RUN groupadd -g $gid nens && useradd -lm -u $uid -g $gid nens
WORKDIR /code
RUN chown nens:nens /code
USER nens

VOLUME /code
