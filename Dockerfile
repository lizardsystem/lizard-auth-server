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

WORKDIR /code

RUN python3 -m venv .
COPY . .
RUN bin/pip install -U pip setuptools wheel
RUN bin/pip install -r requirements.txt
RUN mkdir -p var/log var/media var/static
RUN bin/python manage.py collectstatic --noinput
