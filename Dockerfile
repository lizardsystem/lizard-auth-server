FROM ubuntu:xenial

MAINTAINER OPS <ops@nelen-schuurmans.nl>

# Change the date to force rebuilding the whole image
ENV REFRESHED_AT 20160531

# system dependencies
RUN apt-get update && apt-get install -y \
    python-software-properties \
    wget \
    build-essential \
    git \
    libevent-dev \
    libfreetype6-dev \
    libgeos-dev \
    libpng12-dev \
    python-dev \
    python-pip \
    python-psycopg2 \
    python-gdal \
&& apt-get clean -y && rm -rf /var/lib/apt/lists/*

VOLUME /code
WORKDIR /code
