FROM ubuntu:xenial

MAINTAINER 3Di <3Di@nelen-schuurmans.nl>

# change the date to force rebuilding the whole image
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

# Install buildout with pip so bootstrap.py isn't needed.
RUN pip install zc.buildout

VOLUME /buildout
WORKDIR /buildout
