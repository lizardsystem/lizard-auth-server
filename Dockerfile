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

RUN mkdir -p /root/.buildout/eggs && \
    echo '[buildout]\neggs-directory = /root/.buildout/eggs' > /root/.buildout/default.cfg

# pip packages
RUN pip install zc.buildout

ADD . /code
WORKDIR /code

RUN buildout
