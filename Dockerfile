# ubuntu trusty base image for building other images within N & S
#
# build
# $ docker build -f Dockerfile.ubuntu-trusty-base -t nens/ubuntu-trusty-base:latest .
#
# release
# $ docker tag <image_id> dockrepo.lizard.net/nens/ubuntu-trusty-base:latest
#
# push it to the registry
# $ docker push dockrepo.lizard.net/nens/ubuntu-trusty-base:latest
#

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

# pip packages
RUN pip install zc.buildout

ADD . /code
WORKDIR /code

RUN buildout
