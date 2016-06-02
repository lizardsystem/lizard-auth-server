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
# Sympy installs a lot of fonts, latex stuff, etc., which we don't want, so
# that is run with the --no-install-recommends option.
RUN apt-get update && apt-get install -y \
    python-software-properties \
    wget \
    build-essential \
    git \
    libevent-dev \
    libfreetype6-dev \
    libgeos-dev \
    libhdf5-serial-dev \
    libpng12-dev \
    mercurial \
    python-dev \
    python-lxml \
    python-mapnik \
    python-numpy \
    python-pip \
    python-pyproj \
    python-pysqlite2 \
    python-psycopg2 \
    python-scipy \
    spatialite-bin \
    gdal-bin \
    libgdal1i \
    libnetcdf-dev \
    netcdf-bin \
    python-gdal \
    vim \
&& apt-get install -y --no-install-recommends \
    python-sympy \
&& apt-get clean -y && rm -rf /var/lib/apt/lists/*

# pip packages
RUN pip install \
    matplotlib \
    six

ADD . /code
WORKDIR /code

RUN python bootstrap.py \
&& bin/buildout \
&& yes no | bin/django syncdb \
&& bin/django migrate

CMD bin/django runserver 0.0.0.0:5000
