FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y apt-utils

RUN apt update && apt install -y software-properties-common

#Install Build Essentials
RUN apt install -y build-essential checkinstall

RUN apt update && \
    apt install -y \
    cmake \
    git \
    wget \
    sudo \
    less \
    vim \
    socat \
    unzip \
    libboost-dev \
    libboost-filesystem-dev \
    libboost-thread-dev \
    libboost-date-time-dev \
    libboost-iostreams-dev \
    libboost-system-dev \
    lcov \
    libeigen3-dev \
    libvtk6-dev \
    libqhull-dev \
    libflann-dev \
    libopenni-dev \
    libffi-dev \
    libyaml-cpp-dev \
    libreadline-gplv2-dev \
    libncursesw5-dev \
    libssl-dev \
    libsqlite3-dev \
    tk-dev \
    libgdbm-dev \
    libc6-dev \
    libbz2-dev \
    gawk \
    git-core \
    diffstat \
    unzip \
    texinfo \
    gcc-multilib \
    chrpath \
    make \
    xsltproc \
    docbook-utils \
    fop \
    dblatex \
    xmlto \
    sqlite3 \
    asciidoctor \
    sendmail mailutils \
    libsasl2-dev python3-dev python3-pip libldap2-dev libssl-dev \
    ldap-utils

# RUN gem install asciidoctor-pdf

#Install QT5
RUN apt update && \
    apt install -y qt5-default libqt5x11extras5

RUN pip3 install requests django pandas python-decouple python-ldap xlrd bokeh matplotlib xlsxwriter datetime Sphinx gitpython progress openpyxl aiohttp asyncio reportlab beautifulsoup4 django-cors-headers djangorestframework django-auth-ldap djangorestframework-simplejwt psutil django-cron


RUN pip3 install django

RUN apt-get update && apt-get -y install cron

CMD bash
