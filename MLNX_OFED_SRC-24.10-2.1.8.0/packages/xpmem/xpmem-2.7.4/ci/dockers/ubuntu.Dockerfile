ARG OS_VERSION
FROM ubuntu:${OS_VERSION}

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get -qq install -y \
        automake \
        bison \
        build-essential \
        bzip2 \
        debhelper \
        dkms \
        flex \
        git \
        libtool \
        rpm \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

