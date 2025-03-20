ARG OS_VERSION
FROM centos:${OS_VERSION}

ARG OS_VERSION
RUN sed -i -e "s|mirrorlist=|#mirrorlist=|g" /etc/yum.repos.d/CentOS-* && \
    sed -i -e "s|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g" /etc/yum.repos.d/CentOS-* ;

RUN yum install -y epel-release && \
    yum install -y \
        automake \
        bison \
        bzip2 \
        dkms \
        elfutils-libelf-devel \
        environment-modules \
        flex \
        git \
        kernel-devel \
        kernel-headers \
        libtool \
        make \
        rpm-build \
        sudo \
    && yum clean all
