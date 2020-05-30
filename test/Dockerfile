FROM alpine:3.11.6

LABEL maintainer=<nic.cheneweth@thoughtworks.com>

# packages required for use as a circleci remote-docker primary container
# include edge repo for sudo 1.8.31p1-r1. fixes 'setrlimit(RLIMIT_CORE): Operation not permitted' on distroless
# hadolint ignore=DL3003
RUN echo 'http://dl-3.alpinelinux.org/alpine/edge/main' >> /etc/apk/repositories && \
    apk add --no-cache \
        git==2.24.3-r0 \
        openssh==8.1_p1-r0 \
        tar==1.32-r1 \
        gzip==1.10-r0 \
        ca-certificates==20191127-r1 \
        sudo==1.8.31p1-r1 \
        libintl==0.20.1-r2 && \
        apk --no-cache add --virtual build-dependencies \
        cmake==3.15.5-r0 \
        make==4.2.1-r2 \
        musl-dev==1.1.24-r2 \
        gcc==9.2.0-r4 \
        gettext-dev==0.20.1-r2 && \
    wget https://gitlab.com/rilian-la-te/musl-locales/-/archive/master/musl-locales-master.zip && \
    unzip musl-locales-master.zip && cd musl-locales-master && \
    cmake -DLOCALE_PROFILE=OFF -D CMAKE_INSTALL_PREFIX:PATH=/usr . && \
    make && make install && \
    cd .. && rm -r musl-locales-master && \
    apk del build-dependencies

ENV PATH=/home/circleci/bin:/home/circleci/.local/bin:$PATH \
    MUSL_LOCPATH=/usr/share/i18n/locales/musl \
    LANG="C.UTF-8" \
    LANGUAGE="en_US.UTF-8" \
    LC_ALL="en_US.UTF-8"

ENV USER=circleci
RUN addgroup --gid 3434 -S $USER && \
    adduser --uid 3434 --ingroup $USER --disabled-password $USER && \
    echo "$USER ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/$USER && \
    chmod 0440 /etc/sudoers.d/$USER && \
    mkdir -p /home/circleci/project && \
    chown -R $USER:$USER /home/circleci/project

USER circleci

WORKDIR /home/circleci/project

HEALTHCHECK NONE

