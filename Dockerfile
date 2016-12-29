FROM ubuntu:16.04

MAINTAINER Mario Zieschang <mziescha@cpan.org>

RUN    apt-get update && apt-get upgrade -y && apt-get install -y make curl g++ gcc libssl-dev build-essential \
    && curl -L https://cpanmin.us | perl - App::cpanminus \
    && cpanm \
        Carp \
        Pod::Usage \
        Getopt::Long \
        DDP \
        Term::ReadKey \
        Pod::Coverage::TrustPod \
        Pod::Usage \
        Test::CheckManifest \
        Test::Pod \
        Test::Pod::Coverage \
        Test::Requires \
        Test::Spelling \
        Test::Net::LDAP \
        Devel::Cover \
        Devel::Cover::Report::Coveralls \
    && apt-get remove --purge -y curl \
    && apt-get autoremove -y && apt-get clean && apt-get autoclean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /root/.cpanm/* /usr/share/man/* /usr/local/share/man/*

RUN    cpanm \
        Dancer2 \
        Auth::ActiveDirectory \
    && apt-get autoremove -y && apt-get clean && apt-get autoclean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /root/.cpanm/* /usr/share/man/* /usr/local/share/man/*

WORKDIR /app