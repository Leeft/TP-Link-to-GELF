FROM debian:trixie-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends libdata-printer-perl libtry-tiny-perl libio-compress-perl libjson-xs-perl libreadonly-perl && \
    rm -rf /var/lib/apt/lists/*

EXPOSE 514

WORKDIR /opt

COPY bin/tp-link-graylog-forwarder.pl /opt/tp-link-graylog-forwarder.pl

ENTRYPOINT ["perl", "tp-link-graylog-forwarder.pl"]