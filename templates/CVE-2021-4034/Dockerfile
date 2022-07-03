FROM ubuntu:latest

RUN apt -q update && \
    apt -q -y install libpolkit-gobject-1-0=0.105-26ubuntu1 libpolkit-agent-1-0=0.105-26ubuntu1 policykit-1=0.105-26ubuntu1

RUN useradd -m -s /bin/bash low && \
    mkdir -p /opt/test && \
    chown low:low /opt/test && \
    chmod 777 /opt/test

WORKDIR /opt/test

COPY pwnkit /opt/test/pwnkit

RUN chmod +x /opt/test/pwnkit && \
    chown low:low /opt/test/pwnkit

USER low
