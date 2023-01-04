FROM --platform=linux/amd64 ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && \
    apt upgrade -y && \
    apt install -y curl file && \
    rm -rf /var/lib/apt/lists/*

# installing protostar
RUN curl -L https://raw.githubusercontent.com/software-mansion/protostar/master/install.sh | bash
ENV PATH="/root/.protostar/dist/protostar:${PATH}"

VOLUME [ /slush ]
WORKDIR /slush
EXPOSE 26656 26657
ENTRYPOINT ["/usr/bin/wrapper.sh"]
CMD ["node", "--proxy-app", "kvstore"]
STOPSIGNAL SIGTERM

COPY wrapper.sh /usr/bin/wrapper.sh
COPY config-template.toml /etc/slush/config-template.toml
