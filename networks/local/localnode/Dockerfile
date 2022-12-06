FROM alpine:3.14

RUN apk update && \
    apk upgrade && \
    apk --no-cache add curl jq file python3-dev py3-pip g++ gmp-dev

# installing cairo-lang
RUN pip3 install --no-cache-dir wheel ecdsa fastecdsa sympy cairo-lang

VOLUME [ /slush ]
WORKDIR /slush
EXPOSE 26656 26657
ENTRYPOINT ["/usr/bin/wrapper.sh"]
CMD ["node", "--proxy-app", "kvstore"]
STOPSIGNAL SIGTERM

COPY wrapper.sh /usr/bin/wrapper.sh
COPY config-template.toml /etc/slush/config-template.toml
