FROM --platform=linux/amd64 ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install software-properties-common -y && add-apt-repository ppa:deadsnakes/ppa
RUN apt update && apt upgrade -y && apt install -y \
    curl \
    file \
    libgmp3-dev \
    build-essential \
    python3.9 \
    python3.9-venv \
    python3.9-dev
RUN rm -rf /var/lib/apt/lists/*
RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && python3.9 get-pip.py

# installing protostar
RUN curl -L https://raw.githubusercontent.com/software-mansion/protostar/master/install.sh | bash
ENV PATH="/root/.protostar/dist/protostar:${PATH}"

# installing cairo-lang
RUN python3.9 -m venv ~/cairo_venv && . ~/cairo_venv/bin/activate
RUN pip install --compile --no-cache-dir cairo-lang

VOLUME [ /slush ]
WORKDIR /slush
EXPOSE 26656 26657
ENTRYPOINT ["/usr/bin/wrapper.sh"]
CMD ["node", "--proxy-app", "kvstore"]
STOPSIGNAL SIGTERM

COPY wrapper.sh /usr/bin/wrapper.sh
COPY config-template.toml /etc/slush/config-template.toml
