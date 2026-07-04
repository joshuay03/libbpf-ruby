FROM ruby:latest

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

RUN apt-get update && apt-get install -y --no-install-recommends \
      clang \
      libbpf-dev \
      libelf-dev \
      linux-libc-dev \
    && rm -rf /var/lib/apt/lists/*

ENV BUNDLE_PATH=/workspace/.bundle
ENV BUNDLE_APP_CONFIG=/workspace/.bundle
ENV PATH=/workspace/bin:${PATH}

WORKDIR /workspace

CMD ["bash"]
