FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends tgt && rm -rf /var/lib/apt/lists/*
COPY target.sh /usr/local/sbin/lab-target
ENTRYPOINT ["/usr/local/sbin/lab-target"]
