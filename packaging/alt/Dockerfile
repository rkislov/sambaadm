FROM alt:p10
RUN apt-get update && apt-get install -y rpm-build file shadow-utils systemd util-linux tar coreutils && apt-get clean
RUN apt-get install -y systemd-analyze && apt-get clean
RUN groupadd -r rpm-builder && useradd -r -g rpm-builder -d /tmp -s /bin/false rpm-builder
WORKDIR /src
