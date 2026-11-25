ARG ALT_BRANCH=p10
FROM alt:${ALT_BRANCH}
ARG ALT_BRANCH
ARG ALT_APT_MIRRORS="http://mirror.yandex.ru/altlinux http://mirror.truenetwork.ru/altlinux http://ftp.altlinux.org/pub/distributions/ALTLinux"
COPY packaging/alt/install-build-deps.sh /tmp/install-build-deps.sh
RUN ALT_APT_BRANCH="$ALT_BRANCH" SAMBAADM_RPM_CONTAINER_BUILD=1 bash /tmp/install-build-deps.sh && rm /tmp/install-build-deps.sh
RUN groupadd -r rpm-builder && useradd -r -g rpm-builder -d /tmp -s /bin/false rpm-builder
WORKDIR /src
