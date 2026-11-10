# nazar's Linux test image: the Go toolchain, a software TPM (swtpm), D-Bus
# and polkitd, OpenSSH, git and kubectl. `make linux` and `make linux-run`
# build it and run run.sh, which copies the read-only source to /work and
# runs the tests as the unprivileged user nazartest. Nothing here talks to
# the host's TPM, polkit or buses: the container has none of them.
#
# Everything is pinned: the base image by digest (the multi-arch index of
# golang:1.26.4-bookworm; bump it with go.mod's go line), the Debian
# packages by the bookworm snapshot of the day this file was written, and
# kubectl by its published sha256 for each architecture.
FROM golang:1.26.4-bookworm@sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b

ARG DEBIAN_SNAPSHOT=20261107T000000Z
ARG KUBECTL_VERSION=v1.37.2
ARG KUBECTL_SHA256_AMD64=c04487523e7aa7d1493f7808174c899db93d7a9cf57531420cd76b9bd415f8f4
ARG KUBECTL_SHA256_ARM64=fcc16f63186659d9722014b7e02d5fdd2d4e669cb8c0ab66365d7d3b8ba03509

SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

RUN rm -f /etc/apt/sources.list.d/debian.sources; \
    printf '%s\n' \
      "deb http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT} bookworm main" \
      "deb http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT} bookworm-updates main" \
      "deb http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT} bookworm-security main" \
      > /etc/apt/sources.list; \
    printf '%s\n' \
      'Acquire::Check-Valid-Until "false";' \
      'Acquire::Retries "5";' \
      > /etc/apt/apt.conf.d/99snapshot; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      swtpm swtpm-tools dbus polkitd pkexec openssh-client openssh-server git procps file; \
    rm -rf /var/lib/apt/lists/*

RUN arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) sum="$KUBECTL_SHA256_AMD64" ;; \
      arm64) sum="$KUBECTL_SHA256_ARM64" ;; \
      *) echo "no kubectl sha256 for $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSLo /usr/local/bin/kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${arch}/kubectl"; \
    echo "${sum}  /usr/local/bin/kubectl" | sha256sum -c -; \
    chmod 0755 /usr/local/bin/kubectl

# The test user. Its password is for the test polkit agent (the polkit tests'
# fixture), which answers polkit's prompt the way a person would.
RUN useradd -m -u 1000 -s /bin/bash nazartest; \
    echo 'nazartest:nazar-test-password' | chpasswd

# A login shell (run.sh uses bash -l) resets PATH from /etc/profile; put Go
# back. The toolchain is the image's: never download another one.
RUN printf '%s\n' 'export PATH=/usr/local/go/bin:/tmp/go/bin:$PATH' > /etc/profile.d/go.sh
ENV GOTOOLCHAIN=local
ENV NAZAR_LINUX_TEST_CONTAINER=1

COPY run.sh /usr/local/bin/nazar-linux-run
ENTRYPOINT ["/usr/local/bin/nazar-linux-run"]
