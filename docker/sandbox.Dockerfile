# Hardened execution sandbox for untrusted Solidity + LLM-generated exploits.
# Build:  docker build -t scbh-sandbox:latest -f docker/sandbox.Dockerfile .
#
# Contains the whole analysis/execution toolchain so the host never runs
# untrusted code. Runtime isolation (no network, resource caps, non-root,
# read-only rootfs) is applied by SandboxRunner at `docker run` time.

FROM ghcr.io/foundry-rs/foundry:latest

USER root
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv git curl ca-certificates bash \
    && rm -rf /var/lib/apt/lists/*

# Python security tooling: Slither (static) + Halmos (symbolic).
# The Foundry base image ships pip 22, which has no --break-system-packages.
# Upgrade pip first so that flag exists on both old and PEP 668 images.
RUN python3 -m pip install --no-cache-dir --upgrade pip \
 && python3 -m pip install --no-cache-dir --break-system-packages \
        slither-analyzer halmos

# Aderyn (Rust static analyser). Sits beside Slither in the scout pre-pass.
# Pinned release, installed on /usr/local/bin so the non-root sandbox user can run it.
# The old cyfrinup URL 404s; this is the current official Linux archive.
RUN apt-get update && apt-get install -y --no-install-recommends xz-utils \
 && curl -fsSL -o /tmp/aderyn.tar.xz \
      https://github.com/Cyfrin/aderyn/releases/download/aderyn-v0.6.8/aderyn-x86_64-unknown-linux-gnu.tar.xz \
 && tar -xJf /tmp/aderyn.tar.xz -C /tmp \
 && install -m 0755 /tmp/aderyn-x86_64-unknown-linux-gnu/aderyn /usr/local/bin/aderyn \
 && rm -rf /tmp/aderyn.tar.xz /tmp/aderyn-x86_64-unknown-linux-gnu /var/lib/apt/lists/* \
 && aderyn --version

# solc-select is what Slither lists. The sandbox rootfs is read-only, so the
# artifacts must already exist in the runtime user's home.
RUN python3 -m pip install --no-cache-dir --break-system-packages solc-select \
    && solc-select install \
        0.4.10 0.4.11 0.4.13 0.4.15 0.4.16 0.4.18 0.4.19 \
        0.4.21 0.4.22 0.4.23 0.4.24 0.4.25 0.4.26 0.5.0 0.5.17 0.6.12 0.7.6 \
        0.8.0 0.8.1 0.8.2 0.8.3 0.8.4 0.8.5 0.8.6 0.8.7 0.8.8 0.8.9 0.8.10 \
        0.8.11 0.8.12 0.8.13 0.8.14 0.8.15 0.8.16 0.8.17 0.8.18 0.8.19 0.8.20 \
        0.8.21 0.8.22 0.8.23 0.8.24 0.8.25 0.8.26 0.8.27 0.8.28 \
    && solc-select use 0.8.24 \
    && mkdir -p /home/foundry \
    && cp -a /root/.solc-select /home/foundry/.solc-select \
    && chown -R 1000:1000 /home/foundry/.solc-select

# Non-root runtime user. UID/GID match SandboxRunner (--user=1000:1000).
# The Foundry base image may already own uid/gid 1000; reuse it.
RUN if ! getent group 1000 >/dev/null; then groupadd -g 1000 sbx; fi \
 && if ! getent passwd 1000 >/dev/null; then useradd -m -u 1000 -g 1000 sbx; fi
USER 1000:1000

# Forge resolves solc from ~/.svm and would download a missing version at audit
# time. The runtime sandbox has no network, so cache the range here as uid 1000.
RUN for v in \
      0.8.0 0.8.1 0.8.2 0.8.3 0.8.4 0.8.5 0.8.6 0.8.7 0.8.8 0.8.9 0.8.10 \
      0.8.11 0.8.12 0.8.13 0.8.14 0.8.15 0.8.16 0.8.17 0.8.18 0.8.19 0.8.20 \
      0.8.21 0.8.22 0.8.23 0.8.24 0.8.25 0.8.26 0.8.27 0.8.28 \
      0.7.6 0.6.12 0.5.17 0.4.26 ; do \
      d="/tmp/solc-$v" && mkdir -p "$d/src" \
      && printf '%s\n' '[profile.default]' 'src = "src"' "solc = \"$v\"" > "$d/foundry.toml" \
      && printf '%s\n' "pragma solidity $v;" 'contract C { uint256 public x; }' > "$d/src/C.sol" \
      && (cd "$d" && forge build) || echo "solc $v cache failed" ; \
      rm -rf "$d" ; \
    done \
 && test -x "$HOME/.svm/0.8.17/solc-0.8.17" \
 && test -x "$HOME/.svm/0.8.19/solc-0.8.19" \
 && test -x "$HOME/.svm/0.8.24/solc-0.8.24" \
 && test -x "$HOME/.svm/0.8.25/solc-0.8.25"

# Aderyn fetches solc on first run. Seed it now so the read-only sandbox does not.
RUN mkdir -p /tmp/aderyn-seed/src \
 && printf '%s\n' '[profile.default]' 'src = "src"' 'solc = "0.8.24"' > /tmp/aderyn-seed/foundry.toml \
 && printf '%s\n' 'pragma solidity ^0.8.24;' 'contract C { uint256 public x; }' > /tmp/aderyn-seed/src/C.sol \
 && cd /tmp/aderyn-seed && aderyn . --output /tmp/aderyn-seed/report.md \
 && rm -rf /tmp/aderyn-seed

WORKDIR /work

# Drop Foundry's `/bin/sh -c` entrypoint so `docker run` executes bash.
ENTRYPOINT []
CMD ["bash"]
