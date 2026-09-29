# Chameleon honeypot — Attack container (Debian-based)
#
# A lightweight scanner environment on the same Docker network as the honeypot
# stack, used to generate scanner traffic for testing the engine's detection
# and persona-switching behaviour.
#
# Build:
#   docker compose build attacker
#
# Usage:
#   docker compose run attacker            # interactive shell
#   make attack-nikto     # nikto probe blitz
#   make attack-fast      # fast scanner-like probes
#   make attack-nmap      # nmap service scan
#   make attack-human     # browser-like traffic (no detection expected)
#
# Notes:
#   - The proxy is reachable at http://proxy:80 (internal Docker network).
#   - From the host you can also use http://localhost:8080.
#   - Tools: nmap, nikto (from git), gobuster, sqlmap, wget, curl.
#   - dirb is installed for its wordlists only (/usr/share/wordlists/dirb/),
#     used by gobuster's configs -- dirb itself is not otherwise used.
#   - iproute2 (tc) is for Phase 6 generation/generate.py, which shapes this
#     container's own eth0 with netem (delay/jitter/loss) before each run --
#     requires cap_add: NET_ADMIN in docker-compose.yml.
#   - The engine will see this as real scanner traffic and rotate personas
#     (Phase 6 generation pauses the engine for the duration of a run --
#     see generate.py -- so this only applies to ad-hoc manual use).

FROM debian:bookworm-slim

RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
    nmap \
    curl \
    wget \
    ca-certificates \
    perl \
    libxml-writer-perl \
    libnet-ssleay-perl \
    libio-socket-ssl-perl \
    git \
    iproute2 \
    gobuster \
    sqlmap \
    dirb \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install nikto (not in Debian repos — grab from GitHub). Pinned to a tagged
# release, not the default branch: an earlier unpinned build silently picked
# up HEAD, which turned out to carry a port_check() regression (it returns
# an error string instead of the expected 1/2 on success, so nikto reports
# "Unable to connect" against a target curl reaches fine) -- and an unpinned
# tool version also breaks the manifest's tool_version provenance field,
# which is supposed to be an honest record of what actually ran.
ARG NIKTO_VERSION=2.5.0
RUN git clone --branch "${NIKTO_VERSION}" --depth 1 https://github.com/sullo/nikto /opt/nikto && \
    chmod +x /opt/nikto/program/nikto.pl && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

COPY scripts/ /opt/attack/
# A genuinely tiny wordlist (10 entries) for gobuster's broad_scanning
# config -- even dirb's "small" list (959 words) produces enough requests to
# look systematic, not shallow.
COPY wordlists/ /opt/attack/wordlists/

WORKDIR /opt/attack

CMD ["/bin/bash"]