# Custom Caddy build embedding the Phase 5 timing_probe module
# (proxy/timingprobe/) via xcaddy. Everything else about the proxy is
# unchanged from the stock caddy:alpine image previously used directly --
# see README.md.
#
# This is incremental, not a new category of change: the persona containers
# already need custom images for their own header/module requirements, so a
# built (rather than pulled-as-is) proxy image doesn't change the project's
# operational shape.

FROM caddy:2.11.4-builder-alpine AS builder

COPY timingprobe /timingprobe
COPY sourcehash /sourcehash
COPY traps /traps

RUN xcaddy build \
    --with github.com/chameleon-honeypot/timingprobe=/timingprobe \
    --with github.com/chameleon-honeypot/sourcehash=/sourcehash \
    --with github.com/chameleon-honeypot/traps=/traps

FROM caddy:2.11.4-alpine

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
