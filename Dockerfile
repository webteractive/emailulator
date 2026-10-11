# syntax=docker/dockerfile:1

# The server-only build: no `desktop` feature, so nothing here needs a display.
FROM rust:1.92-slim-bookworm AS build
WORKDIR /src

COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
COPY ui ./ui
COPY data ./data

# There is no .git in the build context; pass these to stamp `--version`:
#   --build-arg EMAILULATOR_GIT_SHA=$(git rev-parse --short HEAD)
#   --build-arg EMAILULATOR_GIT_DATE=$(git log -1 --format=%cs)
ARG EMAILULATOR_GIT_SHA=""
ARG EMAILULATOR_GIT_DATE=""
ENV EMAILULATOR_GIT_SHA=${EMAILULATOR_GIT_SHA} EMAILULATOR_GIT_DATE=${EMAILULATOR_GIT_DATE}

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
    && cp target/release/emailulator /emailulator \
    && mkdir /data

# No shell, no package manager, and an unprivileged user.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /emailulator /usr/local/bin/emailulator
COPY --from=build --chown=65532:65532 /data /data

# A container's loopback is unreachable from outside it, so the listeners bind
# to every interface. In return the server refuses to start without
# EMAILULATOR_AUTH_TOKEN, and SMTP clients must sign in with an inbox id and
# one of its API keys.
ENV EMAILULATOR_SMTP_ADDR=0.0.0.0:1025 \
    EMAILULATOR_HTTP_ADDR=0.0.0.0:8025 \
    EMAILULATOR_DATA_DIR=/data
VOLUME /data
EXPOSE 1025 8025
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=6s --start-period=5s \
    CMD ["/usr/local/bin/emailulator", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/emailulator"]
CMD ["run"]
