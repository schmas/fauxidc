FROM scratch
ARG TARGETARCH
COPY dist/${TARGETARCH}/fauxidc /fauxidc
# The example configs, for `docker run <image> --config /examples/generic.toml`.
COPY examples/*.toml /examples/
WORKDIR /config
EXPOSE 9000
HEALTHCHECK --interval=5s --timeout=3s --start-period=1s CMD ["/fauxidc", "healthcheck"]
# --bind is in the entrypoint, so arguments to `docker run` add to it. A later --bind wins.
ENTRYPOINT ["/fauxidc", "--bind", "0.0.0.0"]
