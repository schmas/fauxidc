FROM scratch
ARG TARGETARCH
COPY dist/${TARGETARCH}/fauxidc /fauxidc
WORKDIR /config
EXPOSE 9000
HEALTHCHECK --interval=5s --timeout=3s --start-period=1s CMD ["/fauxidc", "healthcheck"]
ENTRYPOINT ["/fauxidc"]
CMD ["--bind", "0.0.0.0"]
