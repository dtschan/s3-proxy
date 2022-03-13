FROM rust:latest AS builder

#RUN mkdir -p $HOME/.cargo && echo "[net] git-fetch-with-cli = true" >>$HOME/.cargo/config
RUN getent hosts github.com

WORKDIR /rust

COPY ./ .

RUN cargo build  --release



FROM registry.access.redhat.com/ubi8-minimal

WORKDIR /rust

# Copy our build
COPY --from=builder /rust/target/release/s3-proxy ./

EXPOSE 8080

ENTRYPOINT ["/rust/s3-proxy"]

