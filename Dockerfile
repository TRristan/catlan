FROM rust:1-alpine AS build
RUN apk add --no-cache build-base
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src src
COPY index.html kitty.ps1 kitty.sh ./
RUN cargo build --release --locked

FROM alpine:3
# ca-certificates: para comprobar webs HTTPS y avisar por Telegram o webhooks
RUN apk add --no-cache ca-certificates
COPY --from=build /src/target/release/catlan /usr/local/bin/catlan
ENV CATLAN_DATA=/data CATLAN_PORT=8080
VOLUME /data
EXPOSE 8080 514/udp
CMD ["catlan"]
