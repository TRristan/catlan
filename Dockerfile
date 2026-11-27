FROM rust:1-alpine AS build
RUN apk add --no-cache build-base
WORKDIR /src
COPY Cargo.toml Cargo.lock build.rs ./
COPY src src
COPY kitty kitty
RUN cargo build --release --locked

FROM alpine:3
# ca-certificates: para comprobar webs HTTPS y avisar por Telegram o webhooks
# su-exec: arranca como root solo para dejar /data al usuario catlan (instalaciones de antes) y suelta los permisos
RUN apk add --no-cache ca-certificates su-exec && adduser -D -H -u 10001 catlan
COPY --from=build /src/target/release/catlan /usr/local/bin/catlan
ENV CATLAN_DATA=/data CATLAN_PORT=8080
VOLUME /data
EXPOSE 8080 514/udp
# Docker 20.10+ ya deja a un usuario normal usar ping y puertos bajos (514) dentro del contenedor
CMD ["sh", "-c", "chown -R catlan:catlan /data && exec su-exec catlan catlan"]
