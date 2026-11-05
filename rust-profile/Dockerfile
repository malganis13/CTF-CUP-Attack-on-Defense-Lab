FROM rust:1.82-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release

FROM alpine:3.20
RUN addgroup -S app && adduser -S -G app app && mkdir -p /data && chown -R app:app /data
COPY --from=build /src/target/release/rust-profile /usr/local/bin/rust-profile
USER app
EXPOSE 8085
ENTRYPOINT ["/usr/local/bin/rust-profile"]
