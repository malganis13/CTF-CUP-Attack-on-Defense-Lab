FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/go-files ./

FROM alpine:3.20
RUN addgroup -S app && adduser -S -G app app && mkdir -p /data && chown -R app:app /data
COPY --from=build /out/go-files /usr/local/bin/go-files
USER app
EXPOSE 8084
ENTRYPOINT ["/usr/local/bin/go-files"]
