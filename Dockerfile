FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download || true
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /relay ./cmd/relay

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /relay /relay
EXPOSE 8080 9090
VOLUME ["/data"]
ENTRYPOINT ["/relay"]
CMD ["-db", "/data/relay.db", "-listen", ":8080", "-metrics", ":9090"]
