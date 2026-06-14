# Build context is the repo root (see docker-compose.yml). Multi-stage: compile a
# static binary, then ship it on a minimal base. config.ini is bind-mounted at
# /app/config.ini by compose, which is the working directory the server reads
# from.
FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO off: lib/pq and the mysql driver are pure Go, so the binary is static.
RUN CGO_ENABLED=0 go build -o /out/pathql-server .

FROM gcr.io/distroless/static-debian12
WORKDIR /app
COPY --from=build /out/pathql-server /app/pathql-server
EXPOSE 8000 8001
ENTRYPOINT ["/app/pathql-server"]
