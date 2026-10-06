FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /out/sambaadm ./cmd/sambaadm

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/sambaadm /sambaadm
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/sambaadm"]
CMD ["serve", "--listen=:8080"]
