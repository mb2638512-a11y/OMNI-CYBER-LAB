FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/play-verifier .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/play-verifier /play-verifier
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/play-verifier"]
