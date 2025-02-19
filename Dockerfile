FROM rust

ARG VERSION_TAG
ARG API_KEY

WORKDIR /AppGuard

COPY . /AppGuard

EXPOSE 50051

RUN apt-get clean
RUN apt-get update
RUN apt-get install -y protobuf-compiler

RUN VERSION_TAG=${VERSION_TAG} API_KEY=${API_KEY} cargo build --release --features no-ai,no-tls

CMD ["./target/release/appguard-server"]
