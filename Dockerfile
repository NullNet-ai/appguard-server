FROM rust

ARG VERSION_TAG
ARG API_KEY
ARG MMDB_KEY

WORKDIR /AppGuard

COPY . /AppGuard

EXPOSE 50051

RUN apt-get clean
RUN apt-get update
RUN apt-get install -y protobuf-compiler

RUN VERSION_TAG=${VERSION_TAG} API_KEY=${API_KEY} MMDB_KEY=${MMDB_KEY} cargo build --release

CMD ["./target/release/appguard"]
