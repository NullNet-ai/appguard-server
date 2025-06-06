FROM rust

ARG VERSION_TAG
ARG IP_INFO_API_KEY

WORKDIR /AppGuard

COPY . /AppGuard

EXPOSE 50051

RUN apt-get clean
RUN apt-get update
RUN apt-get install -y protobuf-compiler

RUN VERSION_TAG=${VERSION_TAG} IP_INFO_API_KEY=${IP_INFO_API_KEY} cargo build --release

CMD ["./target/release/appguard-server"]
