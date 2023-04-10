FROM rust:1.68-slim as builder
WORKDIR /code

COPY ./src ./src
COPY ./.cargo ./.cargo
COPY Cargo.toml ./

ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse
ENV http_proxy=
ENV https_proxy=

RUN cargo build --release

FROM rust:1.68-slim as client
WORKDIR /bin

COPY --from=builder /code/target/release/client /bin/client
COPY ./key /tmp/key

CMD ["/bin/client", "--key=/tmp/key", "--data=186723723", "172.16.238.11", "53"]

FROM rust:1.68-slim as server
WORKDIR /bin

COPY --from=builder /code/target/release/server /bin/server
COPY ./key /tmp/key

CMD ["/bin/server", "--key=/tmp/key", "53"]