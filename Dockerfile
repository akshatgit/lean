FROM python:3.12-slim AS lean-build

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates curl gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

ENV ELAN_HOME=/opt/elan
ENV PATH=/opt/elan/bin:$PATH

RUN curl -sSfL https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh \
    | sh -s -- -y --default-toolchain none

WORKDIR /build/core
COPY core/ ./
RUN lake build

FROM python:3.12-slim AS runtime

WORKDIR /opt/keyhole
COPY pyproject.toml README.md ./
COPY keyhole/ ./keyhole/
COPY --from=lean-build /build/core/.lake/build/bin/keyhole-core /usr/local/bin/keyhole-core

RUN pip install --no-cache-dir .

ENTRYPOINT ["keyhole"]
CMD ["--help"]
