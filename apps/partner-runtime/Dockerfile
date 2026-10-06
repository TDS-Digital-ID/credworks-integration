# syntax=docker/dockerfile:1.12
FROM rust:1.92.0-bookworm AS rust-toolchain
FROM node:22.22.0-bookworm-slim AS build
COPY --from=rust-toolchain /usr/local/cargo /usr/local/cargo
COPY --from=rust-toolchain /usr/local/rustup /usr/local/rustup
ENV PATH="/usr/local/cargo/bin:${PATH}" RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo RUSTUP_TOOLCHAIN=1.92.0 CARGO_BUILD_JOBS=2
RUN apt-get update && apt-get install --yes --no-install-recommends build-essential ca-certificates python3 && rm -rf /var/lib/apt/lists/* && corepack enable && corepack prepare pnpm@10.34.4 --activate
WORKDIR /workspace
COPY . .
RUN --mount=type=cache,id=vc363-cargo-registry,target=/usr/local/cargo/registry --mount=type=cache,id=vc363-cargo-target,target=/workspace/target pnpm install --frozen-lockfile \
    && rm -f packages/identity-core-node/native/*.node \
    && pnpm --filter @unsw-vc/identity-core-node exec napi build --release --features partner-runtime --manifest-path ../../core/bindings-node/Cargo.toml --platform --output-dir native --js index.js --dts index.d.ts --package-json-path package.json --js-package-name @unsw-vc/identity-core-node -- --locked \
    && cp packages/identity-core-node/native/index.js packages/identity-core-node/native/index.cjs \
    && pnpm --filter @unsw-vc/partner-runtime build \
    && pnpm --filter @unsw-vc/partner-runtime deploy --legacy --prod /partner \
    && cd /partner && node tool/check-packaged-addon.mjs \
    && rm -rf /partner/tool

FROM node:22.22.0-bookworm-slim AS runtime
ARG SOURCE_REVISION
LABEL org.opencontainers.image.title="CredWorks Education partner verifier" org.opencontainers.image.revision="${SOURCE_REVISION}"
RUN apt-get update && apt-get install --yes --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
RUN test "${#SOURCE_REVISION}" -eq 40 && test -z "$(printf '%s' "$SOURCE_REVISION" | tr -d '0-9a-f')" && groupadd --gid 10001 credworks && useradd --uid 10001 --gid credworks --no-create-home --shell /usr/sbin/nologin credworks && mkdir /state && chown 10001:10001 /state
ENV NODE_ENV=production SOURCE_REVISION="${SOURCE_REVISION}"
WORKDIR /partner
COPY --from=build --chown=10001:10001 /partner /partner
USER 10001:10001
VOLUME ["/state"]
EXPOSE 3080
ENTRYPOINT ["node","--import","tsx","src/cli.ts"]
CMD ["start"]
