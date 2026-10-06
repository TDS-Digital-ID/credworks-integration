# syntax=docker/dockerfile:1.12
FROM node:22.22.0-bookworm-slim AS build
RUN corepack enable && corepack prepare pnpm@10.34.4 --activate
WORKDIR /workspace
COPY . .
RUN pnpm install --frozen-lockfile && pnpm --filter @unsw-vc/education-sign-in build && pnpm --filter @unsw-vc/education-sign-in deploy --legacy --prod /application
FROM node:22.22.0-bookworm-slim AS runtime
ARG SOURCE_REVISION
LABEL org.opencontainers.image.title="CredWorks Education sign-in example" org.opencontainers.image.revision="${SOURCE_REVISION}"
RUN test "${#SOURCE_REVISION}" -eq 40 && test -z "$(printf '%s' "$SOURCE_REVISION" | tr -d '0-9a-f')" && groupadd --gid 10001 credworks && useradd --uid 10001 --gid credworks --no-create-home --shell /usr/sbin/nologin credworks
WORKDIR /application
COPY --from=build --chown=10001:10001 /application /application
USER 10001:10001
ENV NODE_ENV=production SOURCE_REVISION="${SOURCE_REVISION}"
EXPOSE 3082
ENTRYPOINT ["node","--import","tsx","src/cli.ts"]
