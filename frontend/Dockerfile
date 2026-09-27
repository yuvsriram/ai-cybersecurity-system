# syntax=docker/dockerfile:1

FROM node:24-alpine AS builder

WORKDIR /build

COPY package.json package-lock.json ./

RUN npm ci

COPY . .

RUN VITE_AUTH_MODE=demo npm run build


FROM nginxinc/nginx-unprivileged:stable-alpine AS runtime

ENV NGINX_ENVSUBST_FILTER=DEMO_API_KEY

COPY \
    nginx/default.conf.template \
    /etc/nginx/templates/default.conf.template

COPY \
    --chmod=755 \
    docker-entrypoint.d/10-require-demo-key.sh \
    /docker-entrypoint.d/10-require-demo-key.sh

COPY \
    --from=builder \
    /build/dist \
    /usr/share/nginx/html

EXPOSE 8080