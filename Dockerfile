# SPDX-License-Identifier: Apache-2.0
ARG NODE_RUNTIME_IMAGE
FROM ${NODE_RUNTIME_IMAGE}

LABEL org.opencontainers.image.licenses="Apache-2.0"

RUN useradd --uid 10002 --create-home --shell /usr/sbin/nologin broker \
    && install -d --owner=0 --group=0 --mode=0555 \
      /usr/share/licenses/lazurio-github-app/third-party/github-cli
COPY --chown=0:0 --chmod=0555 src /opt/lazurio/github-app/src
COPY --chown=0:0 --chmod=0555 adapter /opt/lazurio/github-app/adapter
COPY --chown=0:0 --chmod=0444 LICENSE THIRD_PARTY_NOTICES.md /usr/share/licenses/lazurio-github-app/
COPY --chown=0:0 --chmod=0444 third_party/github-cli/LICENSE /usr/share/licenses/lazurio-github-app/third-party/github-cli/LICENSE

USER 10002:10002
WORKDIR /home/broker
ENV NODE_ENV=production PORT=8787
EXPOSE 8787
CMD ["node", "/opt/lazurio/github-app/src/broker.mjs"]
