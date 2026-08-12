ARG NODE_RUNTIME_IMAGE
FROM ${NODE_RUNTIME_IMAGE}

RUN useradd --uid 10002 --create-home --shell /usr/sbin/nologin broker
COPY --chown=10002:10002 src /opt/lazurio/github-app/src

USER 10002:10002
WORKDIR /home/broker
ENV NODE_ENV=production PORT=8787
EXPOSE 8787
CMD ["node", "/opt/lazurio/github-app/src/broker.mjs"]
