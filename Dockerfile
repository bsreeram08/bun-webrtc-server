FROM oven/bun:1.4.0-alpine
WORKDIR /app
# The signaling service uses Bun and Node built-ins only; legacy dependencies are unnecessary.
COPY --chown=bun:bun packages/signaling ./packages/signaling
COPY --chown=bun:bun packages/stun-server/native ./packages/stun-server/native
COPY --chown=bun:bun scripts/create-room.ts ./scripts/create-room.ts
USER bun
EXPOSE 3000
CMD ["bun", "--no-env-file", "packages/signaling/server.ts"]
