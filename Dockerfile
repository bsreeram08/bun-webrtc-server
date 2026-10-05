FROM oven/bun:1.4.0-alpine
WORKDIR /app
# Signaling needs Bun built-ins plus one passkey verifier, installed exactly as pinned in packages/signaling/bun.lock.
COPY --chown=bun:bun packages/signaling ./packages/signaling
COPY --chown=bun:bun packages/stun-server/native ./packages/stun-server/native
COPY --chown=bun:bun scripts/create-room.ts scripts/create-invite.ts ./scripts/
RUN cd packages/signaling && bun install --production --frozen-lockfile && mkdir -p /data && chown bun:bun /data
USER bun
ENV DATA_DIR=/data
EXPOSE 3000
CMD ["bun", "--no-env-file", "packages/signaling/server.ts"]
