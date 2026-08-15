FROM node:22-slim

WORKDIR /app

# Installed from the lockfile in its own layer, same reasoning as the
# Python image: source edits shouldn't force a full npm reinstall.
COPY package.json package-lock.json ./
RUN npm ci

COPY . .

# This is the same `npm run build` verified locally — running it inside
# the container from a clean install is the actual test of "a stranger's
# clone works," since it can't see the host's node_modules (excluded via
# .dockerignore, and it contains Windows-only native binaries anyway).
RUN npm run build

EXPOSE 5173

# `vite preview` serves the production dist/ build, not the dev server —
# it isn't a hardened production web server, but it's the right amount of
# infrastructure for a portable demo. Swap for nginx if this ever needs to
# hold up outside a demo context.
CMD ["npx", "vite", "preview", "--host", "0.0.0.0", "--port", "5173"]
