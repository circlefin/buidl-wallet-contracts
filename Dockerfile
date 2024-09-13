FROM ghcr.io/foundry-rs/foundry

# Copy our source code into the container
WORKDIR /app
COPY . .

# Remove any local cache to build from a clean base
RUN rm -rf cache_forge
RUN rm -rf out

# Build the source code
EXPOSE 8545
RUN forge build
