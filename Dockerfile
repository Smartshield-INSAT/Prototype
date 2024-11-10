# Stage 1: Build Stage
FROM debian:bookworm-slim AS build



# Set environment variables for non-interactive installation and versions
ENV DEBIAN_FRONTEND=noninteractive \
    ARGUS_VERSION=5.0.0 \
    CLIENTS_VERSION=5.0.0


# Install build dependencies


RUN apt-get update && \
    apt-get install  -y \
    gcc \
    make \
    flex \
    bison \
    zlib1g-dev \
    libpcap-dev \
    curl \
    gpg \
    wget \
    libpcap-dev \
    libtirpc-dev \
    build-essential \
    python3-pip \
    python3-dev \
    liblzma-dev \
    libssl-dev \
    libxml2-dev \
    libxslt-dev \
    cmake \
    g++ \
    clang \
    libmagic-dev \
    libreadline-dev \
    git \
    swig \
    nodejs \
    npm && \
    rm -rf /var/lib/apt/lists/*

# Install Argus
WORKDIR /argus
RUN wget https://github.com/openargus/clients/archive/refs/tags/v${CLIENTS_VERSION}.tar.gz -O clients-${CLIENTS_VERSION}.tar.gz && \
    tar -xvf clients-${CLIENTS_VERSION}.tar.gz && \
    wget https://github.com/openargus/argus/archive/refs/tags/v${ARGUS_VERSION}.tar.gz -O argus-${ARGUS_VERSION}.tar.gz && \
    tar -xvf argus-${ARGUS_VERSION}.tar.gz

RUN cd clients-${CLIENTS_VERSION} && \
    LIBS="-lz" ./configure && \
    make && \
    make install && \
    cd ../argus-${ARGUS_VERSION} && \
    LIBS="-lz" ./configure && \
    make && \
    make install

# Stage 2: Runtime Stage
FROM debian:bookworm-slim

# Install runtime dependencies (excluding build tools and development dependencies)
RUN apt-get update && \
    apt-get install -y \
    zlib1g \
    libpcap0.8 \
    libtirpc3 \
    python3 \
    python3-pip \
    python3-venv \
    libssl-dev \
    curl \
    gpg \
    libxml2-dev \
    libxslt-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy the requirements.txt file into the container
COPY requirements.txt /tmp/

# Create a virtual environment and install the Python dependencies inside it
RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt

# Set up working directory
WORKDIR /app

COPY . .
# Copy Argus and Zeek files from the build stage


RUN echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' |  tee /etc/apt/sources.list.d/security:zeek.list
RUN curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | gpg --dearmor |  tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
RUN apt-get update && \
    apt-get install -y \
    zeek

# Install Zeek
RUN apt-get install zeek

RUN chmod +x ./process_pcap.sh

COPY --from=build /usr/local /usr/local
ENV PATH="/opt/venv/bin:/usr/local/bin:/opt/zeek/bin:$PATH"


# Set environment variable for the virtual environment
ENV PATH="/opt/venv/bin:$PATH"

# # Set a default command (optional)
# CMD ["bash"]