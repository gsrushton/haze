#-------------------------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See https://go.microsoft.com/fwlink/?linkid=2090316 for license information.
#-------------------------------------------------------------------------------------------------------------

FROM ubuntu:19.10

ARG USER=user
ARG UID=1000
ARG GID=$UID
ARG SHELL=zsh

# Avoid warnings by switching to noninteractive
ENV DEBIAN_FRONTEND=noninteractive

# Configure apt and install packages
RUN    apt-get update \
    && apt-get -y install apt-utils \
                          build-essential \
                          curl \
                          dialog \
                          git \
                          iproute2 \
                          libssl-dev \
                          lldb \
                          lsb-release \
                          pkg-config \
                          procps \
                          sudo \
                          $SHELL 2>&1 \
    && apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*


# Create a non-root user to use if preferred - see https://aka.ms/vscode-remote/containers/non-root-user.
RUN    groupadd --gid $GID $USER \
    && useradd -m -s /bin/$SHELL --uid $UID --gid $GID $USER \
    # Add sudo support for the non-root user
    && echo $USER ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USER\
    && chmod 0440 /etc/sudoers.d/$USER

# Switch back to dialog for any ad-hoc use of apt-get
ENV DEBIAN_FRONTEND=

# Install Rust
ARG RUST_VERSION=1.42.0
ENV RUSTUP_HOME=/opt/rust
ENV CARGO_HOME=/opt/rust
RUN    mkdir ${RUSTUP_HOME} \
    && curl https://sh.rustup.rs -sSf | bash -s -- \
      -y \
      --no-modify-path \
      --default-toolchain ${RUST_VERSION} \
      --component rls \
      --component rust-analysis \
      --component rust-src

ENV PATH="${PATH}:${RUSTUP_HOME}/bin"

USER $USER

WORKDIR /home/$USER

CMD ["tail", "-f", "/dev/null"]
