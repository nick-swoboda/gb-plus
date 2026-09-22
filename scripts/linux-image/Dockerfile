# Review candidate. Do not build until its complete input admission is recorded.
FROM rust@sha256:3928ba262c79a46d18a4d1c125b24c089963ba1e1d6b203bd3bc169924e71f04
ADD overlay.tar /
COPY bwrap /usr/bin/bwrap
RUN chmod 0755 /usr/bin/bwrap && chmod -R go-w /usr/local/cargo /usr/local/rustup
ENV PATH="/usr/local/rustup/toolchains/1.97.1-aarch64-unknown-linux-gnu/bin:/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ENV RUSTUP_AUTO_INSTALL=0
ENV CARGO_NET_OFFLINE=true
LABEL org.gbplus.role="offline-repository-build-only"
LABEL org.gbplus.base-manifest="3928ba262c79a46d18a4d1c125b24c089963ba1e1d6b203bd3bc169924e71f04"
LABEL org.gbplus.overlay-sha256="b805c63b0ed41d194b531697b1ef969888b76f04837f830e4f7e4c121eef014b"
ADD gui-overlay.tar /
LABEL org.gbplus.gui-overlay-sha256="022d5d2bb002557005a9a98d248dc1dbda9d08569b5567c9a0f110a913d344c6"
