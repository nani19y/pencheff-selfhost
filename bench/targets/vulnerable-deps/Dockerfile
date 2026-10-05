FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl
ADD https://example.com/install.sh /tmp/install.sh
RUN curl https://example.com/bootstrap.sh | bash
ENV API_KEY=sk_live_hardcoded_demo_placeholder
CMD ["/bin/bash"]
