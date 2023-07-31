FROM quay.io/vexxhost/keystone:zed
COPY . /src
RUN --mount=type=cache,target=/root/.cache/pip \
  pip install /src

COPY hack/keystone.sh /keystone.sh
CMD ["/keystone.sh"]
