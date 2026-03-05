FROM registry.atmosphere.dev/library/keystone:2025.2@sha256:5170d0d954c267c56890279b38bebe94f1c8c3eb88d5ff24cc289c1740a7c72e

COPY . /src

RUN apt update && apt install curl -y
RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
RUN /var/lib/openstack/bin/python3 get-pip.py

RUN --mount=type=cache,target=/root/.cache/pip \
  /var/lib/openstack/bin/pip3 install /src

COPY hack/keystone.sh /keystone.sh
CMD ["/keystone.sh"]
