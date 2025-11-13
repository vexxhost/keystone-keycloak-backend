FROM registry.atmosphere.dev/library/keystone:2025.2

COPY . /src

RUN apt update && apt install curl -y
RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
RUN /var/lib/openstack/bin/python3 get-pip.py

RUN --mount=type=cache,target=/root/.cache/pip \
  /var/lib/openstack/bin/pip3 install /src

COPY hack/keystone.sh /keystone.sh
CMD ["/keystone.sh"]
