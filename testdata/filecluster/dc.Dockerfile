FROM sambaadm-member-dc:local
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 && rm -rf /var/lib/apt/lists/*
COPY samba/entrypoint.sh /usr/local/sbin/sambaadm-lab
ENTRYPOINT ["sh","-c","ip address add 10.0.2.2/32 dev lo; exec /usr/local/sbin/sambaadm-lab"]
