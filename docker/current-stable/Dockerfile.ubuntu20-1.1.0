FROM ubuntu:20.04

RUN groupadd -r nexa && useradd -r -m -g nexa nexa

RUN set -ex \
	&& apt-get update \
	&& apt-get install -qq --no-install-recommends ca-certificates dirmngr gosu wget \
	&& rm -rf /var/lib/apt/lists/*

ENV NEXA_VERSION 1.1.0.0
ENV NEXA_URL https://bitcoinunlimited.info/nexa/1.1.0/nexa-1.1.0.0-linux64.tar.gz
ENV NEXA_SHA256 c6821e0e6be4c4519c92ef1e91ae8dea6a493e0d9f960b274a7fd0df75bc0332

# install nexa binaries
RUN set -ex \
	&& cd /tmp \
	&& wget -qO nexa.tar.gz "$NEXA_URL" \
	&& echo "$NEXA_SHA256 nexa.tar.gz" | sha256sum -c - \
	&& tar -xzvf nexa.tar.gz -C /usr/local --strip-components=1 --exclude=*-qt \
	&& rm -rf /tmp/*

# create data directory
ENV NEXA_DATA /data
RUN mkdir "$NEXA_DATA" \
	&& chown -R nexa:nexa "$NEXA_DATA" \
	&& ln -sfn "$NEXA_DATA" /home/nexa/.nexa \
	&& chown -h nexa:nexa /home/nexa/.nexa
VOLUME /data

COPY docker-entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

EXPOSE 7228 7227 7230 7229

CMD ["nexad"]
