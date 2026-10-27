ARG BUILD_FROM
FROM $BUILD_FROM

RUN apk add --no-cache python3 py3-pip \
    && pip3 install --no-cache-dir --break-system-packages "paho-mqtt>=2.1,<3"

# Código da ponte (na raiz do projeto há links para estes arquivos)
COPY elc6012_client.py elc6012_ha_mqtt.py /app/
COPY run.sh /
RUN chmod a+x /run.sh

CMD [ "/run.sh" ]
