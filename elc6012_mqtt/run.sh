#!/usr/bin/with-contenv bashio
# shellcheck shell=bash

if ! bashio::services.available "mqtt"; then
    bashio::exit.nok "Broker MQTT não encontrado — instale/inicie o add-on Mosquitto."
fi

# Senhas por variável de ambiente, como na ponte standalone (não aparecem no ps).
export ELC_PASSWORD
ELC_PASSWORD="$(bashio::config 'password')"
export MQTT_PASSWORD
MQTT_PASSWORD="$(bashio::services mqtt 'password')"

bashio::log.info "Iniciando ponte ELC 6012 NET (MAC $(bashio::config 'mac'))"
exec python3 -u /app/elc6012_ha_mqtt.py \
    --mac "$(bashio::config 'mac')" \
    --poll "$(bashio::config 'poll')" \
    --prefix "$(bashio::config 'prefix')" \
    --mqtt "$(bashio::services mqtt 'host')" \
    --mqtt-port "$(bashio::services mqtt 'port')" \
    --mqtt-user "$(bashio::services mqtt 'username')"
