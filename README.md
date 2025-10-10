# Bono Lab 3 – Infracom (QUIC)
Pub/Sub en C usando QUIC (MsQuic). QUIC corre sobre UDP pero da fiabilidad/orden (por stream) y TLS 1.3.

## Requisitos
brew install libmsquic openssl@3

## Compilar
make quic

## Ejecutar
./build/broker_quic 5003 quic/certs/server.crt quic/certs/server.key
./build/subscriber_quic 127.0.0.1 5003 AvsB
./build/publisher_quic 127.0.0.1 5003 AvsB 10

## Certificado (self-signed)
mkdir -p quic/certs
openssl req -nodes -new -x509 -keyout quic/certs/server.key -out quic/certs/server.crt -subj "/CN=localhost"
