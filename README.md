# Híbrido “mini-QUIC” en C puro (sin dependencias)

Este tercer programa **corre sobre UDP** pero agrega en **user-space**:
- Handshake ligero (`HELLO/HELLO_OK`)
- Confiabilidad: números de secuencia `seq`, **ACK** y **retransmisión** con timeout (stop-and-wait)
- Control de flujo mínimo (ventana efectiva = 1)
- Esquema Pub/Sub por **tópico** con un **broker**

> **No es QUIC real**: no hay TLS 1.3, protección de encabezados ni múltiples streams. Es un esqueleto educativo para el lab.

## Compilar
```bash
make
