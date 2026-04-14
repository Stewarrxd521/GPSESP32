# GPS Tracker profesional (ESP32 + MQTT + Render)

Servicio web con login para monitoreo en tiempo real de vehículos, mapa, movimiento y ruta por día.

## Arquitectura

- **ESP32** publica telemetría GPS en HiveMQ Cloud vía MQTT TLS.
- **FastAPI** recibe mensajes MQTT, guarda puntos en PostgreSQL y los difunde por WebSocket.
- **Frontend** (Leaflet) muestra posición en vivo + histórico diario por vehículo.
- **Render** hospeda app + base de datos.

## Payload MQTT recomendado

Topic recomendado:

```txt
vehicles/<device_id>/gps
```

Payload JSON:

```json
{
  "lat": 4.7110,
  "lng": -74.0721,
  "speed": 34.2,
  "heading": 185,
  "altitude": 2550,
  "accuracy": 4.8
}
```

## Variables de entorno clave

- `SECRET_KEY`: JWT secreto (Render ya lo genera).
- `ADMIN_USER`, `ADMIN_PASSWORD`: acceso web.
- `DATABASE_URL`: conexión a PostgreSQL (recomendado para producción).
- Alternativa sin URL completa: `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_SSLMODE=require` (ideal para Supabase).
- `MQTT_HOST=5022a5cb4cc744049a477ca9676481fd.s1.eu.hivemq.cloud`
- `MQTT_PORT=8883`
- `MQTT_USER`, `MQTT_PASSWORD`: credenciales HiveMQ Cloud.
- `MQTT_TOPIC=vehicles/+/gps`
- `MQTT_TLS=true`

## Endpoints principales

- `POST /api/login`
- `GET /api/devices`
- `GET /api/latest`
- `GET /api/history/{device_id}/day?day=YYYY-MM-DD`
- `GET /health`

## Deploy

1. Subir repo a GitHub.
2. En Render, crear servicio web desde repo (Render detecta `render.yaml`).
3. Configurar secretos (`ADMIN_PASSWORD`, `MQTT_USER`, `MQTT_PASSWORD`).
4. Abrir URL del servicio y autenticar.

### Ejemplo Supabase

Si vas a usar Supabase Postgres, puedes configurar:

```txt
DB_HOST=db.whpkoqubhccfezrwwpvl.supabase.co
DB_PORT=5432
DB_NAME=postgres
DB_USER=postgres
DB_PASSWORD=<tu-password>
DB_SSLMODE=require
```

O la URL completa:

```txt
DATABASE_URL=postgresql+psycopg://postgres:<tu-password>@db.whpkoqubhccfezrwwpvl.supabase.co:5432/postgres?sslmode=require
```

## Seguridad recomendada

- Cambia credenciales por defecto.
- Usa usuario MQTT con permisos mínimos en topic.
- Activa rotación periódica de credenciales.
- No publiques valores secretos en el repositorio.
