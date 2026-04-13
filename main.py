import asyncio
import json
import logging
import os
import ssl
from datetime import date, datetime, time, timedelta, timezone
from typing import Optional, Set

import paho.mqtt.client as mqtt
from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import OAuth2PasswordBearer
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import Column, DateTime, Float, Integer, String, Text, create_engine, desc
from sqlalchemy.orm import declarative_base, sessionmaker

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("gps-tracker")

SECRET_KEY = os.getenv("SECRET_KEY", "change-me-now")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7

ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./gps.db")

MQTT_HOST = os.getenv("MQTT_HOST", "")
MQTT_PORT = int(os.getenv("MQTT_PORT", "8883"))
MQTT_USER = os.getenv("MQTT_USER", "")
MQTT_PASSWORD = os.getenv("MQTT_PASSWORD", "")
MQTT_TOPIC = os.getenv("MQTT_TOPIC", "vehicles/+/gps")
MQTT_TLS = os.getenv("MQTT_TLS", "true").lower() in {"1", "true", "yes"}
MQTT_TLS_INSECURE = os.getenv("MQTT_TLS_INSECURE", "false").lower() in {"1", "true", "yes"}

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(120), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)


class VehiclePosition(Base):
    __tablename__ = "vehicle_positions"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String(120), index=True, nullable=False)
    lat = Column(Float, nullable=False)
    lng = Column(Float, nullable=False)
    speed = Column(Float, nullable=True)
    heading = Column(Float, nullable=True)
    altitude = Column(Float, nullable=True)
    accuracy = Column(Float, nullable=True)
    raw = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


Base.metadata.create_all(bind=engine)

app = FastAPI(title="GPS Tracker MQTT", version="2.0.0")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


def verify_password(plain_password: str, password_hash: str) -> bool:
    return pwd_context.verify(plain_password, password_hash)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def ensure_admin_user():
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == ADMIN_USER).first()
        if not user:
            user = User(username=ADMIN_USER, password_hash=get_password_hash(ADMIN_PASSWORD))
            db.add(user)
            db.commit()
            logger.info("Admin user created: %s", ADMIN_USER)
    finally:
        db.close()


def authenticate_user(username: str, password: str):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user or not verify_password(password, user.password_hash):
            return None
        return user
    finally:
        db.close()


def get_current_user(token: str = Depends(oauth2_scheme)):
    unauthorized = HTTPException(status_code=401, detail="No autorizado", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise unauthorized
    except JWTError as exc:
        raise unauthorized from exc

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise unauthorized
        return user
    finally:
        db.close()


class ConnectionManager:
    def __init__(self):
        self.active: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active.add(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active.discard(websocket)

    async def broadcast(self, message: dict):
        dead = []
        payload = json.dumps(message, default=str)
        for ws in list(self.active):
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()


def parse_vehicle_payload(topic: str, payload: bytes) -> dict:
    raw = payload.decode("utf-8", errors="ignore")
    data = json.loads(raw)

    parts = topic.split("/")
    device_id = data.get("device_id") or (parts[1] if len(parts) >= 3 else "unknown")

    lat = float(data["lat"])
    lng = float(data["lng"])
    speed = float(data.get("speed")) if data.get("speed") not in (None, "") else None
    heading = float(data.get("heading")) if data.get("heading") not in (None, "") else None
    altitude = float(data.get("altitude")) if data.get("altitude") not in (None, "") else None
    accuracy = float(data.get("accuracy")) if data.get("accuracy") not in (None, "") else None

    return {
        "device_id": str(device_id),
        "lat": lat,
        "lng": lng,
        "speed": speed,
        "heading": heading,
        "altitude": altitude,
        "accuracy": accuracy,
        "raw": raw,
        "ts": datetime.now(timezone.utc).isoformat(),
    }


def save_position(data: dict):
    db = SessionLocal()
    try:
        db.add(
            VehiclePosition(
                device_id=data["device_id"],
                lat=data["lat"],
                lng=data["lng"],
                speed=data.get("speed"),
                heading=data.get("heading"),
                altitude=data.get("altitude"),
                accuracy=data.get("accuracy"),
                raw=data.get("raw"),
            )
        )
        db.commit()
    finally:
        db.close()


def on_mqtt_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        logger.info("MQTT conectado")
        client.subscribe(MQTT_TOPIC, qos=1)
        logger.info("Suscrito a %s", MQTT_TOPIC)
    else:
        logger.error("MQTT conexión fallida rc=%s", rc)


def on_mqtt_message(client, userdata, msg):
    try:
        data = parse_vehicle_payload(msg.topic, msg.payload)
        save_position(data)
        asyncio.run_coroutine_threadsafe(manager.broadcast({"type": "gps", **data}), userdata["loop"])
    except Exception as e:
        logger.exception("Error procesando MQTT: %s", e)


def start_mqtt(loop: asyncio.AbstractEventLoop):
    if not MQTT_HOST:
        logger.warning("MQTT_HOST no configurado, el servicio iniciará sin escuchar MQTT")
        return

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.user_data_set({"loop": loop})
    client.on_connect = on_mqtt_connect
    client.on_message = on_mqtt_message

    if MQTT_USER:
        client.username_pw_set(MQTT_USER, MQTT_PASSWORD)

    if MQTT_TLS:
        context = ssl.create_default_context()
        client.tls_set_context(context)
        if MQTT_TLS_INSECURE:
            client.tls_insecure_set(True)

    logger.info("Conectando MQTT a %s:%s", MQTT_HOST, MQTT_PORT)
    client.connect(MQTT_HOST, MQTT_PORT, keepalive=60)
    client.loop_start()


@app.on_event("startup")
async def startup_event():
    ensure_admin_user()
    start_mqtt(asyncio.get_running_loop())


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/app", response_class=HTMLResponse)
def app_page(request: Request):
    return templates.TemplateResponse("app.html", {"request": request})


@app.post("/api/login")
def login(username: str = Form(...), password: str = Form(...)):
    user = authenticate_user(username, password)
    if not user:
        raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos")

    token = create_access_token({"sub": user.username})
    return JSONResponse({"access_token": token, "token_type": "bearer"})


@app.get("/api/latest")
def latest(current_user=Depends(get_current_user)):
    del current_user
    db = SessionLocal()
    try:
        row = db.query(VehiclePosition).order_by(desc(VehiclePosition.created_at)).first()
        if not row:
            return {"ok": True, "data": None}
        return {
            "ok": True,
            "data": {
                "device_id": row.device_id,
                "lat": row.lat,
                "lng": row.lng,
                "speed": row.speed,
                "heading": row.heading,
                "altitude": row.altitude,
                "accuracy": row.accuracy,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            },
        }
    finally:
        db.close()


@app.get("/api/devices")
def devices(current_user=Depends(get_current_user)):
    del current_user
    db = SessionLocal()
    try:
        rows = db.query(VehiclePosition.device_id).distinct().all()
        return {"devices": sorted([r[0] for r in rows])}
    finally:
        db.close()


@app.get("/api/history/{device_id}")
def history(device_id: str, limit: int = 500, current_user=Depends(get_current_user)):
    del current_user
    db = SessionLocal()
    try:
        rows = (
            db.query(VehiclePosition)
            .filter(VehiclePosition.device_id == device_id)
            .order_by(desc(VehiclePosition.created_at))
            .limit(min(limit, 3000))
            .all()
        )
        rows.reverse()
        return {"device_id": device_id, "points": [_row_to_point(r) for r in rows]}
    finally:
        db.close()


@app.get("/api/history/{device_id}/day")
def history_by_day(
    device_id: str,
    day: date = Query(..., description="Formato YYYY-MM-DD en UTC"),
    current_user=Depends(get_current_user),
):
    del current_user
    start = datetime.combine(day, time.min, tzinfo=timezone.utc)
    end = start + timedelta(days=1)

    db = SessionLocal()
    try:
        rows = (
            db.query(VehiclePosition)
            .filter(VehiclePosition.device_id == device_id)
            .filter(VehiclePosition.created_at >= start)
            .filter(VehiclePosition.created_at < end)
            .order_by(VehiclePosition.created_at.asc())
            .all()
        )
        return {"device_id": device_id, "day": day.isoformat(), "points": [_row_to_point(r) for r in rows]}
    finally:
        db.close()


def _row_to_point(row: VehiclePosition) -> dict:
    return {
        "lat": row.lat,
        "lng": row.lng,
        "speed": row.speed,
        "heading": row.heading,
        "altitude": row.altitude,
        "accuracy": row.accuracy,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=1008)
        return

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if not payload.get("sub"):
            await websocket.close(code=1008)
            return
    except JWTError:
        await websocket.close(code=1008)
        return

    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.get("/health")
def health():
    return {"status": "ok"}
