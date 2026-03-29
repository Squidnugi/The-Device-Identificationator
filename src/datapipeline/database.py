"""
SQLAlchemy Database Configuration and Models for SQLite
"""
from sqlalchemy import create_engine, Column, Integer, String, Float, ForeignKey, UniqueConstraint
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from sqlalchemy.exc import IntegrityError

# Database configuration
DATABASE_URL = "sqlite:///./database.db"  # SQLite database file
# For different location: DATABASE_URL = "sqlite:////absolute/path/to/database.db"

# Create engine
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},  # Required for SQLite
    echo=False  # Set to True to see SQL queries
)

# Create base class for models
Base = declarative_base()

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    """Get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_all_tables():
    """Create all tables in the database"""
    Base.metadata.create_all(bind=engine)
    _migrate_devices_to_network_scoped_mac_uniqueness()


def drop_all_tables():
    """Drop all tables from the database (WARNING: destructive)"""
    Base.metadata.drop_all(bind=engine)


def reset_database():
    """Reset the database by dropping and recreating all tables (WARNING: destructive)"""
    drop_all_tables()
    create_all_tables()


def _migrate_devices_to_network_scoped_mac_uniqueness():
    """Migrate legacy devices uniqueness from mac_address -> (mac_address, Network_id)."""
    try:
        with engine.connect() as conn:
            table_info = conn.exec_driver_sql(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='devices'"
            ).fetchone()
            if not table_info or not table_info[0]:
                return

            create_sql = table_info[0]
            has_legacy_unique = "UNIQUE (mac_address)" in create_sql
            already_network_scoped = "UNIQUE (mac_address, Network_id)" in create_sql

            if not has_legacy_unique or already_network_scoped:
                return

        with engine.begin() as conn:
            conn.exec_driver_sql("PRAGMA foreign_keys=OFF")
            conn.exec_driver_sql(
                """
                CREATE TABLE devices_new (
                    id INTEGER NOT NULL,
                    device_name VARCHAR NOT NULL,
                    device_type VARCHAR NOT NULL,
                    mac_address VARCHAR NOT NULL,
                    ip_address VARCHAR,
                    confidence FLOAT,
                    Network_id INTEGER NOT NULL,
                    PRIMARY KEY (id),
                    UNIQUE (mac_address, Network_id),
                    FOREIGN KEY(Network_id) REFERENCES networks (id)
                )
                """
            )
            conn.exec_driver_sql(
                """
                INSERT INTO devices_new (id, device_name, device_type, mac_address, ip_address, confidence, Network_id)
                SELECT id, device_name, device_type, mac_address, ip_address, confidence, Network_id FROM devices
                """
            )
            conn.exec_driver_sql("DROP TABLE devices")
            conn.exec_driver_sql("ALTER TABLE devices_new RENAME TO devices")
            conn.exec_driver_sql("CREATE INDEX IF NOT EXISTS ix_devices_id ON devices (id)")
            conn.exec_driver_sql("CREATE INDEX IF NOT EXISTS ix_devices_device_name ON devices (device_name)")
            conn.exec_driver_sql("PRAGMA foreign_keys=ON")
    except Exception as e:
        print(f"Warning: devices table uniqueness migration skipped: {e}")

def _add_model_instance(db, model_instance):
    """Add a SQLAlchemy model instance to the database."""
    try:
        db.add(model_instance)
        db.commit()
        db.refresh(model_instance)
        return model_instance
    except IntegrityError:
        db.rollback()
        raise


def get_or_create(db, model, defaults=None, **lookup):
    """Get an existing row by lookup fields, or create it if missing."""
    instance = db.query(model).filter_by(**lookup).first()
    if instance:
        return instance, False

    params = {**lookup, **(defaults or {})}
    instance = model(**params)
    db.add(instance)
    try:
        db.commit()
        db.refresh(instance)
        return instance, True
    except IntegrityError:
        # Handle races/duplicates and return canonical existing row.
        db.rollback()
        instance = db.query(model).filter_by(**lookup).first()
        if instance is None:
            raise
        return instance, False

def get_data(db, model, filters=None):
    """Query data from the database with optional filters"""
    query = db.query(model)
    if filters:
        query = query.filter_by(**filters)
    return query.all()

def update_data(db, model, filters, updates):
    """Update records in the database based on filters"""
    query = db.query(model).filter_by(**filters)
    query.update(updates)
    db.commit()
    
def delete_data(db, model, filters):
    """Delete records from the database based on filters"""
    query = db.query(model).filter_by(**filters)
    query.delete()
    db.commit()
    

def add_to_network(network_name):
    """Add a new network to the database"""
    try:
        db = SessionLocal()
        network, created = get_or_create(db, Network, network_name=network_name)
        db.close()
        return network, created
    except Exception as e:
        print(f"Error adding network: {e}")
        return None, False

def add_device(devices, network):
    """Add or update devices for a network and return persistence stats."""
    _migrate_devices_to_network_scoped_mac_uniqueness()
    db = SessionLocal()
    stats = {"inserted": 0, "updated": 0, "skipped": 0}

    network_row = network if isinstance(network, Network) else db.query(Network).filter_by(network_name=network).first()
    if network_row is None and isinstance(network, str):
        network_row, _ = get_or_create(db, Network, network_name=network)
    if network_row is None:
        db.close()
        raise ValueError("Network must exist before adding devices")

    network_id = network_row.id

    for i in devices.to_dict(orient="records"):
        mac = i.get('MAC_Address')
        if not mac:
            stats["skipped"] += 1
            continue

        try:
            existing = db.query(Device).filter_by(mac_address=mac, Network_id=network_id).first()
            if existing:
                existing.device_name = i.get('Predicted_Device') or existing.device_name
                existing.device_type = i.get('Predicted_Device') or existing.device_type
                existing.ip_address = i.get('IP_Address') or existing.ip_address
                existing.confidence = i.get('Confidence')
                db.commit()
                stats["updated"] += 1
            else:
                device = Device(
                    device_name=i.get('Predicted_Device') or 'Unknown',
                    device_type=i.get('Predicted_Device') or 'Unknown',
                    mac_address=mac,
                    ip_address=i.get('IP_Address'),
                    confidence=i.get('Confidence'),
                    Network_id=network_id
                )
                _add_model_instance(db, device)
                stats["inserted"] += 1
        except IntegrityError:
            db.rollback()
            stats["skipped"] += 1
            print(f"Device with MAC {mac} could not be persisted. Skipping.")
    db.close()
    return stats

def get_devices_by_network(network_name):
    """Get all devices associated with a specific network"""
    db = SessionLocal()
    network = db.query(Network).filter_by(network_name=network_name).first()
    if not network:
        db.close()
        raise ValueError(f"Network '{network_name}' not found.")
    devices = network.devices
    db.close()
    return devices


def all_networks():
    """Get a list of all networks in the database"""
    db = SessionLocal()
    networks = db.query(Network).all()
    db.close()
    return networks

# ============================================================================
# Models
# ============================================================================

class Device(Base):
    """Example Device model"""
    __tablename__ = "devices"
    __table_args__ = (
        UniqueConstraint("mac_address", "Network_id", name="uq_devices_mac_network"),
    )

    id = Column(Integer, primary_key=True, index=True)
    device_name = Column(String, index=True, nullable=False)
    device_type = Column(String, nullable=False)
    mac_address = Column(String, nullable=False)
    ip_address = Column(String)
    confidence = Column(Float)
    #packet_count = Column(Integer)
    #vote_count = Column(Integer)
    Network_id = Column(Integer, ForeignKey("networks.id"), nullable=False)

    # Relationship
    network = relationship("Network", back_populates="devices")


class Network(Base):
    """Example Network model"""
    __tablename__ = "networks"

    id = Column(Integer, primary_key=True, index=True)
    network_name = Column(String, unique=True, index=True, nullable=False)

    # Relationship
    devices = relationship("Device", back_populates="network")

# ============================================================================
# Usage Examples
# ============================================================================

if __name__ == "__main__":
    # Create all tables
    create_all_tables()
    
    # Get a session
    db = SessionLocal()
    
    devices = get_devices_by_network("Default_Network")
    for device in devices:
        print(f"Device: {device.device_name}, MAC: {device.mac_address}, Confidence: {device.confidence}")
    
    db.close()





