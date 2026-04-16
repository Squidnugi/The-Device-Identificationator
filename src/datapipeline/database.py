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


def drop_all_tables():
    """Drop all tables from the database (WARNING: destructive)"""
    Base.metadata.drop_all(bind=engine)


def reset_database():
    """Reset the database by dropping and recreating all tables (WARNING: destructive)"""
    drop_all_tables()
    create_all_tables()


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
    """Create or retrieve a network record by name.

    Parameters
    ----------
    network_name : str
        Name of the network to create or look up.

    Returns
    -------
    tuple[Network, bool]
        The Network instance and a boolean that is True when newly created.
    """
    db = SessionLocal()
    try:
        network, created = get_or_create(db, Network, network_name=network_name)
        return network, created
    finally:
        db.close()

def add_device(devices, network):
    """Add or update devices for a network and return persistence stats."""
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

        incoming_confidence = i.get('Confidence')
        try:
            incoming_confidence = float(incoming_confidence) if incoming_confidence is not None else None
            if incoming_confidence != incoming_confidence:  # NaN check
                incoming_confidence = None
        except (TypeError, ValueError):
            incoming_confidence = None

        try:
            existing = db.query(Device).filter_by(mac_address=mac, Network_id=network_id).first()
            if existing:
                should_replace = (
                    incoming_confidence is not None
                    and (existing.confidence is None or incoming_confidence > existing.confidence)
                )

                if should_replace:
                    existing.device_name = i.get('Predicted_Device') or existing.device_name
                    existing.device_type = i.get('Predicted_Device') or existing.device_type
                    existing.ip_address = i.get('IP_Address') or existing.ip_address
                    existing.confidence = incoming_confidence
                    db.commit()
                    stats["updated"] += 1
                else:
                    stats["skipped"] += 1
            else:
                device = Device(
                    device_name=i.get('Predicted_Device') or 'Unknown',
                    device_type=i.get('Predicted_Device') or 'Unknown',
                    mac_address=mac,
                    ip_address=i.get('IP_Address'),
                    confidence=incoming_confidence,
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
    """Device model"""
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
    Network_id = Column(Integer, ForeignKey("networks.id"), nullable=False)

    # Relationship
    network = relationship("Network", back_populates="devices")


class Network(Base):
    """Network model"""
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





