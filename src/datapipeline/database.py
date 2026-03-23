"""
SQLAlchemy Database Configuration and Models for SQLite
"""
from sqlalchemy import create_engine, Column, Integer, String, Float, ForeignKey
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
    """Add a new device to the database"""
    db = SessionLocal()
    network_id = network.id if isinstance(network, Network) else db.query(Network).filter_by(network_name=network).first().id
    for i in devices.to_dict(orient="records"):
        try:
            device = Device(
                device_name=i.get('Predicted_Device'),
                device_type=i.get('Predicted_Device'),
                mac_address=i.get('MAC_Address'),
                ip_address=i.get('IP_Address'),
                confidence=i.get('Confidence'),
                Network_id=network_id
            )
            _add_model_instance(db, device)
        except IntegrityError:
            print(f"Device with MAC {i.get('MAC_Address')} already exists. Skipping.")
    db.close()

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

    id = Column(Integer, primary_key=True, index=True)
    device_name = Column(String, index=True, nullable=False)
    device_type = Column(String, nullable=False)
    mac_address = Column(String, unique=True, nullable=False)
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





