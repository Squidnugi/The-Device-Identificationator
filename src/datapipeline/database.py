"""SQLAlchemy database configuration, ORM models, and CRUD helpers for SQLite."""
import pandas as pd
from sqlalchemy import create_engine, Column, Integer, String, Float, ForeignKey, UniqueConstraint
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from sqlalchemy.exc import IntegrityError

DATABASE_URL = "sqlite:///./database.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False,
)

Base = declarative_base()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# ============================================================================
# Models
# ============================================================================

class Device(Base):
    """ORM model representing a network device stored in the database."""

    __tablename__ = "devices"
    __table_args__ = (
        UniqueConstraint("mac_address", "network_id", name="uq_devices_mac_network"),
    )

    id = Column(Integer, primary_key=True, index=True)
    device_name = Column(String, index=True, nullable=False)
    device_type = Column(String, nullable=False)
    mac_address = Column(String, nullable=False)
    ip_address = Column(String)
    confidence = Column(Float)
    network_id = Column(Integer, ForeignKey("networks.id"), nullable=False)

    network = relationship("Network", back_populates="devices")


class Network(Base):
    """ORM model representing a named network that groups devices."""

    __tablename__ = "networks"

    id = Column(Integer, primary_key=True, index=True)
    network_name = Column(String, unique=True, index=True, nullable=False)

    devices = relationship("Device", back_populates="network")


# ============================================================================
# Session helpers
# ============================================================================

def create_all_tables():
    """Create all ORM-mapped tables in the database if they do not already exist."""
    Base.metadata.create_all(bind=engine)


def drop_all_tables():
    """Drop all ORM-mapped tables from the database.

    Warning
    -------
    This is a destructive operation — all data will be permanently deleted.
    """
    Base.metadata.drop_all(bind=engine)


def reset_database():
    """Drop and recreate all tables, wiping all stored data.

    Warning
    -------
    This is a destructive operation — all data will be permanently deleted.
    """
    drop_all_tables()
    create_all_tables()


# ============================================================================
# Low-level CRUD utilities
# ============================================================================

def _add_model_instance(db, model_instance):
    """Persist a new SQLAlchemy model instance and refresh it from the database.

    Parameters
    ----------
    db : Session
        Active SQLAlchemy session.
    model_instance : Base
        Unsaved ORM instance to add.

    Returns
    -------
    Base
        The same instance after commit and refresh (primary key populated).

    Raises
    ------
    IntegrityError
        If a unique constraint is violated.
    """
    try:
        db.add(model_instance)
        db.commit()
        db.refresh(model_instance)
        return model_instance
    except IntegrityError:
        db.rollback()
        raise


def get_or_create(db, model, defaults=None, **lookup):
    """Fetch a row matching *lookup* fields, or create it if none exists.

    Parameters
    ----------
    db : Session
        Active SQLAlchemy session.
    model : type
        SQLAlchemy ORM model class to query.
    defaults : dict or None
        Extra field values applied only when creating a new row.
    **lookup
        Column=value pairs used as the lookup filter.

    Returns
    -------
    tuple[Base, bool]
        The existing or newly created instance, and True when newly created.
    """
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
    """Query all rows of *model*, optionally filtered by keyword arguments.

    Parameters
    ----------
    db : Session
        Active SQLAlchemy session.
    model : type
        SQLAlchemy ORM model class to query.
    filters : dict or None
        Column=value pairs passed to ``filter_by``; None returns all rows.

    Returns
    -------
    list[Base]
        All matching ORM instances.
    """
    query = db.query(model)
    if filters:
        query = query.filter_by(**filters)
    return query.all()


def update_data(db, model, filters, updates):
    """Update rows in *model* that match *filters* with the given *updates*.

    Parameters
    ----------
    db : Session
        Active SQLAlchemy session.
    model : type
        SQLAlchemy ORM model class to update.
    filters : dict
        Column=value pairs identifying rows to update.
    updates : dict
        Column=value pairs to apply to matching rows.
    """
    query = db.query(model).filter_by(**filters)
    query.update(updates)
    db.commit()


def delete_data(db, model, filters):
    """Delete rows from *model* that match *filters*.

    Parameters
    ----------
    db : Session
        Active SQLAlchemy session.
    model : type
        SQLAlchemy ORM model class to delete from.
    filters : dict
        Column=value pairs identifying rows to delete.
    """
    query = db.query(model).filter_by(**filters)
    query.delete()
    db.commit()


# ============================================================================
# Domain operations
# ============================================================================

def add_to_network(network_name):
    """Create or retrieve a network record by name.

    Parameters
    ----------
    network_name : str
        Name of the network to create or look up.

    Returns
    -------
    tuple[Network, bool]
        The Network instance and True when newly created.
    """
    db = SessionLocal()
    try:
        network, created = get_or_create(db, Network, network_name=network_name)
        return network, created
    finally:
        db.close()


def add_device(devices, network):
    """Add or update devices for a network, skipping lower-confidence duplicates.

    Each device row is compared against any existing record for the same MAC and
    network. The stored record is updated only when the incoming confidence is
    strictly higher than the stored value.

    Parameters
    ----------
    devices : pd.DataFrame
        Prediction results with columns: MAC_Address, Predicted_Device,
        Confidence, and optionally IP_Address.
    network : str or Network
        Network name string or an existing Network ORM instance.

    Returns
    -------
    dict
        Counts of ``inserted``, ``updated``, and ``skipped`` rows.

    Raises
    ------
    ValueError
        If the specified network does not exist and cannot be resolved.
    """
    db = SessionLocal()
    stats = {"inserted": 0, "updated": 0, "skipped": 0}

    network_row = network if isinstance(network, Network) else db.query(Network).filter_by(network_name=network).first()
    if network_row is None and isinstance(network, str):
        network_row, _ = get_or_create(db, Network, network_name=network)
    if network_row is None:
        db.close()
        raise ValueError("Network must exist before adding devices")

    network_id = network_row.id

    for record in devices.to_dict(orient="records"):
        mac = record.get('MAC_Address')
        if not mac:
            stats["skipped"] += 1
            continue

        incoming_confidence = record.get('Confidence')
        try:
            incoming_confidence = float(incoming_confidence) if incoming_confidence is not None else None
            if pd.isna(incoming_confidence):
                incoming_confidence = None
        except (TypeError, ValueError):
            incoming_confidence = None

        try:
            existing = db.query(Device).filter_by(mac_address=mac, network_id=network_id).first()
            if existing:
                should_replace = (
                    incoming_confidence is not None
                    and (existing.confidence is None or incoming_confidence > existing.confidence)
                )

                if should_replace:
                    existing.device_name = record.get('Predicted_Device') or existing.device_name
                    existing.device_type = record.get('Predicted_Device') or existing.device_type
                    existing.ip_address = record.get('IP_Address') or existing.ip_address
                    existing.confidence = incoming_confidence
                    db.commit()
                    stats["updated"] += 1
                else:
                    stats["skipped"] += 1
            else:
                device = Device(
                    device_name=record.get('Predicted_Device') or 'Unknown',
                    device_type=record.get('Predicted_Device') or 'Unknown',
                    mac_address=mac,
                    ip_address=record.get('IP_Address'),
                    confidence=incoming_confidence,
                    network_id=network_id
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
    """Return all devices associated with the named network.

    Parameters
    ----------
    network_name : str
        Name of the network to query.

    Returns
    -------
    list[Device]
        All Device instances belonging to the network.

    Raises
    ------
    ValueError
        If no network with the given name exists in the database.
    """
    db = SessionLocal()
    network = db.query(Network).filter_by(network_name=network_name).first()
    if not network:
        db.close()
        raise ValueError(f"Network '{network_name}' not found.")
    devices = list(network.devices)  # eager-load before session close to avoid DetachedInstanceError
    db.close()
    return devices


def all_networks():
    """Return all Network records stored in the database.

    Returns
    -------
    list[Network]
        All Network instances.
    """
    db = SessionLocal()
    networks = db.query(Network).all()
    db.close()
    return networks


if __name__ == "__main__":
    create_all_tables()

    db = SessionLocal()

    devices = get_devices_by_network("Default_Network")
    for device in devices:
        print(f"Device: {device.device_name}, MAC: {device.mac_address}, Confidence: {device.confidence}")

    db.close()
