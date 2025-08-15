#!/usr/bin/env python3
"""
MongoDB Connection Manager for InfraScanner Pro
Production-ready MongoDB connection handling with error handling and security features.
"""

import os
import logging
import time
from typing import Optional, Dict, Any
from pymongo import MongoClient
from pymongo.errors import (
    ServerSelectionTimeoutError, 
    ConnectionFailure, 
    ConfigurationError,
    OperationFailure,
    PyMongoError
)
from urllib.parse import quote_plus

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MongoConnectionManager:
    """
    MongoDB Connection Manager with connection pooling, health checks, and error handling.
    Implements singleton pattern to ensure single connection instance.
    """
    
    _instance: Optional['MongoConnectionManager'] = None
    _client: Optional[MongoClient] = None
    _db = None
    
    def __new__(cls) -> 'MongoConnectionManager':
        if cls._instance is None:
            cls._instance = super(MongoConnectionManager, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._initialized = True
        self.connection_attempts = 0
        self.max_retries = 3
        self.retry_delay = 2  # seconds
        
        # Load configuration
        self._load_config()
        
        # Initialize connection
        self._initialize_connection()
    
    def _load_config(self) -> None:
        """Load MongoDB configuration from environment variables."""
        # Primary connection URI
        self.mongo_uri = os.getenv("MONGO_URI")
        
        # Individual connection parameters (fallback if URI not provided)
        self.mongo_host = os.getenv("MONGO_HOST", "127.0.0.1")
        mongo_port_str = os.getenv("MONGO_PORT", "27017")
        
        # Validate port
        try:
            self.mongo_port = int(mongo_port_str)
            if not (1 <= self.mongo_port <= 65535):
                raise ValueError(f"Port {self.mongo_port} out of range")
        except ValueError as e:
            logger.error(f"Invalid MongoDB port: {mongo_port_str}. Using default 27017. Error: {e}")
            self.mongo_port = 27017
            
        self.mongo_username = os.getenv("MONGO_USERNAME", "admin")
        self.mongo_password = os.getenv("MONGO_PASSWORD", "admin123")
        self.mongo_database = os.getenv("MONGO_DATABASE", "scan_results")
        self.mongo_auth_source = os.getenv("MONGO_AUTH_SOURCE", "admin")
        
        # Connection pool settings
        self.max_pool_size = int(os.getenv("MONGO_MAX_POOL_SIZE", "100"))
        self.min_pool_size = int(os.getenv("MONGO_MIN_POOL_SIZE", "10"))
        self.connect_timeout_ms = int(os.getenv("MONGO_CONNECT_TIMEOUT_MS", "10000"))
        self.server_selection_timeout_ms = int(os.getenv("MONGO_SERVER_SELECTION_TIMEOUT_MS", "5000"))
    
    def _build_connection_uri(self) -> str:
        """Build MongoDB connection URI with proper encoding and security."""
        if self.mongo_uri:
            # Use provided URI but log a warning about credentials
            if "admin123" in self.mongo_uri:
                logger.warning("Default credentials detected in MONGO_URI. Please use strong credentials in production.")
            return self.mongo_uri
        
        # Build URI from individual components
        username = quote_plus(self.mongo_username)
        password = quote_plus(self.mongo_password)
        
        # Base URI
        if username and password:
            uri = f"mongodb://{username}:{password}@{self.mongo_host}:{self.mongo_port}"
        else:
            uri = f"mongodb://{self.mongo_host}:{self.mongo_port}"
        
        # Add database and auth source
        uri += f"/{self.mongo_database}?authSource={self.mongo_auth_source}"
        
        return uri
    
    def _get_connection_options(self) -> Dict[str, Any]:
        """Get MongoDB connection options."""
        options = {
            'serverSelectionTimeoutMS': self.server_selection_timeout_ms,
            'connectTimeoutMS': self.connect_timeout_ms,
            'maxPoolSize': self.max_pool_size,
            'minPoolSize': self.min_pool_size,
            'retryWrites': True,
            'retryReads': True,
        }
        return options
    
    def _initialize_connection(self) -> None:
        """Initialize MongoDB connection with retry logic."""
        uri = self._build_connection_uri()
        options = self._get_connection_options()
        
        for attempt in range(self.max_retries):
            try:
                logger.info(f"Attempting MongoDB connection (attempt {attempt + 1}/{self.max_retries})")
                
                self._client = MongoClient(uri, **options)
                
                # Test the connection
                self._client.admin.command('ping')
                
                # Get database reference
                self._db = self._client[self.mongo_database]
                
                # Create indexes for better performance
                self._create_indexes()
                
                logger.info("MongoDB connection established successfully")
                self.connection_attempts = attempt + 1
                return
                
            except ServerSelectionTimeoutError as e:
                logger.error(f"MongoDB server selection timeout (attempt {attempt + 1}): {e}")
            except ConnectionFailure as e:
                logger.error(f"MongoDB connection failed (attempt {attempt + 1}): {e}")
            except ConfigurationError as e:
                logger.error(f"MongoDB configuration error (attempt {attempt + 1}): {e}")
            except Exception as e:
                logger.error(f"Unexpected MongoDB connection error (attempt {attempt + 1}): {e}")
            
            if attempt < self.max_retries - 1:
                logger.info(f"Retrying in {self.retry_delay} seconds...")
                time.sleep(self.retry_delay)
                self.retry_delay *= 2  # Exponential backoff
        
        raise ConnectionFailure(f"Failed to connect to MongoDB after {self.max_retries} attempts")
    
    def _create_indexes(self) -> None:
        """Create database indexes for better performance."""
        try:
            # Indexes for nmap_scans collection
            nmap_collection = self._db["nmap_scans"]
            nmap_collection.create_index("server_ip")
            nmap_collection.create_index([("scanned_date", -1)])
            nmap_collection.create_index([("server_ip", 1), ("scanned_date", -1)])
            
            # Indexes for nuclei_vuln collection
            vuln_collection = self._db["nuclei_vuln"]
            vuln_collection.create_index("target")
            vuln_collection.create_index([("timestamp", -1)])
            vuln_collection.create_index([("target", 1), ("timestamp", -1)])
            
            # Indexes for alerts collection
            alert_collection = self._db["alerts"]
            alert_collection.create_index("server_ip")
            alert_collection.create_index([("alert_date", -1)])
            alert_collection.create_index([("server_ip", 1), ("alert_date", -1)])
            
            # Indexes for config_settings collection
            config_collection = self._db["config_settings"]
            config_collection.create_index("type")
            
            logger.info("Database indexes created successfully")
            
        except Exception as e:
            logger.warning(f"Failed to create database indexes: {e}")
    
    def get_database(self):
        """Get database connection with health check. FIXED: Use None comparison instead of boolean check."""
        # ✅ FIXED: Compare with None instead of using boolean evaluation
        if self._db is None or self._client is None:
            logger.warning("Database connection not initialized, reinitializing...")
            self._initialize_connection()
        
        try:
            # Health check
            self._client.admin.command('ping')
            return self._db
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            logger.info("Attempting to reconnect...")
            self._initialize_connection()
            return self._db
    
    def get_client(self) -> MongoClient:
        """Get MongoDB client with health check. FIXED: Use None comparison."""
        # ✅ FIXED: Compare with None instead of using boolean evaluation
        if self._client is None:
            logger.warning("MongoDB client not initialized, reinitializing...")
            self._initialize_connection()
        
        try:
            # Health check
            self._client.admin.command('ping')
            return self._client
        except Exception as e:
            logger.error(f"MongoDB client health check failed: {e}")
            logger.info("Attempting to reconnect...")
            self._initialize_connection()
            return self._client
    
    def close_connection(self) -> None:
        """Close MongoDB connection."""
        if self._client is not None:
            try:
                self._client.close()
                logger.info("MongoDB connection closed")
            except Exception as e:
                logger.error(f"Error closing MongoDB connection: {e}")
            finally:
                self._client = None
                self._db = None

# Global connection manager instance
_mongo_manager = None

def get_db():
    """Get database connection (backward compatible function)."""
    global _mongo_manager
    if _mongo_manager is None:
        _mongo_manager = MongoConnectionManager()
    return _mongo_manager.get_database()

def get_client() -> MongoClient:
    """Get MongoDB client."""
    global _mongo_manager
    if _mongo_manager is None:
        _mongo_manager = MongoConnectionManager()
    return _mongo_manager.get_client()

def health_check() -> Dict[str, Any]:
    """Perform MongoDB health check."""
    global _mongo_manager
    if _mongo_manager is None:
        _mongo_manager = MongoConnectionManager()
    
    health_status = {
        "status": "unknown",
        "connected": False,
        "connection_attempts": _mongo_manager.connection_attempts,
        "error": None
    }
    
    try:
        # Basic ping
        _mongo_manager._client.admin.command('ping')
        health_status["connected"] = True
        health_status["status"] = "healthy"
    except Exception as e:
        health_status["status"] = "unhealthy"
        health_status["error"] = str(e)
        logger.error(f"MongoDB health check failed: {e}")
    
    return health_status

# For testing and development
if __name__ == "__main__":
    # Test the connection
    try:
        print("Testing MongoDB connection...")
        db = get_db()
        print("✅ Database connection successful")
        
        health = health_check()
        print(f"✅ Health check: {health['status']}")
        
        # Test collections
        collections = db.list_collection_names()
        print(f"📁 Available collections: {collections}")
        
    except Exception as e:
        print(f"❌ Connection test failed: {e}")
