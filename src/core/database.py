"""
Database Initialization and Management
Handles database setup, migrations, and lifecycle
"""

import asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text
from alembic.config import Config
from alembic import command
import alembic.util.messaging

from ..core.production_config import DatabaseSettings
from ..core.production_logging import get_logger
from ..auth.models import Base


logger = get_logger(__name__)


class DatabaseManager:
    """Database management for DevSecOps Platform"""
    
    def __init__(self, db_settings: DatabaseSettings):
        self.db_settings = db_settings
        self.engine = None
        self.session_factory = None
        
    async def initialize(self) -> None:
        """Initialize database connection and create tables"""
        try:
            # Build database URL
            if self.db_settings.url:
                database_url = self.db_settings.url
            else:
                database_url = (
                    f"postgresql+asyncpg://{self.db_settings.username}:"
                    f"{self.db_settings.password.get_secret_value()}@"
                    f"{self.db_settings.host}:{self.db_settings.port}/"
                    f"{self.db_settings.name}"
                )
            
            # Create async engine
            self.engine = create_async_engine(
                database_url,
                echo=self.db_settings.echo,
                pool_size=self.db_settings.pool_size,
                max_overflow=self.db_settings.max_overflow,
                pool_timeout=self.db_settings.pool_timeout,
                pool_recycle=self.db_settings.pool_recycle,
            )
            
            # Create session factory
            self.session_factory = sessionmaker(
                self.engine,
                class_=AsyncSession,
                expire_on_commit=False
            )
            
            # Test connection
            await self._test_connection()
            
            # Create tables if they don't exist
            await self._create_tables()
            
            logger.info("Database initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise
    
    async def _test_connection(self) -> None:
        """Test database connection"""
        async with self.engine.begin() as conn:
            result = await conn.execute(text("SELECT 1"))
            assert result.scalar() == 1
        logger.info("Database connection test successful")
    
    async def _create_tables(self) -> None:
        """Create database tables"""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables created/verified")
    
    async def cleanup(self) -> None:
        """Cleanup database connections"""
        if self.engine:
            await self.engine.dispose()
        logger.info("Database connections closed")
    
    def get_session(self) -> AsyncSession:
        """Get database session"""
        if not self.session_factory:
            raise RuntimeError("Database not initialized")
        return self.session_factory()
    
    async def health_check(self) -> bool:
        """Database health check"""
        try:
            async with self.engine.begin() as conn:
                await conn.execute(text("SELECT 1"))
            return True
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False
    
    def run_migrations(self) -> None:
        """Run database migrations (sync operation)"""
        try:
            # Configure Alembic
            alembic_cfg = Config("alembic.ini")
            
            # Run migrations to latest
            command.upgrade(alembic_cfg, "head")
            
            logger.info("Database migrations completed successfully")
            
        except Exception as e:
            logger.error(f"Database migration failed: {e}")
            raise
    
    async def backup_database(self, backup_path: str) -> None:
        """Create database backup"""
        # This would implement database backup logic
        # For PostgreSQL, this could use pg_dump
        logger.info(f"Database backup functionality not yet implemented: {backup_path}")
    
    async def get_database_stats(self) -> dict:
        """Get database statistics"""
        try:
            async with self.engine.begin() as conn:
                # Get table sizes and row counts
                stats = {}
                
                # Get total database size
                size_query = text("""
                    SELECT pg_size_pretty(pg_database_size(current_database())) as size
                """)
                result = await conn.execute(size_query)
                stats["database_size"] = result.scalar()
                
                # Get table statistics
                table_stats_query = text("""
                    SELECT 
                        schemaname,
                        tablename,
                        attname,
                        n_distinct,
                        correlation
                    FROM pg_stats 
                    WHERE schemaname = 'public'
                    ORDER BY tablename, attname
                """)
                result = await conn.execute(table_stats_query)
                stats["table_stats"] = [dict(row) for row in result]
                
                # Get connection count
                conn_query = text("""
                    SELECT count(*) as active_connections
                    FROM pg_stat_activity 
                    WHERE state = 'active'
                """)
                result = await conn.execute(conn_query)
                stats["active_connections"] = result.scalar()
                
                return stats
                
        except Exception as e:
            logger.error(f"Failed to get database stats: {e}")
            return {"error": str(e)}


# Global database manager instance
db_manager: DatabaseManager = None


def get_database_manager() -> DatabaseManager:
    """Get global database manager instance"""
    if not db_manager:
        raise RuntimeError("Database manager not initialized")
    return db_manager


def initialize_database_manager(db_settings: DatabaseSettings) -> DatabaseManager:
    """Initialize global database manager"""
    global db_manager
    db_manager = DatabaseManager(db_settings)
    return db_manager
