from database import init_db
import asyncio

# Initialize the tables
asyncio.run(init_db())
