import asyncio
import os

# Ensure emulator is bypassed
if "FIRESTORE_EMULATOR_HOST" in os.environ:
    del os.environ["FIRESTORE_EMULATOR_HOST"]
# Force production environment to pick up proper credentials
os.environ["IDENTITY_ENVIRONMENT"] = "production"

from app.core.database import get_db_client, init_db


async def delete_collection(coll_ref, batch_size):
    deleted = 0
    async for doc in coll_ref.limit(batch_size).stream():
        print(f"Deleting doc {doc.id} => {doc.reference.path}")
        await doc.reference.delete()
        deleted += 1
        
    if deleted >= batch_size:
        return await delete_collection(coll_ref, batch_size)

async def main():
    print("Initializing DB connection...")
    init_db()
    db = get_db_client()
    
    # We must explicitly list collections as we might not be able to dynamically fetch them all
    # without specific permissions, but let's try db.collections() first
    try:
        collections = db.collections()
        async for coll in collections:
            print(f"Deleting collection: {coll.id}")
            await delete_collection(coll, 500)
    except Exception as e:
        print(f"Failed to fetch collections dynamically: {e}")
        print("Falling back to hardcoded collections...")
        collections = ["applications", "application_credentials", "users", "refresh_tokens", "roles", "permissions"]
        for coll_name in collections:
            coll = db.collection(coll_name)
            print(f"Deleting collection: {coll_name}")
            await delete_collection(coll, 500)
        
    print("Done dropping all documents.")

if __name__ == "__main__":
    asyncio.run(main())
