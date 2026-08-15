
from google.cloud.firestore_v1.async_client import AsyncClient

from app.repositories.base import BaseRepository


class OAuthTransactionRepository(BaseRepository):
    def __init__(self, db: AsyncClient):
        """
        Initializes the OAuthTransactionRepository.
        """
        super().__init__(db, "oauth_transactions")
