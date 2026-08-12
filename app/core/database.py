import os

import firebase_admin
from fastapi import Request
from firebase_admin import credentials
from google.cloud.firestore_v1.async_client import AsyncClient

from app.core.config import settings


def init_db():
    """
    Initializes the Firebase Admin SDK using the credentials
    specified in the environment variables.
    """
    if not firebase_admin._apps:
        cred = None
        if settings.google_application_credentials and os.path.exists(settings.google_application_credentials):
            cred = credentials.Certificate(settings.google_application_credentials)
            firebase_admin.initialize_app(cred)
        else:
            firebase_admin.initialize_app()
    print("Firebase Admin initialized successfully.")

def get_db_client() -> AsyncClient:
    """
    Creates and returns an AsyncClient for Firestore, correctly
    resolving the project ID from the initialized Firebase app.
    """
    app = firebase_admin.get_app()
    project_id = app.project_id or os.environ.get("GOOGLE_CLOUD_PROJECT")
    if not project_id:
        cred = firebase_admin.get_app().credential
        if hasattr(cred, "project_id"):
            project_id = cred.project_id

    database = settings.firestore_database or "(default)"
    return AsyncClient(project=project_id, database=database)

def get_db(request: Request) -> AsyncClient:
    """Dependency that returns an Async Firestore client from app state."""
    return request.app.state.db_client
