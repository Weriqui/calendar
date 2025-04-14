from __future__ import print_function

import os
from typing import List, Optional

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from lista import calendarios

SCOPES: List[str] = ["https://www.googleapis.com/auth/calendar"]


def obter_credenciais(
    token_path: str = "token.json",
    client_secret: str = "credentials.json",
    scopes: Optional[List[str]] = None,
) -> Credentials:
    """
    Valida o token existente ou executa o fluxo OAuth e devolve `Credentials`.
    Compatível com Python 3.8+ (usa typing.Optional / typing.List).
    """
    if scopes is None:
        scopes = SCOPES

    creds: Optional[Credentials] = None

    # 1) Tenta carregar token salvo
    if os.path.exists(token_path):
        creds = Credentials.from_authorized_user_file(token_path, scopes)

    # 2) Valida / renova ou inicia novo fluxo
    if creds and creds.valid:
        return creds

    if creds and creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            with open(token_path, "w", encoding="utf-8") as token_file:
                token_file.write(creds.to_json())
            return creds
        except Exception:
            pass  # se falhar, cai no fluxo interativo

    # 3) Fluxo OAuth interativo
    flow = InstalledAppFlow.from_client_secrets_file(client_secret, scopes)
    creds = flow.run_local_server(port=0)

    # 4) Salva token
    with open(token_path, "w", encoding="utf-8") as token_file:
        token_file.write(creds.to_json())

    return creds


def criar_calendario(
    nome: str,
    creds: Credentials,
    time_zone: str = "America/Sao_Paulo",
) -> str:
    """Cria um calendário usando credenciais já obtidas."""
    service = build("calendar", "v3", credentials=creds)
    body = {"summary": nome, "timeZone": time_zone}
    calendar = service.calendars().insert(body=body).execute()

    calendar_id = calendar["id"]
    print(f"Calendário “{nome}” criado! ID: {calendar_id}")
    return calendar_id


# Uso mínimo ------------------------------------------------------------------
if __name__ == "__main__":
    credenciais = obter_credenciais()          # faz/renova login
    for cal in calendarios:
        criar_calendario(cal, credenciais)
