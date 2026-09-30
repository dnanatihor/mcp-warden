"""Bearer-token authentication for the HTTP gateway.

The presented key is hashed and compared by ``PrincipalDirectory.lookup``.
A miss is an authentication failure: the verifier returns ``None`` so FastMCP
answers HTTP 401, and the application log records that failure without the key.
"""

from __future__ import annotations

import logging

from fastmcp.server.auth import AccessToken, TokenVerifier

from mcp_warden.principals import PrincipalDirectory

logger = logging.getLogger("mcp_warden.auth")


class PrincipalTokenVerifier(TokenVerifier):
    def __init__(self, directory: PrincipalDirectory) -> None:
        super().__init__()
        self._directory = directory

    async def verify_token(self, token: str) -> AccessToken | None:
        principal = self._directory.lookup(token)
        if principal is None:
            logger.warning("authentication failed")
            return None
        return AccessToken(
            token=principal.key_sha256,
            client_id=principal.id,
            scopes=[],
        )
