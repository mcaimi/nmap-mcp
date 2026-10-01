"""FastAPI application with MCP server for nmap scanning."""

from __future__ import annotations

import contextlib
import os
import shutil

from fastapi import FastAPI
from mcp.server import MCPServer

from nmap_mcp import prompts, resources, tools

mcp = MCPServer(
    name="nmap-mcp",
    description=(
        "Network port scanner and host discovery server using nmap. "
        "Performs host discovery, TCP/UDP/SCTP port scanning, service version detection, "
        "OS fingerprinting, firewall analysis, and vulnerability assessment."
    ),
    version="0.1.0",
)

tools.register(mcp)
resources.register(mcp)
prompts.register(mcp)

mcp_http_app = mcp.streamable_http_app()


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    async with contextlib.AsyncExitStack() as stack:
        await stack.enter_async_context(mcp.session_manager.run())
        yield


app = FastAPI(
    title="nmap-mcp",
    description="MCP server for nmap port scanning and network reconnaissance",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health():
    nmap_path = shutil.which("nmap")
    return {
        "status": "ok",
        "nmap_available": nmap_path is not None,
        "nmap_path": nmap_path,
        "privileged": os.getuid() == 0,
    }


app.mount("/mcp", mcp_http_app)


def main():
    import uvicorn
    uvicorn.run(
        "nmap_mcp.server:app",
        host="0.0.0.0",
        port=8000,
    )
