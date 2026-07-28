"""MCP server skeleton.

TODO: register tools once policy (Phase 1) and executor (Phase 2) exist.
"""

from mcp.server.fastmcp import FastMCP

server = FastMCP("hardened-terminal-mcp")


def main() -> None:
    server.run()
