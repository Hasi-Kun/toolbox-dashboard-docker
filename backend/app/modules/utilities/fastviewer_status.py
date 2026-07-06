import httpx
from pydantic import BaseModel

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import query

DEFAULT_UPDATE_SERVER = "update.fastviewer.com"
SERVER_LIST_PATH = "ServersV3.txt"


@register_module
class FastviewerStatusModule(ToolModule):
    slug = "fastviewer-status"
    category = "utilities"
    name = "FastViewer Server Status"
    description = (
        "Ruft die FastViewer-Serverliste ab und prueft per DNS, ob die Server aufloesbar sind -- "
        "analog zum FastViewer-eigenen PowerShell-Diagnoseskript (GetFVSrvIP)."
    )
    is_active_scan = False
    timeout_seconds = 15

    class Input(BaseModel):
        pass

    class ServerStatus(BaseModel):
        hostname: str
        resolved: bool
        ip_addresses: list[str] = []

    class Output(BaseModel):
        success: bool
        checked_count: int
        online_count: int
        servers: list["FastviewerStatusModule.ServerStatus"] = []
        error: str | None = None

    async def run(self, data: Input) -> Output:
        server_names: list[str] = [DEFAULT_UPDATE_SERVER]

        warning = None
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.get(f"https://{DEFAULT_UPDATE_SERVER}/{SERVER_LIST_PATH}")
            if response.status_code == 200:
                for line in response.text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    hostname = line.split(":", 1)[1] if ":" in line else line
                    hostname = "".join(c for c in hostname if c.isalnum() or c in ".-")
                    if hostname and hostname not in server_names:
                        server_names.append(hostname)
            else:
                warning = f"Serverliste antwortete mit HTTP {response.status_code}"
        except httpx.HTTPError as exc:
            warning = f"Serverliste konnte nicht geladen werden: {exc}"

        statuses: list[FastviewerStatusModule.ServerStatus] = []
        for hostname in server_names:
            result = await query(hostname, "A", timeout=5)
            statuses.append(
                self.ServerStatus(
                    hostname=hostname,
                    resolved=result["success"] and bool(result["records"]),
                    ip_addresses=result["records"] if result["success"] else [],
                )
            )

        online_count = sum(1 for s in statuses if s.resolved)
        return self.Output(
            success=True, checked_count=len(statuses), online_count=online_count,
            servers=statuses, error=warning,
        )
