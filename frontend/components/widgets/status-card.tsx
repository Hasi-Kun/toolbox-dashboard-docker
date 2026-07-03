type Status = "online" | "degraded" | "offline";

const statusColor: Record<Status, string> = {
  online: "text-signal",
  degraded: "text-warn",
  offline: "text-critical",
};

const statusLabel: Record<Status, string> = {
  online: "Online",
  degraded: "Eingeschraenkt",
  offline: "Offline",
};

export function StatusCard({
  status = "online",
  label = "Server Status",
}: {
  status?: Status;
  label?: string;
}) {
  return (
    <div className="rounded-xl border border-base-border bg-base-elevated p-5 shadow-card">
      <div className="flex items-center justify-between">
        <p className="text-sm text-ink-muted">{label}</p>
        <span className={`text-xs font-medium ${statusColor[status]}`}>
          {statusLabel[status]}
        </span>
      </div>

      <div className="mt-4 flex items-center justify-center">
        <RadarIndicator status={status} />
      </div>
    </div>
  );
}

function RadarIndicator({ status }: { status: Status }) {
  const ringColor =
    status === "online" ? "#35E0C0" : status === "degraded" ? "#F5A623" : "#FF5C5C";

  return (
    <svg viewBox="0 0 100 100" className="h-24 w-24">
      <circle cx="50" cy="50" r="46" fill="none" stroke="#1E293F" strokeWidth="1.5" />
      <circle cx="50" cy="50" r="30" fill="none" stroke="#1E293F" strokeWidth="1" />
      <circle cx="50" cy="50" r="14" fill="none" stroke="#1E293F" strokeWidth="1" />

      {status !== "offline" && (
        <g className="radar-sweep" style={{ transformOrigin: "50% 50%", transformBox: "view-box" }}>
          <path
            d="M50 50 L50 4 A46 46 0 0 1 88 27 Z"
            fill={ringColor}
            opacity="0.15"
          />
          <line x1="50" y1="50" x2="50" y2="4" stroke={ringColor} strokeWidth="1.5" />
        </g>
      )}

      <circle cx="50" cy="50" r="4" fill={ringColor} />
    </svg>
  );
}
