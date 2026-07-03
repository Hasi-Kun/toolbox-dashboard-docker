export function MetricCard({
  label,
  value,
  unit,
  hint,
}: {
  label: string;
  value: string;
  unit?: string;
  hint?: string;
}) {
  return (
    <div className="rounded-xl border border-base-border bg-base-elevated p-5 shadow-card">
      <p className="text-sm text-ink-muted">{label}</p>
      <p className="mt-2 font-mono text-2xl text-ink">
        {value}
        {unit && <span className="ml-1 text-sm text-ink-muted">{unit}</span>}
      </p>
      {hint && <p className="mt-1 text-xs text-ink-muted">{hint}</p>}
    </div>
  );
}

export function EmptyListCard({
  label,
  emptyText,
}: {
  label: string;
  emptyText: string;
}) {
  return (
    <div className="rounded-xl border border-base-border bg-base-elevated p-5 shadow-card">
      <p className="text-sm text-ink-muted">{label}</p>
      <div className="mt-4 flex h-24 items-center justify-center rounded-lg border border-dashed border-base-border text-center text-sm text-ink-muted">
        {emptyText}
      </div>
    </div>
  );
}
