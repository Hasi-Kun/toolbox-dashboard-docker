import { Crown } from "lucide-react";

export function PremiumBadge({ color = "#F5C518" }: { color?: string }) {
  return (
    <span
      className="premium-badge inline-flex items-center gap-0.5 rounded-full px-1.5 py-0.5 text-[10px] font-semibold"
      style={{
        color,
        backgroundColor: `${color}1A`,
        border: `1px solid ${color}55`,
      }}
      title="Premium"
    >
      <Crown className="h-2.5 w-2.5" style={{ color }} />
      VIP
    </span>
  );
}
