import { Crown, ShieldCheck } from "lucide-react";

type StyledUsernameProps = {
  username: string;
  role: string;
  isPremium: boolean;
  displayNameStyle: string;
  displayNameColor: string;
  displayNameGradientColor: string;
  premiumBadgeColor?: string;
  showBadge?: boolean;
};

export function StyledUsername({
  username,
  role,
  isPremium,
  displayNameStyle,
  displayNameColor,
  displayNameGradientColor,
  premiumBadgeColor = "#F5C518",
  showBadge = true,
}: StyledUsernameProps) {
  const isAdmin = role === "admin";
  const applyStyle = isPremium && displayNameStyle !== "default";

  const nameStyle: React.CSSProperties = {};
  let nameClassName = "font-medium";

  if (applyStyle && displayNameStyle === "solid") {
    nameStyle.color = displayNameColor;
  } else if (applyStyle && displayNameStyle === "gradient") {
    nameStyle.backgroundImage = `linear-gradient(90deg, ${displayNameColor}, ${displayNameGradientColor})`;
    nameStyle.WebkitBackgroundClip = "text";
    nameStyle.backgroundClip = "text";
    nameStyle.color = "transparent";
  } else if (applyStyle && displayNameStyle === "particles") {
    nameStyle.color = displayNameColor;
    nameClassName += " styled-name-particles";
  } else if (applyStyle && displayNameStyle === "twinkle") {
    nameClassName += " styled-name-twinkle";
    nameStyle.backgroundImage = `linear-gradient(110deg, ${displayNameColor} 0%, ${displayNameColor} 40%, ${displayNameGradientColor} 50%, ${displayNameColor} 60%, ${displayNameColor} 100%)`;
    nameStyle.WebkitBackgroundClip = "text";
    nameStyle.backgroundClip = "text";
    nameStyle.color = "transparent";
    (nameStyle as Record<string, string>)["--twinkle-glow"] = displayNameGradientColor;
  } else if (applyStyle && displayNameStyle === "glitter") {
    nameClassName += " styled-name-glitter";
    (nameStyle as Record<string, string>)["--glitter-base"] = displayNameColor;
  } else if (applyStyle && displayNameStyle === "rainbow") {
    nameClassName += " styled-name-rainbow";
  }

  return (
    <span className="inline-flex items-center gap-1.5">
      <span className={nameClassName} style={nameStyle}>
        {username}
      </span>
      {showBadge && isAdmin && (
        <span
          className="inline-flex items-center gap-0.5 rounded-full border border-signal/40 bg-signal/10 px-1.5 py-0.5 text-[10px] font-semibold text-signal"
          title="Administrator"
        >
          <ShieldCheck className="h-2.5 w-2.5" />
          ADMIN
        </span>
      )}
      {showBadge && !isAdmin && isPremium && (
        <span
          className="premium-badge inline-flex items-center gap-0.5 rounded-full px-1.5 py-0.5 text-[10px] font-semibold"
          style={{ color: premiumBadgeColor, backgroundColor: `${premiumBadgeColor}1A`, border: `1px solid ${premiumBadgeColor}55` }}
          title="Premium"
        >
          <Crown className="h-2.5 w-2.5" style={{ color: premiumBadgeColor }} />
          VIP
        </span>
      )}
    </span>
  );
}
