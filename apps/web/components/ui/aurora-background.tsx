"use client";
import { cn } from "@/lib/cn";
import React, { ReactNode } from "react";

interface AuroraBackgroundProps extends React.HTMLProps<HTMLDivElement> {
  children: ReactNode;
  showRadialGradient?: boolean;
}

/**
 * AuroraBackground — monochrome edition.
 * Soft drifting bands of grayscale behind hero sections, masked into the
 * top-right corner so it reads as a quiet horizon glow.
 */
export const AuroraBackground = ({
  className,
  children,
  showRadialGradient = true,
  ...props
}: AuroraBackgroundProps) => {
  return (
    <main>
      <div
        className={cn(
          "relative flex flex-col h-[100vh] items-center justify-center bg-transparent text-ink transition-bg",
          className
        )}
        {...props}
      >
        <div className="absolute inset-0 overflow-hidden">
          <div
            className={cn(
              `
            [--white-gradient:repeating-linear-gradient(110deg,#FFFFFF_0%,#FFFFFF_7%,transparent_10%,transparent_12%,#FFFFFF_16%)]
            [--mono:repeating-linear-gradient(110deg,#D4D4D4_10%,#E5E5E5_15%,#A3A3A3_20%,#F5F5F5_25%,#737373_30%)]
            [background-image:var(--white-gradient),var(--mono)]
            [background-size:300%,_220%]
            [background-position:50%_50%,50%_50%]
            filter blur-[28px]
            after:content-[""] after:absolute after:inset-0
            after:[background-image:var(--white-gradient),var(--mono)]
            after:[background-size:220%,_120%]
            after:animate-aurora after:[background-attachment:fixed] after:mix-blend-multiply
            pointer-events-none
            absolute -inset-[14px] opacity-[0.40] will-change-transform`,

              showRadialGradient &&
                `[mask-image:radial-gradient(ellipse_at_100%_0%,black_10%,transparent_70%)]`
            )}
          ></div>
        </div>
        {children}
      </div>
    </main>
  );
};
