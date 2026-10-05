import Link from "next/link";

type LandingArticleSection = {
  heading: string;
  body: React.ReactNode;
};

export function LandingArticle({
  eyebrow,
  title,
  lede,
  sections,
  cta,
}: {
  eyebrow: string;
  title: React.ReactNode;
  lede: string;
  sections?: LandingArticleSection[];
  cta?: { label: string; href: string; external?: boolean };
}) {
  return (
    <main className="lp-article">
      <section className="lp-article-head">
        <div className="lp-shell">
          <div className="lp-article-grid">
            <div className="lp-article-copy">
              <span className="lp-eyebrow lp-fade-up">{eyebrow}</span>
              <h1
                className="lp-h-section lp-fade-up"
                style={{ ["--lp-d" as string]: "100ms" } as React.CSSProperties}
              >
                {title}
              </h1>
              <p
                className="lp-lede lp-fade-up"
                style={{ ["--lp-d" as string]: "220ms" } as React.CSSProperties}
              >
                {lede}
              </p>
              {cta && (
                <div
                  className="lp-article-cta lp-fade-up"
                  style={{ ["--lp-d" as string]: "320ms" } as React.CSSProperties}
                >
                  {cta.external ? (
                    <a
                      className="lp-btn lp-btn-arrow lp-btn-lime"
                      href={cta.href}
                      target="_blank"
                      rel="noreferrer"
                    >
                      {cta.label}
                    </a>
                  ) : (
                    <Link className="lp-btn lp-btn-arrow lp-btn-lime" href={cta.href}>
                      {cta.label}
                    </Link>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      </section>

      {sections && sections.length > 0 && (
        <section className="lp-article-body">
          <div className="lp-shell">
            <div className="lp-article-sections">
              {sections.map((s, idx) => (
                <article
                  key={`${s.heading}-${idx}`}
                  className="lp-article-section lp-fade-spring"
                  style={
                    { ["--lp-d" as string]: `${idx * 90}ms` } as React.CSSProperties
                  }
                >
                  <h2>{s.heading}</h2>
                  <div className="lp-article-section-body">
                    {typeof s.body === "string" ? <p>{s.body}</p> : s.body}
                  </div>
                </article>
              ))}
            </div>
          </div>
        </section>
      )}
    </main>
  );
}
