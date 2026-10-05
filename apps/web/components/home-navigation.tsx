import Image from "next/image";
import Link from "next/link";
import { getNavItemHref, NAV_MENUS, type NavMenu } from "@/lib/marketing-nav";

function MegaNavMenu({ menu }: { menu: NavMenu }) {
  return (
    <div className="home-nav-menu">
      <button className="home-nav-trigger" type="button" aria-haspopup="true">
        <span>{menu.label}</span>
        <span aria-hidden="true" className="home-nav-chevron">
          v
        </span>
      </button>
      <div className="home-mega" aria-label={`${menu.label} navigation`}>
        <aside className="home-mega-aside">
          <p className="home-mega-eyebrow">{menu.eyebrow}</p>
          <h2>{menu.title}</h2>
          <p>{menu.body}</p>
          <Link href={getNavItemHref(menu, menu.cta)} className="home-mega-cta">
            <strong>{menu.cta.title}</strong>
            <span>{menu.cta.body}</span>
          </Link>
          <div className="home-mega-quick">
            {menu.quickLinks.map((item) => (
              <Link href={getNavItemHref(menu, item)} key={item.title}>
                <strong>{item.title}</strong>
                <span>{item.body}</span>
              </Link>
            ))}
          </div>
        </aside>
        <div className="home-mega-main">
          {menu.groups.map((group) => (
            <section className="home-mega-group" key={group.title}>
              <h3>{group.title}</h3>
              <div className="home-mega-items">
                {group.items.map((item) => (
                  <Link
                    href={getNavItemHref(menu, item)}
                    className="home-mega-item"
                    key={item.title}
                  >
                    <strong>{item.title}</strong>
                    <span>{item.body}</span>
                  </Link>
                ))}
              </div>
            </section>
          ))}
        </div>
      </div>
    </div>
  );
}

export function HomeNavigation() {
  return (
    <nav className="home-nav" aria-label="Pencheff landing navigation">
      <Link href="/" className="home-brand" aria-label="Pencheff home">
        <Image
          src="/protect-deploy-deliver.jpeg"
          alt=""
          width={42}
          height={42}
          priority
          unoptimized
        />
        <span>Pencheff</span>
      </Link>
      <div className="home-nav-links">
        {NAV_MENUS.map((menu) => (
          <MegaNavMenu menu={menu} key={menu.label} />
        ))}
        <Link href="/login">Sign in</Link>
        <Link href="/signup" className="home-nav-cta">
          Start free
        </Link>
      </div>
    </nav>
  );
}
