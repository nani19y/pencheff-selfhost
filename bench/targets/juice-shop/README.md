# OWASP Juice Shop target

Modern Node/Angular single-page application that deliberately ships
with 100+ vulnerabilities across every OWASP Top-10 category and
many of the OWASP ASVS categories. The big advantage over WAVSEP /
Benchmark is that **the app self-verifies exploits** via its
built-in scoreboard — there is no ambiguity about whether a reported
finding was actually exploited.

## Reachability

`docker-compose.targets.yml` exposes it on the host at
`http://localhost:3001`. From other containers (Pencheff worker,
dockerised ZAP):

* macOS / Windows → `http://host.docker.internal:3001`
* Linux → `http://172.17.0.1:3001` (default bridge) or join the
  `bench-default` network and use `http://juice-shop:3000`.

## Scoring

`GET /api/challenges` returns the full list with a `solved` flag per
entry. `score/juice_shop_score.py` reads this and writes:

```
scanner,target,solved,total,solved_ratio
pencheff,juice-shop,47,112,0.42
zap,juice-shop,11,112,0.098
```

## Resetting between runs

Juice Shop's scoreboard persists in memory for the life of the
container. To reset between scanners:

```
docker compose -f bench/docker-compose.targets.yml restart juice-shop
```

(Takes ~15 s.)

## Useful challenge classes for Pencheff

Pencheff's agent should be able to confirm at least these without the
human supplying payloads:

- **Broken authentication** — login via SQLi, password guessing,
  forgotten-password flow abuse.
- **IDOR** — view another user's basket, order, address.
- **JWT flaws** — algorithm confusion, kid path traversal.
- **Improper input validation** — XSS reflected in the product search
  autocomplete, DOM XSS in the `redirect` query parameter.
- **SSRF** — via the profile-image-URL upload feature.
- **Business logic** — discount-code brute force, negative quantity.

If Pencheff's agent solves < 30 challenges in 15 minutes on the
default profile, something's wrong.
