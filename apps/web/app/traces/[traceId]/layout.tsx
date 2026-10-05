export function generateStaticParams() {
  return [{ traceId: "_" }];
}

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}
