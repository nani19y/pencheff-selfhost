export function generateStaticParams() {
  return [{ scanId: "_" }];
}

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}
