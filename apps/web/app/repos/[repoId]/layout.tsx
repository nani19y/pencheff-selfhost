export function generateStaticParams() {
  return [{ repoId: "_" }];
}

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}
