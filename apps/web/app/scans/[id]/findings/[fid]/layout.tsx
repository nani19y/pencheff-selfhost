export function generateStaticParams() {
  return [{ fid: "_" }];
}

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}
