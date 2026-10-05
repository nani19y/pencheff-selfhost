import { notFound } from "next/navigation";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import rehypeRaw from "rehype-raw";
import rehypeHighlight from "rehype-highlight";
import { getPost } from "@/lib/content";
import type { Metadata } from "next";

export const dynamic = "force-dynamic";
export const revalidate = 0;

// NO generateStaticParams — routes are resolved at request time so new .md
// files dropped into the content directory appear immediately without rebuild.

interface Props {
  params: Promise<{ slug: string }>;
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { slug } = await params;
  const post = getPost(slug);
  if (!post) return {};
  return {
    title: post.title,
    description: post.description || undefined,
    authors: post.author ? [{ name: post.author }] : undefined,
    openGraph: {
      title: post.title,
      description: post.description || undefined,
      type: "article",
      publishedTime: post.date || undefined,
    },
  };
}

export default async function PostPage({ params }: Props) {
  const { slug } = await params;
  const post = getPost(slug);
  if (!post) notFound();

  return (
    <article>
      <header className="post-header">
        <h1 className="post-headline">{post.title}</h1>
        {(post.date || post.author) && (
          <p className="post-byline">
            {post.date && <time dateTime={post.date}>{post.date}</time>}
            {post.date && post.author && " · "}
            {post.author && <span>by {post.author}</span>}
          </p>
        )}
      </header>

      <div className="prose">
        <ReactMarkdown
          remarkPlugins={[remarkGfm]}
          // rehype-raw MUST come before rehype-highlight so that raw HTML
          // tags (<video>, <audio>, <iframe>) are parsed into the hast tree
          // before the highlighter walks it.
          rehypePlugins={[rehypeRaw, rehypeHighlight]}
          urlTransform={(url: string) => {
            // Pass through absolute URLs, anchors, data URIs, mailto
            if (/^(https?:\/\/|\/\/|#|data:|mailto:)/.test(url)) return url;
            // Rewrite relative paths to the asset API route:
            //   images/photo.png  → /api/asset/images/photo.png
            //   ./images/photo.png → /api/asset/images/photo.png
            return `/api/asset/${url.replace(/^\.\//, "")}`;
          }}
        >
          {post.content}
        </ReactMarkdown>
      </div>
    </article>
  );
}
