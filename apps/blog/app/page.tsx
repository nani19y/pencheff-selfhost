import Link from "next/link";
import { getAllPosts } from "@/lib/content";

export const dynamic = "force-dynamic";
export const revalidate = 0;

export default function BlogIndexPage() {
  const posts = getAllPosts();

  if (posts.length === 0) {
    return (
      <div className="no-posts">
        <p>No posts yet.</p>
        <p>
          Drop a <code>.md</code> file into <code>blog-content/</code> and it
          appears here immediately — no restart needed.
        </p>
      </div>
    );
  }

  return (
    <>
      <h1 className="index-heading">Latest posts</h1>
      <ul className="post-list">
        {posts.map((post) => (
          <li key={post.slug} className="post-card">
            <Link href={`/${post.slug}`}>
              <h2 className="post-title">{post.title}</h2>
              {(post.date || post.author) && (
                <p className="post-meta">
                  {post.date && (
                    <time dateTime={post.date}>{post.date}</time>
                  )}
                  {post.date && post.author && " · "}
                  {post.author && <span>{post.author}</span>}
                </p>
              )}
              {post.description && (
                <p className="post-description">{post.description}</p>
              )}
            </Link>
          </li>
        ))}
      </ul>
    </>
  );
}
