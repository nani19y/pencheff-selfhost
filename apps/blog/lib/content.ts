import fs from "fs";
import path from "path";
import matter from "gray-matter";
import { unstable_noStore as noStore } from "next/cache";

const CONTENT_DIR =
  process.env.BLOG_CONTENT_DIR ?? path.join(process.cwd(), "blog-content");

export interface PostMeta {
  slug: string;
  title: string;
  date: string;
  description: string;
  author: string;
}

export interface Post extends PostMeta {
  content: string;
}

export function getAllPosts(): PostMeta[] {
  noStore();

  if (!fs.existsSync(CONTENT_DIR)) return [];

  const files = fs.readdirSync(CONTENT_DIR).filter((f) => f.endsWith(".md"));

  const posts: PostMeta[] = files
    .map((filename) => {
      const slug = filename.replace(/\.md$/, "");
      try {
        const raw = fs.readFileSync(path.join(CONTENT_DIR, filename), "utf8");
        const { data } = matter(raw);
        return {
          slug,
          title: (data.title as string) || slug,
          date: data.date ? String(data.date) : "",
          description: (data.description as string) || "",
          author: (data.author as string) || "",
        };
      } catch {
        return null;
      }
    })
    .filter((p): p is PostMeta => p !== null);

  return posts.sort((a, b) => {
    if (!a.date && !b.date) return 0;
    if (!a.date) return 1;
    if (!b.date) return -1;
    return new Date(b.date).getTime() - new Date(a.date).getTime();
  });
}

export function getPost(slug: string): Post | null {
  noStore();

  // Path traversal guard: resolve fully and verify containment.
  // The `+ path.sep` suffix prevents /content-evil from matching /content.
  const resolvedDir = path.resolve(CONTENT_DIR);
  const filePath = path.resolve(resolvedDir, `${slug}.md`);
  if (!filePath.startsWith(resolvedDir + path.sep)) return null;

  if (!fs.existsSync(filePath)) return null;

  try {
    const raw = fs.readFileSync(filePath, "utf8");
    const { data, content } = matter(raw);
    return {
      slug,
      title: (data.title as string) || slug,
      date: data.date ? String(data.date) : "",
      description: (data.description as string) || "",
      author: (data.author as string) || "",
      content,
    };
  } catch {
    return null;
  }
}
