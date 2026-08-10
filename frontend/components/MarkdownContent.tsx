"use client";

import ReactMarkdown from "react-markdown";
import type { Components } from "react-markdown";
import remarkGfm from "remark-gfm";
import rehypeHighlight from "rehype-highlight";
import "highlight.js/styles/github-dark.css";

const mdComponents: Components = {
  p: ({ children }) => (
    <p className="text-xs text-primary leading-relaxed mb-1.5 last:mb-0">{children}</p>
  ),
  strong: ({ children }) => (
    <strong className="font-semibold text-primary">{children}</strong>
  ),
  em: ({ children }) => (
    <em className="italic text-subtle">{children}</em>
  ),
  code: ({ className, children }) => {
    const isBlock = /language-/.test(className ?? "");
    if (isBlock) {
      return <code className={className}>{children}</code>;
    }
    return (
      <code className="text-2xs font-mono text-accent-blue bg-surface-2 px-1 py-0.5 rounded">
        {children}
      </code>
    );
  },
  pre: ({ children }) => (
    <pre className="text-2xs font-mono bg-surface-2 border border-border rounded-lg p-3 overflow-x-auto my-2 leading-relaxed">
      {children}
    </pre>
  ),
  ul: ({ children }) => (
    <ul className="list-disc list-outside pl-4 space-y-0.5 my-1.5">{children}</ul>
  ),
  ol: ({ children }) => (
    <ol className="list-decimal list-outside pl-4 space-y-0.5 my-1.5">{children}</ol>
  ),
  li: ({ children }) => (
    <li className="text-xs text-subtle leading-relaxed">{children}</li>
  ),
  // Shifted down one level from what the `#`/`##`/`###` markdown syntax
  // would normally produce (h1→h2, h2→h3, h3→h4, ...): this content is
  // chat/artifact/context text, always rendered nested inside a page that
  // already has its own real `<h1>` — a raw `<h1>` from arbitrary user- or
  // agent-authored markdown would collide with it (two h1s on one page) or
  // read as a level skip depending on which markdown level shows up first.
  // Visual sizing is kept exactly as before; only the semantic tag + rank
  // moves, so this is invisible in the rendered page, only in the a11y tree.
  h1: ({ children }) => (
    <h2 className="text-sm font-semibold text-primary mt-2 mb-1 first:mt-0">{children}</h2>
  ),
  h2: ({ children }) => (
    <h3 className="text-xs font-semibold text-primary mt-2 mb-0.5 first:mt-0">{children}</h3>
  ),
  h3: ({ children }) => (
    <h4 className="text-xs font-medium text-subtle mt-1.5 mb-0.5 first:mt-0">{children}</h4>
  ),
  h4: ({ children }) => (
    <h5 className="text-xs font-medium text-subtle mt-1.5 mb-0.5 first:mt-0">{children}</h5>
  ),
  h5: ({ children }) => (
    <h6 className="text-xs font-medium text-subtle mt-1.5 mb-0.5 first:mt-0">{children}</h6>
  ),
  // h6 has nowhere lower to shift to (HTML tops out at h6) — rendered as-is.
  blockquote: ({ children }) => (
    <blockquote className="border-l-2 border-border pl-3 text-xs text-muted italic my-1.5">
      {children}
    </blockquote>
  ),
  hr: () => <hr className="border-border my-2" />,
  a: ({ href, children }) => (
    <a href={href} className="text-accent-blue hover:underline" target="_blank" rel="noreferrer">
      {children}
    </a>
  ),
  table: ({ children }) => (
    <div className="overflow-x-auto my-2">
      <table className="text-2xs w-full border-collapse">{children}</table>
    </div>
  ),
  th: ({ children }) => (
    <th className="text-left font-medium text-subtle border-b border-border px-2 py-1 bg-surface-2">
      {children}
    </th>
  ),
  td: ({ children }) => (
    <td className="text-primary border-b border-border/40 px-2 py-1">{children}</td>
  ),
};

export default function MarkdownContent({ content }: { content: string }) {
  return (
    <ReactMarkdown
      remarkPlugins={[remarkGfm]}
      rehypePlugins={[rehypeHighlight]}
      components={mdComponents}
    >
      {content}
    </ReactMarkdown>
  );
}
