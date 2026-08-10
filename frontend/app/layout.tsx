import type { Metadata } from "next";
import "./globals.css";
import Providers from "./providers";

export const metadata: Metadata = {
  title: "Solarplex",
  description: "Shared operational platform for AI agent orchestration",
  // Served from public/, not the app/ file convention — an app/favicon.ico
  // (or icon.*) file short-circuits this whole `icons` field in this Next
  // version (14.2.5): it silently wins over anything declared here instead
  // of merging with it, so multi-size icons have to live here or not at all.
  icons: {
    icon: [
      { url: "/favicon.ico", sizes: "any" },
      { url: "/favicon-32x32.png", sizes: "32x32", type: "image/png" },
      { url: "/android-chrome-192x192.png", sizes: "192x192", type: "image/png" },
    ],
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="h-full">
      <body className="h-full">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
