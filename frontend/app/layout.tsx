import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import Header from "../components/Header";
import Footer from "../components/Footer";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
  display: "swap",
});

export const metadata: Metadata = {
  title: "SecureScore — Website Security Health Check",
  description:
    "Check your website's security in 60 seconds. SSL, security headers, HTTPS redirect, and cookie security — explained in plain English with copy-paste fixes.",
  keywords: ["website security", "SSL check", "security headers", "small business security"],
  openGraph: {
    title: "SecureScore — Website Security Health Check",
    description: "Check your website's security in 60 seconds. Plain-English findings with copy-paste fixes.",
    type: "website",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={inter.variable}>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
      </head>
      <body className="font-sans antialiased bg-gray-50 text-gray-900 min-h-screen flex flex-col">
        <Header />
        <main className="flex-1">
          {children}
        </main>
        <Footer />
      </body>
    </html>
  );
}
