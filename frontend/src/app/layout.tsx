import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "FounderShield AI | Zero-Trust Executive Voice & Wire Fraud Interception",
  description:
    "Palantir-grade cyber defense command center intercepting synthetic executive voice deepfakes, triggering out-of-band biometric challenges, and deploying autonomous AI honeypots to extract scammer mule banking intelligence.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="bg-[#07080b] text-[#f1f5f9] min-h-screen antialiased selection:bg-[#06b6d4]/30 selection:text-white font-sans">
        {children}
      </body>
    </html>
  );
}


