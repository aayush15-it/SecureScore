import ScanForm from '@/components/ScanForm';

export default function HomePage() {
  return (
    <div className="flex flex-col items-center justify-center min-h-[calc(100vh-8rem)]">

      {/* Hero Section */}
      <section className="w-full max-w-4xl mx-auto px-4 sm:px-6 py-16 text-center">

        {/* Badge */}
        <div className="inline-flex items-center gap-2 bg-red-50 border border-red-200 rounded-full px-4 py-1.5 mb-6">
          <span className="w-2 h-2 bg-crimson rounded-full animate-pulse-slow" />
          <span className="text-sm font-medium text-crimson">Free Security Check</span>
        </div>

        {/* Heading */}
        <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold text-gray-900 mb-5 tracking-tight">
          Is your website <br />
          <span className="text-crimson">secure</span>?
        </h1>

        <p className="text-lg sm:text-xl text-gray-500 mb-10 max-w-2xl mx-auto text-balance">
          Enter your website URL for an instant security check.
          Get plain-English findings and copy-paste fixes — in under 60 seconds.
        </p>

        {/* Scan Form */}
        <ScanForm />

        {/* What we check */}
        <div className="mt-14 grid grid-cols-2 sm:grid-cols-4 gap-4">
          {[
            { icon: '🔒', label: 'SSL/TLS', desc: 'Certificate & encryption' },
            { icon: '🛡️', label: 'Security Headers', desc: '5 critical headers' },
            { icon: '↗️', label: 'HTTPS Redirect', desc: 'HTTP → HTTPS' },
            { icon: '🍪', label: 'Cookie Security', desc: 'Secure, HttpOnly, SameSite' },
          ].map((item) => (
            <div key={item.label} className="bg-white border border-gray-100 rounded-xl p-4 shadow-card text-left hover:shadow-card-hover transition-shadow">
              <div className="text-2xl mb-2">{item.icon}</div>
              <div className="font-semibold text-gray-900 text-sm mb-0.5">{item.label}</div>
              <div className="text-xs text-gray-400">{item.desc}</div>
            </div>
          ))}
        </div>

        {/* Honest disclaimer */}
        <p className="mt-8 text-xs text-gray-400 max-w-lg mx-auto">
          SecureScore checks 4 externally observable security areas.
          It is not a penetration testing tool and does not claim to find all vulnerabilities.
        </p>
      </section>
    </div>
  );
}
