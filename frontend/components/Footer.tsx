export default function Footer() {
  return (
    <footer className="bg-white border-t border-gray-100 mt-auto">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-sm text-gray-400">
            <span className="font-semibold text-gray-600">SecureScore</span>
            <span>·</span>
            <span>Website Security Health Check for Small Businesses</span>
          </div>
          <div className="text-xs text-gray-400 text-center">
            SecureScore checks 4 external security areas.
            It is not a penetration testing tool.
          </div>
        </div>
      </div>
    </footer>
  );
}
