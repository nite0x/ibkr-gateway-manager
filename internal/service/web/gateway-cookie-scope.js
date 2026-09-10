// Keep IBKR SSO cookies on the current Gateway host, including *.localhost.
;(function () {
  // Multiple loads must not stack adapters. Preserve the native accessor's
  // semantics and all cookie attributes except the parent Domain scope.
  if (Object.getOwnPropertyDescriptor(document, "cookie")) return;
  var owner = Object.getPrototypeOf(document);
  var cookie;
  while (owner && !cookie) {
    cookie = Object.getOwnPropertyDescriptor(owner, "cookie");
    owner = Object.getPrototypeOf(owner);
  }
  if (!cookie || !cookie.get || !cookie.set) return;
  Object.defineProperty(document, "cookie", {
    configurable: true,
    enumerable: cookie.enumerable,
    get: function () { return cookie.get.call(document); },
    set: function (value) {
      cookie.set.call(document, String(value).replace(/;\s*domain\s*=[^;]*/gi, ""));
    }
  });
})();
