export function safeAuthenticationReturnPath(value?: string) {
  return value && /^\/r\/[A-Za-z0-9_-]{43}$/.test(value) ? value : "/workspace";
}
