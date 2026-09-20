// A fixed Supabase auth cookie/storage-key name shared by the browser and server
// clients. @supabase/ssr otherwise derives the storage key from the Supabase URL
// host, so if the browser reaches Supabase at one host (e.g. 127.0.0.1) and the
// server at another (e.g. host.docker.internal), the cookie names diverge and the
// server never sees the session. Pinning the name keeps them identical regardless
// of how each side reaches Supabase.
export const SUPABASE_COOKIE_NAME = "sb-nlw-auth";
