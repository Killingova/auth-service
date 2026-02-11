process.env.NODE_ENV ||= "test";

// JWT strict validation requires one active secret at import time.
process.env.JWT_SECRET_ACTIVE ||= process.env.JWT_SECRET || "test-secret";
process.env.JWT_SECRET ||= process.env.JWT_SECRET_ACTIVE;

// Keep existing runtime env if provided; otherwise set local test defaults.
if (!process.env.DATABASE_URL && !process.env.DATABASE_URL_FILE) {
  process.env.DATABASE_URL = "postgres://test:test@127.0.0.1:5432/test";
}

process.env.REDIS_HOST ||= "127.0.0.1";
process.env.REDIS_PORT ||= "6379";
process.env.REDIS_USERNAME ||= "default";
process.env.REDIS_PASSWORD ||= "test";
process.env.REDIS_NAMESPACE ||= "auth-test";
