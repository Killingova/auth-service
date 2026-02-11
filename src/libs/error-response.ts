import type { FastifyReply } from "fastify";

export type ApiErrorBody = {
  status: number;
  error: {
    code: string;
    message: string;
  };
  details?: unknown;
};

export function apiError(
  status: number,
  code: string,
  message: string,
  details?: unknown,
): ApiErrorBody {
  const base: ApiErrorBody = {
    status,
    error: {
      code,
      message,
    },
  };

  if (details !== undefined) {
    base.details = details;
  }

  return base;
}

export function sendApiError(
  reply: FastifyReply,
  status: number,
  code: string,
  message: string,
  details?: unknown,
) {
  return reply.code(status).send(apiError(status, code, message, details));
}
