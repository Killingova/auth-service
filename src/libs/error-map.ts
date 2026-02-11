export type MappedDbError = {
  status: number;
  code: string;
  message: string;
};

type DbLikeError = {
  code?: string;
};

export function mapDbError(err: unknown): MappedDbError {
  const e = err as DbLikeError | undefined;

  switch (e?.code) {
    case "23505":
      return {
        status: 400,
        code: "REGISTER_NOT_POSSIBLE",
        message: "Operation konnte nicht ausgefuehrt werden.",
      };
    case "23503":
    case "23514":
    case "23502":
    case "22P02":
      return {
        status: 400,
        code: "VALIDATION_FAILED",
        message: "Ungueltige Eingabedaten.",
      };
    default:
      return {
        status: 500,
        code: "INTERNAL",
        message: "Internal server error.",
      };
  }
}
