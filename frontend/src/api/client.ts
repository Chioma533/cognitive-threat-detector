const configuredApiBase =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:5000/api/v1";
const API_BASE_URL = import.meta.env.DEV
  ? new URL(configuredApiBase, window.location.origin).pathname.replace(/\/+$/, "")
  : configuredApiBase.replace(/\/+$/, "");

interface ApiErrorEnvelope {
  error: {
    code: string;
    message: string;
  };
}

export class ApiClientError extends Error {
  readonly status: number;
  readonly code: string | null;

  constructor(message: string, status: number, code: string | null = null) {
    super(message);
    this.name = "ApiClientError";
    this.status = status;
    this.code = code;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isApiErrorEnvelope(value: unknown): value is ApiErrorEnvelope {
  return (
    isRecord(value) &&
    isRecord(value.error) &&
    typeof value.error.code === "string" &&
    typeof value.error.message === "string"
  );
}

export async function requestApi(
  path: string,
  init?: RequestInit,
): Promise<Response> {
  try {
    return await fetch(`${API_BASE_URL}${path}`, init);
  } catch {
    throw new ApiClientError(
      "Could not reach the backend. Check the connection and try again.",
      0,
    );
  }
}

export async function checkBackendHealth(): Promise<boolean> {
  const response = await requestApi("/health");
  if (!response.ok) {
    throw new ApiClientError(
      "The backend health check failed.",
      response.status,
    );
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw new ApiClientError("The backend returned an invalid health response.", response.status);
  }
  return isRecord(body) && body.status === "ok";
}

export async function getErrorMessage(response: Response): Promise<ApiClientError> {
  if (response.status >= 500) {
    return new ApiClientError(
      "The backend could not process the request. Try again later.",
      response.status,
    );
  }

  try {
    const body: unknown = await response.json();
    if (isApiErrorEnvelope(body)) {
      return new ApiClientError(
        body.error.message,
        response.status,
        body.error.code,
      );
    }
  } catch {
    // Use the generic response below if the error body is not valid JSON.
  }

  return new ApiClientError(
    "The request was rejected. Check the selected CSV and try again.",
    response.status,
  );
}
