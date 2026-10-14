import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

vi.mock("@/lib/supabase/server", () => ({ getAccessToken: vi.fn() }));
vi.mock("@/lib/workspace", () => ({ getSelectedWorkspace: vi.fn() }));

import { maxUploadBytes, proxyUpload } from "./proxy";
import { getAccessToken } from "@/lib/supabase/server";
import { getSelectedWorkspace } from "@/lib/workspace";

const PATH =
  "/datasets/11111111-2222-4333-8444-555555555555/versions/66666666-7777-4888-8999-aaaaaaaaaaaa/content";
const BODY = "region,amount\nnorth,1\n";

function upload(
  over: { headers?: Record<string, string>; body?: string | null; path?: string } = {},
) {
  const body = over.body === undefined ? BODY : over.body;
  return new NextRequest(`http://web.test/api/nlw${over.path ?? PATH}`, {
    method: "PUT",
    headers: {
      host: "web.test",
      origin: "http://web.test",
      "content-type": "text/csv",
      "content-length": String(body ? body.length : 0),
      ...over.headers,
    },
    body: body ?? undefined,
    duplex: "half",
  } as ConstructorParameters<typeof NextRequest>[1]);
}

const fetchMock = vi.fn();

beforeEach(() => {
  vi.mocked(getAccessToken).mockResolvedValue("token-xyz");
  vi.mocked(getSelectedWorkspace).mockResolvedValue("ws-1");
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

async function json(res: Response) {
  return (await res.json()) as { error: { code: string } };
}

describe("streamed upload proxy", () => {
  it("forwards the body unbuffered with fresh, minimal headers", async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ id: "v" }), {
        status: 202,
        headers: { "x-request-id": "r-1" },
      }),
    );
    const res = await proxyUpload(
      upload({ headers: { authorization: "Bearer forged", "x-workspace-id": "evil" } }),
      PATH,
    );
    expect(res.status).toBe(202);
    expect(res.headers.get("x-request-id")).toBe("r-1");
    expect(res.headers.get("cache-control")).toBe("no-store");
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toMatch(new RegExp(`${PATH}$`));
    const h = init.headers as Headers;
    expect(init.method).toBe("PUT");
    expect(init.duplex).toBe("half");
    expect(init.body).toBeInstanceOf(ReadableStream); // streamed, never read here
    expect(h.get("authorization")).toBe("Bearer token-xyz");
    expect(h.get("x-workspace-id")).toBe("ws-1");
    expect(h.get("content-type")).toBe("text/csv");
    expect(h.get("content-length")).toBe(String(BODY.length));
  });

  it.each([
    [{ headers: { origin: "http://evil.test" } }, 403, "forbidden"],
    [{ headers: { "content-type": "application/octet-stream" } }, 415, "unsupported_media_type"],
    [{ headers: { "content-length": "abc" } }, 411, "length_required"],
  ])("refuses %o before contacting the API", async (over, status, code) => {
    const res = await proxyUpload(upload(over), PATH);
    expect(res.status).toBe(status);
    expect((await json(res)).error.code).toBe(code);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("refuses an unauthenticated upload", async () => {
    vi.mocked(getAccessToken).mockResolvedValue(null);
    const res = await proxyUpload(upload(), PATH);
    expect(res.status).toBe(401);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("refuses a declared size over the limit without forwarding the body", async () => {
    vi.stubEnv("NLW_DATASET_MAX_UPLOAD_BYTES", "10");
    const res = await proxyUpload(upload(), PATH);
    expect(res.status).toBe(413);
    expect((await json(res)).error.code).toBe("CONTENT_TOO_LARGE");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("only streams the exact content path", async () => {
    const res = await proxyUpload(upload(), "/datasets/x/versions/y/content");
    expect(res.status).toBe(404);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("reports an unreachable API without its error text", async () => {
    fetchMock.mockRejectedValue(new Error("ECONNREFUSED 10.0.0.5:8000 secret-host"));
    const res = await proxyUpload(upload(), PATH);
    expect(res.status).toBe(503);
    expect(await res.text()).not.toMatch(/ECONNREFUSED|secret-host/);
  });
});

describe("maxUploadBytes", () => {
  it("defaults to the API's 25 MB ceiling and never exceeds it", () => {
    expect(maxUploadBytes()).toBe(25_000_000);
    vi.stubEnv("NLW_DATASET_MAX_UPLOAD_BYTES", "65536");
    expect(maxUploadBytes()).toBe(65536);
    vi.stubEnv("NLW_DATASET_MAX_UPLOAD_BYTES", "999999999");
    expect(maxUploadBytes()).toBe(25_000_000);
    vi.stubEnv("NLW_DATASET_MAX_UPLOAD_BYTES", "nope");
    expect(maxUploadBytes()).toBe(25_000_000);
  });
});
