export interface Env {
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  GOOGLE_REFRESH_TOKEN: string;
  ACCESS_KEY: string;
  SECRET_KEY: string;
  REGION: string;
  ALLOWED_BUCKETS?: string;
  AUTH_KV: KVNamespace;
  FOLDER_CACHE: KVNamespace;
  MULTIPART_UPLOADS: KVNamespace;
}

type SignedRequest = {
  accessKeyId: string;
  signedHeaders: string[];
  signature: string;
  amzDate: string;
  scope: string;
};

const DRIVE_API = "https://www.googleapis.com/drive/v3";
const DRIVE_UPLOAD_API = "https://www.googleapis.com/upload/drive/v3";

const textEncoder = new TextEncoder();

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      const url = new URL(request.url);
      const path = url.pathname.replace(/^\/+/, "");
      if (!path) {
        return jsonResponse({ message: "Drive S3 Gateway" }, 200);
      }

      const [bucket, ...keyParts] = path.split("/");
      const key = keyParts.join("/");

      if (!bucket) {
        return errorResponse("Bucket required", 400);
      }

      if (!isBucketAllowed(bucket, env.ALLOWED_BUCKETS)) {
        return errorResponse("Bucket not allowed", 403);
      }

      const signatureCheck = await verifySignatureV4(request, env);
      if (!signatureCheck.ok) {
        return errorResponse(signatureCheck.message, signatureCheck.status);
      }

      if (request.method === "PUT" && !key) {
        const folderId = await ensureBucketFolder(bucket, env);
        return jsonResponse({ bucket, folderId }, 200);
      }

      if (request.method === "POST" && url.searchParams.has("uploads")) {
        if (!key) {
          return errorResponse("Object key required", 400);
        }
        const uploadId = await initiateMultipartUpload(bucket, key, env);
        return xmlResponse(
          `<InitiateMultipartUploadResult><Bucket>${bucket}</Bucket><Key>${key}</Key><UploadId>${uploadId}</UploadId></InitiateMultipartUploadResult>`,
          200,
        );
      }

      if (request.method === "PUT" && url.searchParams.has("uploadId")) {
        const uploadId = url.searchParams.get("uploadId");
        const partNumber = url.searchParams.get("partNumber");
        if (!uploadId || !partNumber || !key) {
          return errorResponse("uploadId, partNumber, and key are required", 400);
        }
        const etag = await uploadMultipartPart(uploadId, Number(partNumber), request, env);
        return new Response(null, {
          status: 200,
          headers: {
            ETag: etag,
          },
        });
      }

      if (request.method === "POST" && url.searchParams.has("uploadId")) {
        const uploadId = url.searchParams.get("uploadId");
        if (!uploadId || !key) {
          return errorResponse("uploadId and key required", 400);
        }
        const complete = await completeMultipartUpload(bucket, key, uploadId, env);
        return xmlResponse(
          `<CompleteMultipartUploadResult><Location>${complete.location}</Location><Bucket>${bucket}</Bucket><Key>${key}</Key><ETag>${complete.etag}</ETag></CompleteMultipartUploadResult>`,
          200,
        );
      }

      switch (request.method) {
        case "PUT":
          if (!key) {
            return errorResponse("Object key required", 400);
          }
          return await putObject(bucket, key, request, env);
        case "GET":
          if (!key) {
            return await listObjects(bucket, env);
          }
          if (url.searchParams.get("presign") === "1") {
            return await presignUrl(bucket, key, request, env);
          }
          return await getObject(bucket, key, env);
        case "DELETE":
          if (!key) {
            return errorResponse("Object key required", 400);
          }
          return await deleteObject(bucket, key, env);
        default:
          return errorResponse("Method not allowed", 405);
      }
    } catch (error) {
      return errorResponse(error instanceof Error ? error.message : "Internal error", 500);
    }
  },
};

function isBucketAllowed(bucket: string, allowList?: string) {
  if (!allowList) {
    return true;
  }
  const allowed = allowList.split(",").map((value) => value.trim());
  return allowed.includes(bucket);
}

async function getAccessToken(env: Env): Promise<string> {
  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      refresh_token: env.GOOGLE_REFRESH_TOKEN,
      grant_type: "refresh_token",
    }),
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Failed to refresh token: ${body}`);
  }

  const data = (await response.json()) as { access_token: string };
  return data.access_token;
}

async function driveRequest(env: Env, input: RequestInfo, init?: RequestInit) {
  const token = await getAccessToken(env);
  const headers = new Headers(init?.headers);
  headers.set("Authorization", `Bearer ${token}`);
  return fetch(input, { ...init, headers });
}

async function ensureBucketFolder(bucket: string, env: Env): Promise<string> {
  const cached = await env.AUTH_KV.get(bucket);
  if (cached) {
    return cached;
  }

  const response = await driveRequest(env, `${DRIVE_API}/files`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      name: bucket,
      mimeType: "application/vnd.google-apps.folder",
    }),
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Failed to create bucket folder: ${body}`);
  }

  const data = (await response.json()) as { id: string };
  await env.AUTH_KV.put(bucket, data.id);
  return data.id;
}

async function ensureFolderPath(
  bucketId: string,
  pathSegments: string[],
  env: Env,
): Promise<string> {
  let parentId = bucketId;
  for (const segment of pathSegments) {
    if (!segment) continue;
    const cacheKey = `folder:${parentId}:${segment}`;
    const cached = await env.FOLDER_CACHE.get(cacheKey);
    if (cached) {
      parentId = cached;
      continue;
    }

    const response = await driveRequest(env, `${DRIVE_API}/files?q=${encodeURIComponent(
      `'${parentId}' in parents and name='${segment.replace(/'/g, "\\'")}' and mimeType='application/vnd.google-apps.folder' and trashed=false`,
    )}&fields=files(id,name)`, {
      method: "GET",
    });
    if (!response.ok) {
      const body = await response.text();
      throw new Error(`Failed to query folder: ${body}`);
    }
    const data = (await response.json()) as { files: { id: string }[] };
    if (data.files.length > 0) {
      parentId = data.files[0].id;
      await env.FOLDER_CACHE.put(cacheKey, parentId);
      continue;
    }

    const createResponse = await driveRequest(env, `${DRIVE_API}/files`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        name: segment,
        mimeType: "application/vnd.google-apps.folder",
        parents: [parentId],
      }),
    });

    if (!createResponse.ok) {
      const body = await createResponse.text();
      throw new Error(`Failed to create folder: ${body}`);
    }
    const created = (await createResponse.json()) as { id: string };
    parentId = created.id;
    await env.FOLDER_CACHE.put(cacheKey, parentId);
  }
  return parentId;
}

async function putObject(bucket: string, key: string, request: Request, env: Env) {
  const bucketId = await ensureBucketFolder(bucket, env);
  const parts = key.split("/");
  const fileName = parts.pop() ?? key;
  const folderId = await ensureFolderPath(bucketId, parts, env);

  const metadata = {
    name: fileName,
    parents: [folderId],
  };

  const contentType = request.headers.get("Content-Type") ?? "application/octet-stream";
  const body = await request.arrayBuffer();

  const boundary = "drive-s3-boundary";
  const multipartBody = buildMultipartBody(boundary, metadata, contentType, body);

  const response = await driveRequest(env, `${DRIVE_UPLOAD_API}/files?uploadType=multipart`, {
    method: "POST",
    headers: {
      "Content-Type": `multipart/related; boundary=${boundary}`,
    },
    body: multipartBody,
  });

  if (!response.ok) {
    const payload = await response.text();
    return errorResponse(`Upload failed: ${payload}`, 500);
  }

  const data = (await response.json()) as { id: string; name: string };
  await env.FOLDER_CACHE.put(`${bucket}/${key}`, data.id);
  return jsonResponse({ bucket, key, fileId: data.id }, 200);
}

async function getObject(bucket: string, key: string, env: Env) {
  const fileId = await resolveFileId(bucket, key, env);
  if (!fileId) {
    return errorResponse("Object not found", 404);
  }

  const metaResponse = await driveRequest(env, `${DRIVE_API}/files/${fileId}?fields=name,size,mimeType`, {
    method: "GET",
  });
  if (!metaResponse.ok) {
    return errorResponse("Failed to fetch metadata", 500);
  }
  const metadata = (await metaResponse.json()) as {
    name: string;
    size?: string;
    mimeType?: string;
  };

  const response = await driveRequest(env, `${DRIVE_API}/files/${fileId}?alt=media`, {
    method: "GET",
  });

  if (!response.ok) {
    return errorResponse("Failed to download file", 500);
  }

  const headers = new Headers();
  headers.set("Content-Type", metadata.mimeType ?? "application/octet-stream");
  if (metadata.size) {
    headers.set("Content-Length", metadata.size);
  }

  return new Response(response.body, {
    status: 200,
    headers,
  });
}

async function deleteObject(bucket: string, key: string, env: Env) {
  const fileId = await resolveFileId(bucket, key, env);
  if (!fileId) {
    return errorResponse("Object not found", 404);
  }

  const response = await driveRequest(env, `${DRIVE_API}/files/${fileId}`, {
    method: "DELETE",
  });

  if (!response.ok) {
    return errorResponse("Failed to delete file", 500);
  }

  await env.FOLDER_CACHE.delete(`${bucket}/${key}`);
  return new Response(null, { status: 204 });
}

async function listObjects(bucket: string, env: Env) {
  const bucketId = await ensureBucketFolder(bucket, env);
  const response = await driveRequest(
    env,
    `${DRIVE_API}/files?q=${encodeURIComponent(`'${bucketId}' in parents and trashed=false`)}&fields=files(id,name,size,mimeType)`,
    { method: "GET" },
  );

  if (!response.ok) {
    return errorResponse("Failed to list objects", 500);
  }

  const data = (await response.json()) as {
    files: { id: string; name: string; size?: string; mimeType?: string }[];
  };

  return jsonResponse(
    {
      bucket,
      objects: data.files.map((file) => ({
        key: file.name,
        size: file.size,
        contentType: file.mimeType,
        fileId: file.id,
      })),
    },
    200,
  );
}

async function resolveFileId(bucket: string, key: string, env: Env) {
  const cached = await env.FOLDER_CACHE.get(`${bucket}/${key}`);
  if (cached) {
    return cached;
  }

  const bucketId = await ensureBucketFolder(bucket, env);
  const parts = key.split("/");
  const fileName = parts.pop() ?? key;
  const folderId = await ensureFolderPath(bucketId, parts, env);

  const response = await driveRequest(env, `${DRIVE_API}/files?q=${encodeURIComponent(
    `'${folderId}' in parents and name='${fileName.replace(/'/g, "\\'")}' and trashed=false`,
  )}&fields=files(id,name)`, {
    method: "GET",
  });

  if (!response.ok) {
    return null;
  }
  const data = (await response.json()) as { files: { id: string }[] };
  if (data.files.length === 0) {
    return null;
  }

  const fileId = data.files[0].id;
  await env.FOLDER_CACHE.put(`${bucket}/${key}`, fileId);
  return fileId;
}

async function presignUrl(bucket: string, key: string, request: Request, env: Env) {
  const expiresIn = Number(new URL(request.url).searchParams.get("expires")) || 900;
  const url = new URL(request.url);
  url.searchParams.delete("presign");
  url.searchParams.set("X-Amz-Algorithm", "AWS4-HMAC-SHA256");
  url.searchParams.set("X-Amz-Credential", `${env.ACCESS_KEY}/${scopeDate()}/${env.REGION}/s3/aws4_request`);
  url.searchParams.set("X-Amz-Date", amzDate());
  url.searchParams.set("X-Amz-Expires", expiresIn.toString());
  url.searchParams.set("X-Amz-SignedHeaders", "host");

  const canonicalRequest = [
    request.method,
    canonicalUri(url.pathname),
    canonicalQuery(url.searchParams),
    `host:${url.host}\n`,
    "host",
    "UNSIGNED-PAYLOAD",
  ].join("\n");
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    url.searchParams.get("X-Amz-Date"),
    `${scopeDate()}/${env.REGION}/s3/aws4_request`,
    await hashHex(canonicalRequest),
  ].join("\n");

  const signingKey = await getSigningKey(env.SECRET_KEY, scopeDate(), env.REGION, "s3");
  const signature = await hmacHex(signingKey, stringToSign);
  url.searchParams.set("X-Amz-Signature", signature);

  return jsonResponse({ url: url.toString() }, 200);
}

async function initiateMultipartUpload(bucket: string, key: string, env: Env) {
  const uploadId = crypto.randomUUID();
  const bucketId = await ensureBucketFolder(bucket, env);
  const parts = key.split("/");
  const fileName = parts.pop() ?? key;
  const folderId = await ensureFolderPath(bucketId, parts, env);
  const data = {
    bucket,
    key,
    fileName,
    folderId,
    parts: [] as { etag: string; data: string }[],
  };
  await env.MULTIPART_UPLOADS.put(uploadId, JSON.stringify(data));
  return uploadId;
}

async function uploadMultipartPart(uploadId: string, partNumber: number, request: Request, env: Env) {
  const uploadDataRaw = await env.MULTIPART_UPLOADS.get(uploadId);
  if (!uploadDataRaw) {
    throw new Error("Multipart upload not found");
  }
  const uploadData = JSON.parse(uploadDataRaw) as {
    parts: { etag: string; data: string; partNumber: number }[];
  };
  const body = new Uint8Array(await request.arrayBuffer());
  const etag = await hashHex(body);
  uploadData.parts = uploadData.parts.filter((part) => part.partNumber !== partNumber);
  uploadData.parts.push({ etag, data: arrayBufferToBase64(body), partNumber });
  await env.MULTIPART_UPLOADS.put(uploadId, JSON.stringify(uploadData));
  return etag;
}

async function completeMultipartUpload(bucket: string, key: string, uploadId: string, env: Env) {
  const uploadDataRaw = await env.MULTIPART_UPLOADS.get(uploadId);
  if (!uploadDataRaw) {
    throw new Error("Multipart upload not found");
  }
  const uploadData = JSON.parse(uploadDataRaw) as {
    fileName: string;
    folderId: string;
    parts: { etag: string; data: string; partNumber: number }[];
  };
  const sorted = uploadData.parts.sort((a, b) => a.partNumber - b.partNumber);
  const chunks = sorted.map((part) => base64ToArrayBuffer(part.data));
  const totalLength = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
  const combined = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(new Uint8Array(chunk), offset);
    offset += chunk.byteLength;
  }

  const boundary = "drive-s3-boundary";
  const metadata = { name: uploadData.fileName, parents: [uploadData.folderId] };
  const multipartBody = buildMultipartBody(boundary, metadata, "application/octet-stream", combined.buffer);
  const response = await driveRequest(env, `${DRIVE_UPLOAD_API}/files?uploadType=multipart`, {
    method: "POST",
    headers: {
      "Content-Type": `multipart/related; boundary=${boundary}`,
    },
    body: multipartBody,
  });
  if (!response.ok) {
    const payload = await response.text();
    throw new Error(`Failed to complete upload: ${payload}`);
  }
  const data = (await response.json()) as { id: string };
  await env.FOLDER_CACHE.put(`${bucket}/${key}`, data.id);
  await env.MULTIPART_UPLOADS.delete(uploadId);
  return {
    location: `/${bucket}/${key}`,
    etag: data.id,
  };
}

async function verifySignatureV4(request: Request, env: Env) {
  const authHeader = request.headers.get("Authorization");
  if (!authHeader) {
    return verifyPresignedSignatureV4(request, env);
  }

  const signedRequest = parseAuthorization(authHeader);
  if (!signedRequest) {
    return { ok: false, status: 403, message: "Invalid Authorization header" };
  }

  if (signedRequest.accessKeyId !== env.ACCESS_KEY) {
    return { ok: false, status: 403, message: "Invalid access key" };
  }

  const url = new URL(request.url);
  const signedHeaders = signedRequest.signedHeaders;
  const canonicalHeaders = signedHeaders
    .map((header) => {
      const value = request.headers.get(header) ?? "";
      return `${header}:${value.trim()}`;
    })
    .join("\n");
  const payloadHash = request.headers.get("x-amz-content-sha256") ?? "UNSIGNED-PAYLOAD";

  const canonicalRequest = [
    request.method,
    canonicalUri(url.pathname),
    canonicalQuery(url.searchParams),
    `${canonicalHeaders}\n`,
    signedHeaders.join(";"),
    payloadHash,
  ].join("\n");

  const date = request.headers.get("x-amz-date");
  if (!date) {
    return { ok: false, status: 403, message: "Missing x-amz-date" };
  }

  const stringToSign = [
    "AWS4-HMAC-SHA256",
    date,
    signedRequest.scope,
    await hashHex(canonicalRequest),
  ].join("\n");

  const scopeParts = signedRequest.scope.split("/");
  if (scopeParts.length < 4) {
    return { ok: false, status: 403, message: "Invalid credential scope" };
  }
  const [datePart, region, service] = scopeParts;
  const signingKey = await getSigningKey(env.SECRET_KEY, datePart, region, service);
  const expectedSignature = await hmacHex(signingKey, stringToSign);

  if (expectedSignature !== signedRequest.signature) {
    return { ok: false, status: 403, message: "Signature mismatch" };
  }

  return { ok: true } as const;
}

async function verifyPresignedSignatureV4(request: Request, env: Env) {
  const url = new URL(request.url);
  const algorithm = url.searchParams.get("X-Amz-Algorithm");
  const credential = url.searchParams.get("X-Amz-Credential");
  const amzDate = url.searchParams.get("X-Amz-Date");
  const signedHeaders = url.searchParams.get("X-Amz-SignedHeaders");
  const signature = url.searchParams.get("X-Amz-Signature");
  if (!algorithm || !credential || !amzDate || !signedHeaders || !signature) {
    return { ok: false, status: 403, message: "Missing Authorization header" };
  }
  if (algorithm !== "AWS4-HMAC-SHA256") {
    return { ok: false, status: 403, message: "Invalid presign algorithm" };
  }

  const credentialParts = credential.split("/");
  if (credentialParts[0] !== env.ACCESS_KEY) {
    return { ok: false, status: 403, message: "Invalid access key" };
  }
  const scope = credentialParts.slice(1).join("/");
  const scopeParts = scope.split("/");
  if (scopeParts.length < 4) {
    return { ok: false, status: 403, message: "Invalid credential scope" };
  }

  const canonicalHeaders = signedHeaders
    .split(";")
    .map((header) => `${header}:${request.headers.get(header) ?? ""}`.trim())
    .join("\n");
  const canonicalRequest = [
    request.method,
    canonicalUri(url.pathname),
    canonicalQuery(url.searchParams),
    `${canonicalHeaders}\n`,
    signedHeaders,
    "UNSIGNED-PAYLOAD",
  ].join("\n");
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    scope,
    await hashHex(canonicalRequest),
  ].join("\n");
  const [datePart, region, service] = scopeParts;
  const signingKey = await getSigningKey(env.SECRET_KEY, datePart, region, service);
  const expectedSignature = await hmacHex(signingKey, stringToSign);
  if (expectedSignature !== signature) {
    return { ok: false, status: 403, message: "Signature mismatch" };
  }

  return { ok: true } as const;
}

function parseAuthorization(header: string): SignedRequest | null {
  if (!header.startsWith("AWS4-HMAC-SHA256")) {
    return null;
  }
  const parts = header.replace("AWS4-HMAC-SHA256", "").trim().split(/,\s*/);
  const credential = parts.find((part) => part.startsWith("Credential="));
  const signedHeaders = parts.find((part) => part.startsWith("SignedHeaders="));
  const signature = parts.find((part) => part.startsWith("Signature="));
  if (!credential || !signedHeaders || !signature) {
    return null;
  }
  const credentialValue = credential.split("=")[1];
  const credentialParts = credentialValue.split("/");
  const accessKeyId = credentialParts[0];
  const scope = credentialParts.slice(1).join("/");
  return {
    accessKeyId,
    signedHeaders: signedHeaders.split("=")[1].split(";"),
    signature: signature.split("=")[1],
    amzDate: "",
    scope,
  };
}

function canonicalUri(pathname: string) {
  return pathname
    .split("/")
    .map((segment) => encodeURIComponent(segment))
    .join("/") || "/";
}

function canonicalQuery(params: URLSearchParams) {
  const pairs: string[] = [];
  params.forEach((value, key) => {
    pairs.push(`${encodeURIComponent(key)}=${encodeURIComponent(value)}`);
  });
  return pairs.sort().join("&");
}

function scopeDate() {
  return new Date().toISOString().slice(0, 10).replace(/-/g, "");
}

function amzDate() {
  return new Date().toISOString().replace(/[:-]|\./g, "").slice(0, 15) + "Z";
}

async function hashHex(data: ArrayBuffer | Uint8Array | string) {
  const buffer = typeof data === "string" ? textEncoder.encode(data) : data;
  const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
  return bufferToHex(hashBuffer);
}

async function hmacHex(key: ArrayBuffer | Uint8Array | string, data: string) {
  const keyData = typeof key === "string" ? textEncoder.encode(key) : key;
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, textEncoder.encode(data));
  return bufferToHex(signature);
}

async function getSigningKey(secret: string, date: string, region: string, service: string) {
  const kDate = await hmacRaw(`AWS4${secret}`, date);
  const kRegion = await hmacRaw(kDate, region);
  const kService = await hmacRaw(kRegion, service);
  return hmacRaw(kService, "aws4_request");
}

async function hmacRaw(key: ArrayBuffer | Uint8Array | string, data: string) {
  const keyData = typeof key === "string" ? textEncoder.encode(key) : key;
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return crypto.subtle.sign("HMAC", cryptoKey, textEncoder.encode(data));
}

function bufferToHex(buffer: ArrayBuffer) {
  return Array.from(new Uint8Array(buffer))
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");
}

function buildMultipartBody(
  boundary: string,
  metadata: Record<string, unknown>,
  contentType: string,
  body: ArrayBuffer,
) {
  const metaPart = `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify(metadata)}\r\n`;
  const dataHeader = `--${boundary}\r\nContent-Type: ${contentType}\r\n\r\n`;
  const footer = `\r\n--${boundary}--`;
  const metaBuffer = textEncoder.encode(metaPart);
  const headerBuffer = textEncoder.encode(dataHeader);
  const footerBuffer = textEncoder.encode(footer);
  const bodyBuffer = new Uint8Array(body);
  const combined = new Uint8Array(metaBuffer.length + headerBuffer.length + bodyBuffer.length + footerBuffer.length);
  combined.set(metaBuffer, 0);
  combined.set(headerBuffer, metaBuffer.length);
  combined.set(bodyBuffer, metaBuffer.length + headerBuffer.length);
  combined.set(footerBuffer, metaBuffer.length + headerBuffer.length + bodyBuffer.length);
  return combined;
}

function jsonResponse(data: unknown, status: number) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json",
    },
  });
}

function xmlResponse(body: string, status: number) {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "application/xml",
    },
  });
}

function errorResponse(message: string, status: number) {
  return jsonResponse({ error: message }, status);
}

function arrayBufferToBase64(buffer: Uint8Array) {
  let binary = "";
  for (const byte of buffer) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64: string) {
  const binary = atob(base64);
  const buffer = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    buffer[i] = binary.charCodeAt(i);
  }
  return buffer.buffer;
}
