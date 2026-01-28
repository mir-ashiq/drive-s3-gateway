# Drive S3 Gateway

Cloudflare Worker that exposes an S3-compatible API backed by Google Drive. Each S3 bucket maps to a Drive folder, and object keys map to Drive files within nested folders.

## Features

- **S3-like operations**: PUT, GET, DELETE, and LIST for objects.
- **Bucket management**: PUT `/bucket` creates a Drive folder.
- **OAuth2 token refresh** for Google Drive API.
- **AWS Signature V4** verification for incoming requests.
- **Presigned URLs** for GET requests.
- **Multipart uploads** with S3-style initiate/upload/complete using KV-backed staging.
- **Metadata** surfaced via `Content-Type` and `Content-Length` headers.

## Prerequisites

- Google Drive API enabled in your Google Cloud project.
- OAuth client ID/secret and refresh token (generate with `rclone`).
- Cloudflare Workers and KV namespaces.

## Configuration

Create KV namespaces:

- `AUTH_KV` (bucket name -> Drive folder ID)
- `FOLDER_CACHE` (bucket/key -> Drive file ID, folder path cache)
- `MULTIPART_UPLOADS` (multipart session cache)

Add secrets with `wrangler secret put`:

- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `GOOGLE_REFRESH_TOKEN`
- `ACCESS_KEY`
- `SECRET_KEY`
- `REGION` (optional; defaults to `auto`)
- `ALLOWED_BUCKETS` (comma-separated list)

## Running locally

```bash
npm install
npm run dev
```

## S3-compatible API

### Create bucket

```bash
curl -X PUT \
  -H "Authorization: <AWS4>" \
  -H "x-amz-date: <DATE>" \
  https://<worker-domain>/my-bucket
```

### Upload object

```bash
curl -X PUT \
  -H "Authorization: <AWS4>" \
  -H "x-amz-date: <DATE>" \
  -H "Content-Type: image/jpeg" \
  --data-binary @avatar.jpg \
  https://<worker-domain>/user-files/user123/avatar.jpg
```

### Download object

```bash
curl -X GET \
  -H "Authorization: <AWS4>" \
  -H "x-amz-date: <DATE>" \
  https://<worker-domain>/user-files/user123/avatar.jpg
```

### Delete object

```bash
curl -X DELETE \
  -H "Authorization: <AWS4>" \
  -H "x-amz-date: <DATE>" \
  https://<worker-domain>/user-files/user123/avatar.jpg
```

### List objects

```bash
curl -X GET \
  -H "Authorization: <AWS4>" \
  -H "x-amz-date: <DATE>" \
  https://<worker-domain>/user-files
```

### Presigned URLs

```bash
curl -X GET \
  -H "Authorization: <AWS4>" \
  -H "x-amz-date: <DATE>" \
  "https://<worker-domain>/user-files/user123/avatar.jpg?presign=1&expires=900"
```

### Multipart upload (S3-style)

1. Initiate multipart upload:

```bash
curl -X POST \
  -H "Authorization: <AWS4>" \
  -H "x-amz-date: <DATE>" \
  "https://<worker-domain>/user-files/big.bin?uploads"
```

2. Upload parts:

```bash
curl -X PUT \
  -H "Authorization: <AWS4>" \
  -H "x-amz-date: <DATE>" \
  --data-binary @part1.bin \
  "https://<worker-domain>/user-files/big.bin?uploadId=<UPLOAD_ID>&partNumber=1"
```

3. Complete upload:

```bash
curl -X POST \
  -H "Authorization: <AWS4>" \
  -H "x-amz-date: <DATE>" \
  "https://<worker-domain>/user-files/big.bin?uploadId=<UPLOAD_ID>"
```

> **Note:** Multipart uploads are buffered in KV and then uploaded to Google Drive when completed. For very large files, consider replacing this with a resumable upload flow to avoid KV size limits.

## Error handling

- `403` for signature or bucket allowlist failures.
- `404` for missing objects.
- `500` for Drive API failures.

## Deploy

```bash
npm run deploy
```
