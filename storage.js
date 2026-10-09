import { randomUUID } from 'node:crypto';
import { DeleteObjectCommand, GetObjectCommand, PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';

// Where uploaded images live: student and staff photos, school logos.
//
// With AWS_S3_BUCKET set, an image is uploaded to that (private) bucket
// and the database column holds only a reference, "s3://<key>". Nothing
// in the bucket is public: every API response swaps the reference for a
// link that works for one hour (signImageUrls, applied to all JSON
// responses in index.js).
//
// Without AWS_S3_BUCKET (local development, tests) the image stays in
// the database column as a data URL, exactly as before. Rows saved that
// way keep working after S3 is switched on.
//
// Settings: AWS_S3_BUCKET, AWS_REGION, and the standard AWS credentials
// (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY). AWS_S3_ENDPOINT is only
// for S3-compatible stores (Cloudflare R2, MinIO) and tests.

const REF_PREFIX = 's3://';
const LINK_SECONDS = 60 * 60;
// A link is reused for half its life, so an image keeps the same address
// (and stays in the browser's and the app's cache) between requests.
const LINK_REUSE_MS = (LINK_SECONDS / 2) * 1000;
const MAX_CACHED_LINKS = 5000;

export const MAX_PHOTO_DATA_URL_LENGTH = 4_000_000; // ~3MB of image, base64-inflated
export const MAX_LOGO_DATA_URL_LENGTH = 1_400_000; // ~1MB of image

const IMAGE_TYPES = {
  png: { mime: 'image/png', ext: 'png', matches: b => b.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) },
  jpeg: { mime: 'image/jpeg', ext: 'jpg', matches: b => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff },
  webp: { mime: 'image/webp', ext: 'webp', matches: b => b.subarray(0, 4).toString('latin1') === 'RIFF' && b.subarray(8, 12).toString('latin1') === 'WEBP' },
  gif: { mime: 'image/gif', ext: 'gif', matches: b => /^GIF8[79]a$/.test(b.subarray(0, 6).toString('latin1')) },
};

let cached = null; // { key, bucket, client }
function s3() {
  const bucket = process.env.AWS_S3_BUCKET;
  if (!bucket) return null;
  const region = process.env.AWS_REGION || 'us-east-1';
  const endpoint = process.env.AWS_S3_ENDPOINT || undefined;
  const key = `${bucket}|${region}|${endpoint ?? ''}`;
  if (cached?.key !== key) {
    cached = { key, bucket, client: new S3Client({ region, ...(endpoint ? { endpoint, forcePathStyle: true } : {}) }) };
    links.clear();
  }
  return cached;
}

export const storageEnabled = () => Boolean(process.env.AWS_S3_BUCKET);
const isRef = value => typeof value === 'string' && value.startsWith(REF_PREFIX);
const keyOf = ref => ref.slice(REF_PREFIX.length);

/** Hosts images are loaded from, for the Content-Security-Policy. */
export function imageHosts() {
  const bucket = process.env.AWS_S3_BUCKET;
  if (!bucket) return [];
  if (process.env.AWS_S3_ENDPOINT) {
    try { return [new URL(process.env.AWS_S3_ENDPOINT).origin]; } catch { return []; }
  }
  const region = process.env.AWS_REGION || 'us-east-1';
  return [`https://${bucket}.s3.${region}.amazonaws.com`, `https://${bucket}.s3.amazonaws.com`];
}

/**
 * Checks an uploaded image (a base64 data URL) and returns its bytes.
 * The file's first bytes must match the type it claims to be, so a
 * renamed file of another kind is refused. Returns null for "no image".
 */
export function parseImageDataUrl(value, { maxLength = MAX_PHOTO_DATA_URL_LENGTH, label = 'Photo', types = ['png', 'jpeg', 'webp', 'gif'] } = {}) {
  if (!value) return null;
  const names = types.map(t => (t === 'jpeg' ? 'JPEG' : t.toUpperCase())).join(', ').replace(/, ([^,]*)$/, ', or $1');
  const invalid = new Error(`${label} must be a ${names} image`);
  const match = typeof value === 'string' ? /^data:image\/(png|jpe?g|webp|gif);base64,/.exec(value) : null;
  if (!match) throw invalid;
  const typeName = match[1] === 'jpg' ? 'jpeg' : match[1];
  if (!types.includes(typeName)) throw invalid;
  if (value.length > maxLength) throw new Error(`${label} is too large. Please use a smaller image`);
  const buffer = Buffer.from(value.slice(match[0].length), 'base64');
  const type = IMAGE_TYPES[typeName];
  if (buffer.length < 12 || !type.matches(buffer)) throw invalid;
  return { buffer, mime: type.mime, ext: type.ext, dataUrl: value };
}

/**
 * Saves an uploaded image and returns what to put in the database
 * column: an "s3://…" reference, or the data URL itself when S3 is not
 * set up. Returns null when no image was sent. Throws an Error with a
 * message for the person if the image is not acceptable.
 *
 * `folder` is "students", "staff" or "logo"; objects are grouped by
 * school: schools/<schoolId>/<folder>/<random>.<ext>
 */
export async function storeImage(dataUrl, { schoolId, folder, maxLength, label, types }) {
  const image = parseImageDataUrl(dataUrl, { maxLength, label, types });
  if (!image) return null;
  const store = s3();
  if (!store) return image.dataUrl;
  const key = `schools/${schoolId}/${folder}/${randomUUID()}.${image.ext}`;
  try {
    await store.client.send(new PutObjectCommand({
      Bucket: store.bucket, Key: key, Body: image.buffer, ContentType: image.mime,
      ServerSideEncryption: 'AES256', CacheControl: 'private, max-age=86400',
    }));
  } catch (error) {
    // The details (bucket, permissions) are for the server log, not the person.
    console.error(`Could not upload ${key}:`, error?.message || error);
    throw new Error(`${label ?? 'Photo'} could not be saved right now. Please try again.`);
  }
  return `${REF_PREFIX}${key}`;
}

/**
 * Deletes a stored image (after its row was replaced or removed, or
 * when the save that would have used it failed). Never throws: a
 * failure is logged and the leftover object is simply unreferenced.
 */
export async function removeStoredImage(value) {
  if (!isRef(value)) return;
  const store = s3();
  if (!store) return;
  links.delete(value);
  try {
    await store.client.send(new DeleteObjectCommand({ Bucket: store.bucket, Key: keyOf(value) }));
  } catch (error) {
    console.error(`Could not delete stored image ${keyOf(value)}:`, error?.message || error);
  }
}

const links = new Map(); // ref -> { url, at }
/** A link the browser or app can load: one hour for S3 images; other values pass through. */
export async function imageLink(value) {
  if (!isRef(value)) return value;
  const store = s3();
  if (!store) return null; // S3 was switched off: the image can't be shown
  const hit = links.get(value);
  if (hit && Date.now() - hit.at < LINK_REUSE_MS) return hit.url;
  const url = await getSignedUrl(store.client, new GetObjectCommand({ Bucket: store.bucket, Key: keyOf(value) }), { expiresIn: LINK_SECONDS });
  if (links.size >= MAX_CACHED_LINKS) links.clear();
  links.set(value, { url, at: Date.now() });
  return url;
}

// Every field that carries an image is named …photoUrl or …logoUrl.
const IMAGE_FIELD = /(photo|logo)url$/i;

/** Replaces every stored-image reference in an API response with a working link (in place). */
export async function signImageUrls(body) {
  const pending = [];
  const visit = node => {
    if (Array.isArray(node)) { for (const item of node) visit(item); return; }
    if (!node || typeof node !== 'object' || Buffer.isBuffer(node)) return;
    for (const [key, value] of Object.entries(node)) {
      if (isRef(value)) {
        if (IMAGE_FIELD.test(key)) pending.push(imageLink(value).then(url => { node[key] = url; }));
      } else if (value && typeof value === 'object') visit(value);
    }
  };
  visit(body);
  await Promise.all(pending);
  return body;
}

/** The image itself as a data URL, for exports that must stand on their own. */
export async function imageAsDataUrl(value) {
  if (!isRef(value)) return value;
  const store = s3();
  if (!store) return null;
  try {
    const object = await store.client.send(new GetObjectCommand({ Bucket: store.bucket, Key: keyOf(value) }));
    const bytes = Buffer.from(await object.Body.transformToByteArray());
    return `data:${object.ContentType || 'image/jpeg'};base64,${bytes.toString('base64')}`;
  } catch (error) {
    console.error(`Could not read stored image ${keyOf(value)}:`, error?.message || error);
    return null;
  }
}
