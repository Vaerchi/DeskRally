/**
 * The public-page logo, prepared in the browser (docs/66 2.7): downscaled to at most 512x256 and re-encoded as a PNG through
 * a canvas BEFORE it is uploaded. That keeps the request small and sends the server only a plain raster; the server decodes
 * and re-encodes it regardless (a child process, 2b.3), so this is a convenience and never the defence.
 */

export const LOGO_MAX_WIDTH = 512;
export const LOGO_MAX_HEIGHT = 256;
/** The server refuses an uploaded file over this (control-plane LogoMaxInputBytes), measured on the decoded bytes. */
export const LOGO_MAX_UPLOAD_BYTES = 128 * 1024;
/** What a user may pick: the rasters the canvas can decode. SVG is deliberately absent. */
export const LOGO_PICK_TYPES = ["image/png", "image/jpeg", "image/gif", "image/webp"];

/** The size an image of `w` x `h` is drawn at: shrunk to fit the box keeping its proportions, never enlarged, never zero. */
export function fitWithin(w: number, h: number, maxW = LOGO_MAX_WIDTH, maxH = LOGO_MAX_HEIGHT): { width: number; height: number } {
  if (!(w > 0) || !(h > 0)) return { width: 1, height: 1 };
  const scale = Math.min(1, maxW / w, maxH / h);
  return { width: Math.max(1, Math.round(w * scale)), height: Math.max(1, Math.round(h * scale)) };
}

/** The decoded byte length of a base64 data URI, without decoding it. */
export function dataUriBytes(uri: string): number {
  const comma = uri.indexOf(",");
  if (comma < 0) return 0;
  const b64 = uri.slice(comma + 1);
  const pad = b64.endsWith("==") ? 2 : b64.endsWith("=") ? 1 : 0;
  return Math.floor((b64.length * 3) / 4) - pad;
}

export class LogoPrepareError extends Error {}

function loadImage(src: string): Promise<HTMLImageElement> {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = () => reject(new LogoPrepareError("that image could not be read"));
    img.src = src;
  });
}

/**
 * Draws a picked file (or an existing raster data URI) into a canvas of at most 512x256 and returns it as a PNG data URI.
 * Browser only. Throws LogoPrepareError with a sentence for the Owner.
 */
export async function downscaleLogoToPng(source: Blob | string): Promise<string> {
  const url = typeof source === "string" ? source : URL.createObjectURL(source);
  try {
    const img = await loadImage(url);
    const { width, height } = fitWithin(img.naturalWidth, img.naturalHeight);
    const canvas = document.createElement("canvas");
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext("2d");
    if (ctx === null) throw new LogoPrepareError("this browser cannot resize images");
    ctx.drawImage(img, 0, 0, width, height);
    const uri = canvas.toDataURL("image/png");
    if (!uri.startsWith("data:image/png;base64,")) throw new LogoPrepareError("this browser could not encode a PNG");
    if (dataUriBytes(uri) > LOGO_MAX_UPLOAD_BYTES) {
      throw new LogoPrepareError(`the logo is still over ${LOGO_MAX_UPLOAD_BYTES / 1024} KiB after resizing; use a simpler image`);
    }
    return uri;
  } finally {
    if (typeof source !== "string") URL.revokeObjectURL(url);
  }
}
