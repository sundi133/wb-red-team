import { createCanvas } from "@napi-rs/canvas";

/**
 * Renders attack text onto a white PNG image so a VLM can read it.
 * The resulting Buffer replaces the dummy 1×1 PNG in multipart_image attacks.
 */
export function buildAttackImage(text: string): Buffer {
  const width = 900;
  const fontSize = 18;
  const lineHeight = 28;
  const padding = 40;
  const maxLineWidth = width - padding * 2;

  // Measure and wrap text first to know canvas height
  const canvas = createCanvas(width, 100);
  const ctx = canvas.getContext("2d");
  ctx.font = `${fontSize}px sans-serif`;

  const words = text.split(" ");
  const lines: string[] = [];
  let current = "";
  for (const word of words) {
    const candidate = current ? `${current} ${word}` : word;
    if (ctx.measureText(candidate).width > maxLineWidth && current) {
      lines.push(current);
      current = word;
    } else {
      current = candidate;
    }
  }
  if (current) lines.push(current);

  const height = padding * 2 + lines.length * lineHeight;
  const final = createCanvas(width, height);
  const fctx = final.getContext("2d");

  // White background
  fctx.fillStyle = "#ffffff";
  fctx.fillRect(0, 0, width, height);

  // Black text
  fctx.fillStyle = "#000000";
  fctx.font = `${fontSize}px sans-serif`;
  lines.forEach((line, i) => {
    fctx.fillText(line, padding, padding + (i + 1) * lineHeight);
  });

  return final.toBuffer("image/png");
}
