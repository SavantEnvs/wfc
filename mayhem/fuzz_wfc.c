// fuzz_wfc.c — in-process libFuzzer harness for wfc (Wave Function Collapse).
//
// Fuzzes wfc.h itself, not an image decoder: the input is a raw pixel image with a
// 5-byte header, handed straight to wfc_overlapping (tile extraction, flips +
// rotations) -> wfc_run (propagation/collapse) -> wfc_output_image. No PNG decode
// (stb_image) runs, so every finding lies in wfc.h, the one file an agent can edit.
//
//   byte 0: width  = 3 + b % 6    (3..8)
//   byte 1: height = 3 + b % 6    (3..8)
//   byte 2: components = 1 + b % 4
//   byte 3: bit0 expand input, bit1 xflip, bit2 yflip, bit3 rotate, bit4 tile size 2 (clear) / 3 (set)
//   byte 4: run seed
//   rest  : width*height*components pixel bytes (shorter input is rejected)
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define WFC_IMPLEMENTATION
#include "wfc.h"

#define HEADER 5

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size < HEADER)
    return -1;

  int w = 3 + data[0] % 6;
  int h = 3 + data[1] % 6;
  int comp = 1 + data[2] % 4;
  int flags = data[3];
  unsigned int seed = data[4];

  size_t npix = (size_t)w * h * comp;
  if (size - HEADER < npix)
    return -1;

  unsigned char *pixels = malloc(npix);
  if (!pixels)
    return 0;
  memcpy(pixels, data + HEADER, npix);

  struct wfc_image image = { pixels, comp, w, h };
  int tile = (flags & 16) ? 3 : 2;
  struct wfc *wfc = wfc_overlapping(8, 8, &image, tile, tile,
                                    flags & 1, (flags >> 1) & 1, (flags >> 2) & 1, (flags >> 3) & 1);
  if (wfc) {
    if (wfc_run(wfc, seed)) {
      struct wfc_image *out = wfc_output_image(wfc);
      if (out)
        wfc_img_destroy(out);
    }
    wfc_destroy(wfc);
  }

  free(pixels);
  return 0;
}
