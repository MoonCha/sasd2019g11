/**
 * This tool reads a ascii pgm image and inverts the image.
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <unistd.h>
#include <sys/types.h>
int setresgid(gid_t rgid, gid_t egid, gid_t sgid);

/* Maximum image width */
#define MAX_WIDTH  160

/* Maximum image height */
#define MAX_HEIGHT 120

/* Internal structure for holding the image */
typedef struct {
  unsigned short width;
  unsigned short height;
  unsigned short max_color;
  unsigned short data[MAX_WIDTH * MAX_HEIGHT];
} pgm_image_t;


/* Convenience wrapper around fgets */
static char* get_line(char *line, size_t size, FILE *in)
{
  size_t len;

  // Grab the line
  if (!fgets(line, size, in)) {
    perror("error: i/o error (failed to read a line)");
    return 0;
  }

  // Trim the '\n', fail if nothing could be found
  len = strlen(line);
  if (len < 1 || line[len - 1] != '\n') {
    return 0;
  }

  line[len - 1] = '\0';
  return line;
}


/* Load a PGM image from a file stream into a pgm_image_t structure. */
static int pgm_load(pgm_image_t *img, FILE *in)
{
  static char line[4096];
  unsigned short real_size;

  memset(img, 0, sizeof(*img));

  // P2 header
  if (!get_line(line, sizeof(line), in)) {
    return -1;
  } else if (strcmp(line, "P2") != 0) {
    fprintf(stderr, "error: expected P2 image header\n");
    return -1;
  }

  // Skip comment lines
  do {
    if (!get_line(line, sizeof(line), in)) {
      return -1;
    }
  } while (line[0] == '#');

  // Read the next parts of the header
  if (sscanf(line, "%hu%hu", &img->width, &img->height) != 2) {
    perror("error: malformed width/height information");
    return -1;
  }

  if (!get_line(line, sizeof(line), in) ||
      sscanf(line, "%hu", &img->max_color) != 1) {
    perror("error: malformed color depth information");
    return -1;
  }

  real_size = img->width * img->height;
  if (real_size > (MAX_WIDTH * MAX_HEIGHT)) {
    fprintf(stderr, "error: image is too large (maximum: %d x %d)\n",
        MAX_WIDTH, MAX_HEIGHT);
    return -1;
  }

  // Now load the data
  unsigned short *p = img->data;

  for (int y = 0; !feof(in) && !ferror(in) && y < img->height; ++y) {
    for (int x = 0; x < img->width; ++x) {
      if (fscanf(in, "%hu", p++) != 1) {
        printf("error: failed to read pixel at (%d,%d) - ignoring the rest\n", x, y);
        break;
      }
    }
  }

  return 0;
}


/* Load a PGM image from a pgm_image_t structure to a file stream. */
static int pgm_save(FILE *out, const pgm_image_t *img)
{
  unsigned short max_gray = 0;

  for (int n = 0; n < img->width * img->height; ++n) {
    max_gray = (img->data[n] > max_gray)? img->data[n] : max_gray;
  }

  fprintf(out, "P2\n# Nothing to hide ;)\n%hu %hu\n%hu\n",
          img->width, img->height, max_gray);

  unsigned short *p = (unsigned short*) img->data;

  for (int y = 0; y < img->height; ++y) {
    for (int x = 0; x < img->width; ++x) {
      fprintf(out, (x > 0 ? " %-3hu" : "%-3hu"), *p++);
    }

    fprintf(out, "\n");
  }

  return 0;
}


/* create the negative of the given pgm image */
static int pgm_invert(const pgm_image_t *img)
{
  unsigned short *p = (unsigned short*) img->data;

  for (int y = 0; y < img->height; ++y) {
    for (int x = 0; x < img->width; ++x) {
      *p = img->max_color - *p;
      ++p;
    }
  }
  return 0;
}


/* Main entry point */
int main(int argc, char **argv)
{
  volatile int hidden_flag = 0;
  pgm_image_t im;
  FILE* fin, *fout;

  gid_t gid = getegid();
  setresgid(gid,gid,gid);

  if (argc < 2 || argc > 3) {
    fprintf(stderr, "usage: %s infile [outfile]", argv[0]);
    return -1;
  }

  if ((fin = fopen(argv[1], "r")) == NULL) {
    fprintf(stderr, "failed to open file %s", argv[1]);
    perror("");
    return -1;
  }

  /* Load the image */
  if (pgm_load(&im, fin) != 0) {
    fprintf(stderr, "error: failed to load the image\n");
    return -1;
  }

  /* Warning: hidden backdoor, do *not* keep in production code! */
  if (hidden_flag == 0xCAFE) {
    fprintf(stderr, "Success: time to get some coffee\n");
    return system("cat flag.txt");
  } else if (hidden_flag != 0) {
    fprintf(stderr, "partial success: you are almost there. i read 0x%X but want 0xCAFE.\n",
            (unsigned) hidden_flag);
  }

  if (pgm_invert(&im) != 0) {
    fprintf(stderr, "failed to invert image");
  }

  if (argc == 3) {
    if ((fout = fopen(argv[2], "w")) == NULL) {
      fprintf(stderr, "failed to open output file %s", argv[2]);
      perror("");
    }
  } else {
    fout = stdout;
  }

  return pgm_save(fout, &im);
}
