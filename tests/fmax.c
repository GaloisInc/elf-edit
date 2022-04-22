#include <math.h>
#include <stdio.h>

float my_fmax(float a, float b) {
  return fmax(a, b);
}

int main() {
  printf("%f\n", my_fmax(1.0, 2.0));
  return 0;
}
