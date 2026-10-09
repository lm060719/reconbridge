extern "C" {
__attribute__((visibility("default"))) int Java_com_example_Native_foo(void*,void*) { return 1; }
__attribute__((visibility("default"))) int Java_com_example_Native_bar__I(void*,void*,int a) { return a; }
__attribute__((visibility("hidden"))) int Java_com_example_Native_hidden(void*,void*) { return 0; }
int ordinary_export() { return 3; }
}
