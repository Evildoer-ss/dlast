void func() {
    char* s1 = "func_a";
    while(1 > 2) {
        char* s3 = "func_b";
    }
    return;
}

int main() {
    if (1 == 2) {
        func();
    }
    else {
        func();
        char* s1 = "main_c";
    }
    return 0;
}