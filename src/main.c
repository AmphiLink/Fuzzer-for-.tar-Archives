#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fnmatch.h>

#include "utils.h"

#pragma pack(1)  // S'assurer que la structure fait exactement 512 octets
static tar_t header;

char* path_extractor;
char* file_name;

void create_base_tar(tar_t* header) {
    char end_data[BLOCK_SIZE*2];
    memset(end_data, 0, BLOCK_SIZE*2);
    create_tar(header, NULL, 0, end_data, BLOCK_SIZE*2);
}

int extract(char* path){
    tests_info.num_of_trials++;
    int rv = 0;
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "%s %s", path, file_name);
    char buf[33];
    FILE *fp = popen(cmd, "r");

    if (fp == NULL) {
        printf("Error opening pipe!\n");
        return -1;
    }

    if(fgets(buf, 33, fp) == NULL) {
        tests_info.num_of_no_output++;
        rv = 0;
    } else if(strncmp(buf, "*** The program has crashed ***", 30) == 0) {
        rv = 1;
        tests_info.num_of_success++;
        save_success(tests_info.num_of_success, file_name);
    }

    if (pclose(fp) == -1) {
        printf("Command not found\n");
        rv = -1;
    }

    return rv;
}

void multiple_files(){
    generate_tar_header(&header);
    create_base_tar(&header);
    FILE *file = fopen(file_name, "wb");
    for (int i=0; i<2; i++){
        generate_tar_header(&header);
        fwrite(&header, sizeof(struct tar_t), 1, file);
        
        char data[BLOCK_SIZE] = {0};
        fwrite(data, 1, BLOCK_SIZE, file);
    }

    char end_block[BLOCK_SIZE * 2] = {0};
    fwrite(end_block, 1, BLOCK_SIZE * 2, file);
    
    fclose(file);
    if(extract(path_extractor) == 1){
        tests_info.successful_with_multiple_files++;
    }
}

void fuzz_field(char *field, size_t field_size) { // prend en compte la taille et le type de test avec un pointeur vers le champ à tester 
    // Test 1 : Empty field
    generate_tar_header(&header);
    strncpy(field, "", field_size);
    create_base_tar(&header);
    if(extract(path_extractor) == 1){
        tests_info.successful_with_empty_field++;
    }

    // Test 2 : Non-Numeric field
    generate_tar_header(&header);
    for (size_t i = 0; i < field_size; i++) {
        field[i -1] = generate_non_numeric_char();
    }
    field[field_size] = '\0';
    create_base_tar(&header);
    if(extract(path_extractor) == 1){
        tests_info.successful_with_non_numeric_field++;
    }

    // Test 3 : ASCII Field
    generate_tar_header(&header);
    for (size_t i = 0; i < field_size - 1; i++) {
        field[i - 1] = 128 + (rand() % 128); 
    }
    field[field_size] = '\0';
    create_base_tar(&header);
    if(extract(path_extractor) == 1){
        tests_info.successful_with_non_ASCII_field++;
    }
    // Test 4 : Field not terminated by null byte
    generate_tar_header(&header);
    for (size_t i = 0; i < field_size - 1; i++) {
        field[i] = 'A' + (rand() % 26); 
    }
    
    create_base_tar(&header);
    if(extract(path_extractor) == 1) {
        tests_info.successful_with_non_null_terminated_field++;
    }

    // Test 5 : Null byte in the middle of the field
    generate_tar_header(&header);
    field[field_size / 2] = '\0'; 
    create_base_tar(&header);
    if(extract(path_extractor) == 1) {
        tests_info.successful_with_null_byte_in_middle++;
    }

    // Test 6 : Field starting with a non-null bit
    generate_tar_header(&header);
    field[0] = 1; 
    create_base_tar(&header);
    if(extract(path_extractor) == 1) {
        tests_info.successful_with_non_null_bit_start++;
    }

    // Test 7 : Valeur négative
    generate_tar_header(&header);
    create_base_tar(&header);
    snprintf(header.size, sizeof(header.size), "%011o", -100); // Stocker en octal
    if (extract(path_extractor) == 1) {
        tests_info.successful_with_negative_value++;
    }


    // Test 8 : Champ rempli de NULL
    generate_tar_header(&header);
    create_base_tar(&header);
    memset(header.name, '\0', sizeof(header.name)); 
    if (extract(path_extractor) == 1) {
        tests_info.successful_with_null_field++;
    }

    // Test 9 : Champ plus court que prévu
    generate_tar_header(&header);
    create_base_tar(&header);
    memset(header.name, 'A', 5); 
    header.name[5] = '\0'; 
    if (extract(path_extractor) == 1) {
        tests_info.successful_with_short_field++;
    }

    //Test 10: non-octal value
    generate_tar_header(&header);
    memset(field, '8', field_size);
    create_base_tar(&header);
    if(extract(path_extractor) == 1) {
        tests_info.successful_with_non_octal_value++;
    }

     // Test 11 : Champ trop long
    generate_tar_header(&header);
    create_base_tar(&header);
    memset(header.name, 'E', sizeof(header.name) - 1); 
    header.name[sizeof(header.name) - 1] = '\0';  
    if (extract(path_extractor) == 1) {
        tests_info.successful_with_long_field++;
    }

    // Test 12 : Champ rempli d'espaces
    generate_tar_header(&header);
    create_base_tar(&header);
    memset(header.name, ' ', sizeof(header.name)); 
    if (extract(path_extractor) == 1) {
        tests_info.successful_with_space_field++;
    }

    // Test 13 : Champ avec caractères spéciaux
    generate_tar_header(&header);
    create_base_tar(&header);
    strncpy(header.name, "!@#$%^&*()", sizeof(header.name));
    if (extract(path_extractor) == 1) {
        tests_info.successful_with_special_chars++;
    }


    calculate_checksum(&header);
}

void name_fuzzing() {
    int previous_success = tests_info.num_of_success;
    fuzz_field(header.name, sizeof(header.name));
    tests_info.name_fuzzing_success+= tests_info.num_of_success - previous_success;
}

void mode_fuzzing() {
    int previous_success = tests_info.num_of_success;
    fuzz_field(header.mode, sizeof(header.mode));
    tests_info.mode_fuzzing_success+= tests_info.num_of_success - previous_success;
}

void uid_fuzzing(){
    int previous_success = tests_info.num_of_success;
    fuzz_field(header.uid, sizeof(header.uid));
    tests_info.uid_fuzzing_success+= tests_info.num_of_success - previous_success;
}

void gid_fuzzing(){
    int previous_success = tests_info.num_of_success;
    fuzz_field(header.gid, sizeof(header.gid));
    tests_info.gid_fuzzing_success+= tests_info.num_of_success - previous_success;
}

void size_fuzzing() {
    int previous_success = tests_info.num_of_success;
    fuzz_field(header.size, sizeof(header.size));
    tests_info.size_fuzzing_success+= tests_info.num_of_success - previous_success;
}

void mtime_fuzzing() {
    int previous_success = tests_info.num_of_success;
    fuzz_field(header.mtime, sizeof(header.mtime));
    tests_info.mtime_fuzzing_success+= tests_info.num_of_success - previous_success;
}

void typeflag_fuzzing() {   
    for (int i = 0; i <= 255; i++) {
        generate_tar_header(&header);   
        header.typeflag = (char)i;    
        create_base_tar(&header);

        if (extract(path_extractor) == 1) {
            tests_info.typeflag_fuzzing_success++;
        }
    }
}

void linkname_fuzzing() {
    int previous_success = tests_info.num_of_success;
    fuzz_field(header.linkname, sizeof(header.linkname));
    tests_info.linkname_fuzzing_success+= tests_info.num_of_success - previous_success;
}
void uname_fuzzing() {
    int previous_success = tests_info.num_of_success;
    fuzz_field(header.uname, sizeof(header.uname));
    tests_info.uname_fuzzing_success+= tests_info.num_of_success - previous_success;
}

void gname_fuzzing() {
    int previous_success = tests_info.num_of_success;
    fuzz_field(header.gname, sizeof(header.gname));
    tests_info.gname_fuzzing_success+= tests_info.num_of_success - previous_success;
}

void magic_fuzzing() {
    int previous_success = tests_info.num_of_success;
    fuzz_field(header.magic, sizeof(header.magic));
    tests_info.magic_fuzzing_success+= tests_info.num_of_success - previous_success;
}

void version_fuzzing() {
    int previous_success = tests_info.num_of_success;
    fuzz_field(header.version, sizeof(header.version));
    tests_info.version_fuzzing_success+= tests_info.num_of_success - previous_success;
}

int main(int argc, char* argv[]) {
    if (argc < 2) 
    {
        printf("Wrong number of arguments.\n");
        printf("Please provide the path of the extractor as an argument.");
        return -1;
    }
    path_extractor = argv[1];
    file_name = "Archive.tar";
    srand(time(NULL));
    

    init_tests_info(&tests_info);
    // Exécuter les tests spécifiques
    name_fuzzing();
    mode_fuzzing();
    uid_fuzzing();
    gid_fuzzing();
    size_fuzzing();
    mtime_fuzzing();
    typeflag_fuzzing();
    linkname_fuzzing();
    uname_fuzzing();
    gname_fuzzing();
    version_fuzzing();
    magic_fuzzing();
    multiple_files();
        
    delete_extracted_files();

    clear_terminal();
    print_tests(&tests_info);

    return 0;
}
