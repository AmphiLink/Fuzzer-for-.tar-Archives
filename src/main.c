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

#pragma pack(1)  
static tar_t header;

char* path_extractor;
char* file_name;

/**
 * @brief This function creates a base TAR archive with an empty end block.
 * @param header Pointer to the tar_t structure containing the archive header.
 */
void create_base_tar(tar_t* header) {
    char end_data[BLOCK_SIZE*2];
    memset(end_data, 0, BLOCK_SIZE*2);
    create_tar(header, NULL, 0, end_data, BLOCK_SIZE*2);
}

/**
 * @brief This function executes the extractor on the given path and checks for expected outputs.
 * @param path Path to the extractor binary.
 * @return 1 if the extraction crashes, 0 otherwise.
 */
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

/**
 * @brief This function creates a TAR archive with multiple files inside and attempts extraction.
 */
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

/**
 * @brief This function performs fuzzing on a specific field of the TAR header with various test cases.
 * @param field Pointer to the field being fuzzed.
 * @param field_size Size of the field in bytes.
 */
void fuzz_field(char *field, size_t field_size) { 
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

    // Test 7 : Negative value
    generate_tar_header(&header);
    create_base_tar(&header);
    snprintf(header.size, sizeof(header.size), "%011o", -100); 
    if (extract(path_extractor) == 1) {
        tests_info.successful_with_negative_value++;
    }


    // Test 8 : Field filled with NULL
    generate_tar_header(&header);
    create_base_tar(&header);
    memset(header.name, '\0', sizeof(header.name)); 
    if (extract(path_extractor) == 1) {
        tests_info.successful_with_null_field++;
    }

    // Test 9 : Field shorter than expected 
    generate_tar_header(&header);
    create_base_tar(&header);
    memset(header.name, 'A', 5); 
    header.name[5] = '\0'; 
    if (extract(path_extractor) == 1) {
        tests_info.successful_with_short_field++;
    }

    //Test 10: Non-octal value
    generate_tar_header(&header);
    memset(field, '8', field_size);
    create_base_tar(&header);
    if(extract(path_extractor) == 1) {
        tests_info.successful_with_non_octal_value++;
    }

     // Test 11 : Field too long
    generate_tar_header(&header);
    create_base_tar(&header);
    memset(header.name, 'E', sizeof(header.name) - 1); 
    header.name[sizeof(header.name) - 1] = '\0';  
    if (extract(path_extractor) == 1) {
        tests_info.successful_with_long_field++;
    }

    // Test 12 : Space-filled field 
    generate_tar_header(&header);
    create_base_tar(&header);
    memset(header.name, ' ', sizeof(header.name)); 
    if (extract(path_extractor) == 1) {
        tests_info.successful_with_space_field++;
    }

    // Test 13 : Field with special features 
    generate_tar_header(&header);
    create_base_tar(&header);
    strncpy(header.name, "!@#$%^&*()", sizeof(header.name));
    if (extract(path_extractor) == 1) {
        tests_info.successful_with_special_chars++;
    }


    calculate_checksum(&header);
}

/**
 * @brief This function performs fuzzing on the name field of the TAR header.
 *        This field represents the name of the file stored in the archive.
 */
void name_fuzzing() {
    int previous_success = tests_info.num_of_success;
    fuzz_field(header.name, sizeof(header.name));
    tests_info.name_fuzzing_success+= tests_info.num_of_success - previous_success;
}

/**
 * @brief This function performs fuzzing on the mode field of the TAR header.
 *        This field specifies the file permissions.
*/
void mode_fuzzing() {
    //First pass on each mode to verif if theyr are supported by the extractor
    unsigned int modes[] = {
        TSUID, TSGID, TSVTX, 
        TUREAD, TUWRITE, TUEXEC, 
        TGREAD, TGWRITE, TGEXEC, 
        TOREAD, TOWRITE, TOEXEC
    };
    int num_modes = sizeof(modes) / sizeof(modes[0]);

    for (int i = 0; i < num_modes; i++) {
        snprintf(header.mode, sizeof(header.mode), "%07o", modes[i]);
        if(extract(path_extractor) == 1){
            tests_info.mode_fuzzing_success++;
        }
    }
    int previous_success = tests_info.num_of_success;
    fuzz_field(header.mode, sizeof(header.mode));
    tests_info.mode_fuzzing_success+= tests_info.num_of_success - previous_success;
}

/**
 * @brief This function performs fuzzing on the UID field of the TAR header.
 *        This field contains the user ID of the file owner.
 */
void uid_fuzzing(){
    int previous_success = tests_info.num_of_success;
    fuzz_field(header.uid, sizeof(header.uid));
    tests_info.uid_fuzzing_success+= tests_info.num_of_success - previous_success;
}

/**
 * @brief This function performs fuzzing on the GID field of the TAR header.
 *        This field contains the group ID of the file owner.
 */
void gid_fuzzing(){
    int previous_success = tests_info.num_of_success;
    fuzz_field(header.gid, sizeof(header.gid));
    tests_info.gid_fuzzing_success+= tests_info.num_of_success - previous_success;
}

/**
 * @brief This function performs fuzzing on the size field of the TAR header.
 *        This field specifies the size of the file in bytes.
 */
void size_fuzzing() {
    int previous_success = tests_info.num_of_success;
    fuzz_field(header.size, sizeof(header.size));
    tests_info.size_fuzzing_success+= tests_info.num_of_success - previous_success;
}

/**
 * @brief This function performs fuzzing on the mtime field of the TAR header.
 *        This field represents the last modification time of the file.
 */
void mtime_fuzzing() {
    int minus1 = 0;
    int minus2 = 0;
    int previous_success = tests_info.num_of_success;
    fuzz_field(header.mtime, sizeof(header.mtime));
    struct tm time1 = {0};
    time1.tm_year = 1899 - 1900; 
    time1.tm_mon = 0;            
    time1.tm_mday = 1;           
    time_t timestamp1 = mktime(&time1);
    snprintf(header.mtime, sizeof(header.mtime),"%011lo", timestamp1);
    if (extract(path_extractor) == 1){
        tests_info.mtime_fuzzing_success += 1;
        int minus1 = 1;
    }
    
    // Date 2 : 2027-03-06
    struct tm time2 = {0};
    time2.tm_year = 2027 - 1900; 
    time2.tm_mon = 2;            
    time2.tm_mday = 6;           
    time_t timestamp2 = mktime(&time2);
    snprintf(header.mtime, sizeof(header.mtime),"%011lo", timestamp2);
    snprintf(header.mtime, sizeof(header.mtime),"%011lo", timestamp1);
    if (extract(path_extractor) == 1){
        tests_info.mtime_fuzzing_success += 1;
        int minus2 = 1;
    }
    tests_info.mtime_fuzzing_success+= tests_info.num_of_success - previous_success - minus1 - minus2;
}

/**
 * @brief This function fuzzes the typeflag field by testing all 256 possible byte values so 0 to 0xFF in hexadecimal.
 */
void typeflag_fuzzing() {   
    for (int i = 0; i <= 0xFF; i++) {
        generate_tar_header(&header);   
        header.typeflag = (char)i;    
        create_base_tar(&header);

        if (extract(path_extractor) == 1) {
            tests_info.typeflag_fuzzing_success++;
        }
    }
}

/**
 * @brief This function performs fuzzing on the linkname field of the TAR header.
 *        This field contains the target name if the file is a symbolic or hard link.
 */
void linkname_fuzzing() {
    int previous_success = tests_info.num_of_success;
    fuzz_field(header.linkname, sizeof(header.linkname));
    tests_info.linkname_fuzzing_success+= tests_info.num_of_success - previous_success;
}

/**
 * @brief This function performs fuzzing on the uname field of the TAR header.
 *        This field stores the name of the file owner.
 */
void uname_fuzzing() {
    int previous_success = tests_info.num_of_success;
    fuzz_field(header.uname, sizeof(header.uname));
    tests_info.uname_fuzzing_success+= tests_info.num_of_success - previous_success;
}

/**
 * @brief This function performs fuzzing on the gname field of the TAR header.
 *        This field stores the group name of the file owner.
 */
void gname_fuzzing() {
    int previous_success = tests_info.num_of_success;
    fuzz_field(header.gname, sizeof(header.gname));
    tests_info.gname_fuzzing_success+= tests_info.num_of_success - previous_success;
}

/**
 * @brief This function performs fuzzing on the magic field of the TAR header.
 *        This field identifies the archive format (typically "ustar").
 */
void magic_fuzzing() {
    int previous_success = tests_info.num_of_success;
    fuzz_field(header.magic, sizeof(header.magic));
    tests_info.magic_fuzzing_success+= tests_info.num_of_success - previous_success;
}


/**
 * @brief This function performs fuzzing on the version field of the TAR header.
 *        This field specifies the version of the archive format.
 */
void version_fuzzing() {
    int previous_success = tests_info.num_of_success;
    fuzz_field(header.version, sizeof(header.version));
    tests_info.version_fuzzing_success+= tests_info.num_of_success - previous_success;
}

/**
 * @brief This function is the main function of our project which is an entry point for the program, it initializes tests and runs all fuzzing functions.
 */
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
    // Execut the specific test
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
