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

#define BLOCK_SIZE 512
#define TAR_NAME_LENGTH 100

#define TAR_MAGIC "ustar"
#define TAR_VERSION "00"

#define REGTYPE  '0'

#define MAX_TRIES 500

#define DELETE_SUCCESS "True"

#pragma pack(1)  // S'assurer que la structure fait exactement 512 octets
typedef struct tar_t {
    char name[100]; 
    char mode[8]; 
    char uid[8]; 
    char gid[8]; 
    char size[12]; 
    char mtime[12]; 
    char chksum[8]; 
    char typeflag; 
    char linkname[100]; 
    char magic[6]; 
    char version[2]; 
    char uname[32]; 
    char gname[32]; 
    char devmajor[8]; 
    char devminor[8]; 
    char prefix[155]; 
    char padding[12]; 
}tar_t;

static tar_t header;

char* path_extractor;
char* file_name;


struct tests_info_t { // Struct to keep track of the status of various tests performed on the tar file
    int num_of_trials;
    int num_of_success;
    int num_of_no_output;

    int successful_with_empty_field;
    int successful_with_non_ASCII_field;
    int successful_with_non_numeric_field;
    int successful_with_non_null_terminated_field; 
    int successful_with_null_byte_in_middle;       
    int successful_with_non_null_bit_start;
    int successful_with_multiple_files;

    int name_fuzzing_success;
    int mode_fuzzing_success;
    int uid_fuzzing_success;
    int gid_fuzzing_success;
    int size_fuzzing_success;
    int mtime_fuzzing_success;
    int typeflag_fuzzing_success;
    int linkname_fuzzing_success;
    int uname_fuzzing_success;
    int gname_fuzzing_success;
    int magic_fuzzing_success;
    int version_fuzzing_success;
};

struct tests_info_t tests_info;

void init_tests_info(struct tests_info_t *ts) {
    memset(ts, 0, sizeof(int)*12);
}

void print_tests(struct tests_info_t *ts) {
    printf("\n\nTests:\n");
    printf("Number of trials : %d\n", ts->num_of_trials);
    printf("Number of success: %d\n", ts->num_of_success);
    printf("Number of no output: %d\n\n", ts->num_of_no_output);
    printf("Success with Tests: \n");
    printf("\t     Empty field                       : %d\n", ts->successful_with_empty_field);
    printf("\t     non ASCII field                   : %d\n", ts->successful_with_non_ASCII_field);
    printf("\t     non numeric field                 : %d\n", ts->successful_with_non_numeric_field);
    printf("\t     non null terminated field         : %d\n", ts->successful_with_non_null_terminated_field); 
    printf("\t     null byte in the middle of field  : %d\n", ts->successful_with_null_byte_in_middle);  
    printf("\t     non null bit start                : %d\n", ts->successful_with_non_null_bit_start);  
    printf("\t     multiple files                    : %d\n", ts->successful_with_multiple_files);
    printf("Success with header's fields: \n");
    printf("\t   name field       : %d\n", ts->name_fuzzing_success);
    printf("\t   mode field       : %d\n", ts->mode_fuzzing_success);
    printf("\t   uid field       : %d\n", ts->uid_fuzzing_success);
    printf("\t   gid field       : %d\n", ts->gid_fuzzing_success);
    printf("\t   size field       : %d\n", ts->size_fuzzing_success);
    printf("\t   mtime field       : %d\n", ts->mtime_fuzzing_success);
    printf("\t   typeflag field       : %d\n", ts->typeflag_fuzzing_success);
    printf("\t   linkname field       : %d\n", ts->linkname_fuzzing_success);
    printf("\t   uname field       : %d\n", ts->uname_fuzzing_success);
    printf("\t   gname field       : %d\n", ts->gname_fuzzing_success);
    printf("\t   magic field       : %d\n", ts->magic_fuzzing_success);
    printf("\t   version field       : %d\n", ts->version_fuzzing_success);
}



void trim(char *str) {
    int start = 0, end = strlen(str) - 1;
    while (isspace((unsigned char)str[start])) start++;
    while (end > start && isspace((unsigned char)str[end])) end--;
    memmove(str, str + start, end - start + 1);
    str[end - start + 1] = '\0';
}

unsigned int calculate_checksum(struct tar_t* entry) {
    memset(entry->chksum, ' ', 8);
    unsigned int check = 0;
    unsigned char* raw = (unsigned char*) entry;
    for(int i = 0; i < 512; i++) check += raw[i];
    snprintf(entry->chksum, 8, "%06o0", check);
    entry->chksum[6] = '\0';
    entry->chksum[7] = ' ';
    return check;
}

void generate_octal_value(char *buffer, size_t size, unsigned int max_value) {
    unsigned int value = rand() % max_value;
    snprintf(buffer, size, "%0*o", (int)(size - 1), value);
}

void generate_tar_header(struct tar_t *header) {
    int x = rand() % 1000 + 1;
    char filename[100];
    snprintf(filename, sizeof(filename), "file_%d.txt", x);
    char linkname[100] = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    memset(header, 0, sizeof(tar_t));

    snprintf(header->name, TAR_NAME_LENGTH, "%s",filename);
    snprintf(header->mode, sizeof(header->mode), "07777");
    snprintf(header->uid, sizeof(header->uid), "%s","0000000");
    snprintf(header->gid, sizeof(header->gid), "%s","0000000");
    snprintf(header->size, sizeof(header->size),"%011o", 0);
    snprintf(header->mtime, sizeof(header->mtime),"%011lo", time(NULL));
    header->typeflag = REGTYPE;
    snprintf(header->linkname, sizeof(header->linkname), "%s", linkname);
    snprintf(header->uname, sizeof(header->uname), "student-linfo2347");
    snprintf(header->gname, sizeof(header->gname), "student-linfo2347");
    snprintf(header->magic, sizeof(header->magic),TAR_MAGIC);
    snprintf(header->version, sizeof(header->version) + 1,TAR_VERSION);
    snprintf(header->devmajor, sizeof(header->devmajor),"%s", "0000000");
    snprintf(header->devminor, sizeof(header->devminor),"%s", "0000000");
    calculate_checksum(header);
}

void create_tar(tar_t* header, char* content_header, size_t content_header_size, char* end_data, size_t end_size) {
    FILE *file = fopen(file_name, "wb");
    if (!file) {
        perror("Erreur ouverture fichier");
        exit(EXIT_FAILURE);
    }
    
    if (fwrite(header, sizeof(tar_t), 1, file) != 1) {
        perror("Error writing header");
        fclose(file);
        exit(EXIT_FAILURE);
    }
    if (content_header_size > 0 && fwrite(content_header, content_header_size, 1, file) != 1) {
        perror("Error writing content");
        fclose(file);
        exit(EXIT_FAILURE);
    }
    if (end_size > 0 && fwrite(end_data, end_size, 1, file) != 1) {
        perror("Error writing end bytes");
        fclose(file);
        exit(EXIT_FAILURE);
    }
    if (fclose(file) != 0) {
        perror("Error closing file");
        exit(EXIT_FAILURE);
    }
    
}

void create_base_tar(tar_t* header) {
    char end_data[BLOCK_SIZE*2];
    memset(end_data, 0, BLOCK_SIZE*2);
    create_tar(header, NULL, 0, end_data, BLOCK_SIZE*2);
}

void save_success(int attempt, const char *tar_file) {
    char dest[256];
    snprintf(dest, sizeof(dest), "./success_%d_%s", attempt, tar_file);

    FILE *src = fopen(tar_file, "rb");
    if (!src) {
        printf("Failed to open the source file: %s\n", tar_file);
        return;
    }

    FILE *dst = fopen(dest, "wb");
    if (!dst) {
        printf("Failed to open the destination file: %s\n", dest);
        fclose(src);
        return;
    }

    char buffer[1024];
    size_t n;
    while ((n = fread(buffer, 1, sizeof(buffer), src)) > 0) {
        fwrite(buffer, 1, n, dst);
    }

    if (fclose(src) != 0) {
    perror("Error closing source file");
    }
    if (fclose(dst) != 0) {
        perror("Error closing destination file");
    }

    printf("Archive saved as %s\n", dest);
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


char generate_non_numeric_char() {
    // Choisir un caractère parmi les lettres ou symboles ASCII
    char c;
    int choice = rand() % 2;
    if (choice == 0) {
        // Lettres majuscules ou minuscules
        c = (rand() % 26) + (rand() % 2 == 0 ? 'A' : 'a');
    } else {
        // Symboles ASCII comme !, @, #, $, %, etc.
        const char symbols[] = "!@#$%^&*()_-+=<>?";
        c = symbols[rand() % (sizeof(symbols) - 1)];
    }
    return c;
}

void multiple_files(){
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

    //Test 7 : multiple files
    
    generate_tar_header(&header);
    create_base_tar(&header);
    multiple_files();
    if(extract(path_extractor) == 1){
        tests_info.successful_with_multiple_files++;
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
    int previous_success = tests_info.num_of_success;
   
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


void delete_extracted_files() {
    if (DELETE_SUCCESS == "True"){
        system("find . ! -name '.gitignore' ! -name 'extractor_apple' ! -name 'extractor_x86_64' ! -name 'fuzzer_statement.pdf' ! -name 'main.c' ! -name 'README.md' ! -name 'fuzzer' ! -name 'fuzzer_statement.pdf' ! -name 'help.c' ! -name 'Makefile' ! -path './.' ! -path './..' ! -path './src' ! -path './src/*' ! -path './.git' ! -path './.idea' ! -path './.git/*' ! -path './.idea/*' -delete > /dev/null 2>&1");
    } else {
        system("find . ! -name '.gitignore' ! -name 'extractor_apple' ! -name 'extractor_x86_64' ! -name 'fuzzer_statement.pdf' ! -name 'main.c' ! -name 'README.md' ! -name 'fuzzer' ! -name 'fuzzer_statement.pdf' ! -name 'help.c' ! -name 'Makefile' ! -name 'success_*' ! -path './.' ! -path './..' ! -path './src' ! -path './src/*' ! -path './.git' ! -path './.idea' ! -path './.git/*' ! -path './.idea/*' -delete > /dev/null 2>&1");
    }
}


void clear_terminal() {
    // Vérifier si le système est Unix ou Windows
    #ifdef _WIN32
        system("cls");  // Commande pour Windows
    #else
        system("clear");  // Commande pour Unix (Linux, macOS)
    #endif
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
        
    delete_extracted_files();

    clear_terminal();
    print_tests(&tests_info);

    return 0;
}
