#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#define BLOCK_SIZE 512
#define TAR_NAME_LENGTH 100
#define TAR_MAGIC "ustar"
#define TAR_VERSION "00"
#define MAX_TRIES 500

#pragma pack(1)  // S'assurer que la structure fait exactement 512 octets
struct tar_t {
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
};

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
    memset(header, 0, sizeof(struct tar_t));
    snprintf(header->name, TAR_NAME_LENGTH, "file_%d.txt", rand() % 1000);
    generate_octal_value(header->mode, sizeof(header->mode), 0777);
    generate_octal_value(header->uid, sizeof(header->uid), 1000);
    generate_octal_value(header->gid, sizeof(header->gid), 1000);
    generate_octal_value(header->size, sizeof(header->size), 1024);
    generate_octal_value(header->mtime, sizeof(header->mtime), 16777216);
    header->typeflag = '0' + (rand() % 8);
    snprintf(header->linkname, sizeof(header->linkname), "link_%d", rand() % 100);
    snprintf(header->uname, sizeof(header->uname), "user_%d", rand() % 100);
    snprintf(header->gname, sizeof(header->gname), "group_%d", rand() % 100);
    strncpy(header->magic, TAR_MAGIC, 6);
    strncpy(header->version, TAR_VERSION, 2);
    calculate_checksum(header);
}

void write_random_tar(const char *filename) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("Erreur ouverture fichier");
        exit(EXIT_FAILURE);
    }
    
    int num_files = 1 + rand() % 5;  // Générer entre 1 et 5 fichiers
    for (int i = 0; i < num_files; i++) {
        struct tar_t header;
        generate_tar_header(&header);
        fwrite(&header, sizeof(struct tar_t), 1, file);
        
        char data[BLOCK_SIZE] = {0};
        fwrite(data, 1, BLOCK_SIZE, file);
    }
    
    char end_block[BLOCK_SIZE * 2] = {0};
    fwrite(end_block, 1, BLOCK_SIZE * 2, file);
    
    fclose(file);
}

void delete_extracted_files() {
    DIR *d;
    struct dirent *dir;
    struct stat st;
    d = opendir(".");
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            if ((strncmp(dir->d_name, "file_", 5) == 0) || (strncmp(dir->d_name, "link_", 5)== 0)){
                if (stat(dir->d_name, &st) == 0) {
                    if (S_ISDIR(st.st_mode)) {
                        printf("Removing directory: %s\n", dir->d_name);
                        rmdir(dir->d_name);
                    } else {
                        printf("Removing file: %s\n", dir->d_name);
                        remove(dir->d_name);
                    }
                }
            }
        }
        closedir(d);
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) return -1;
    
    srand(time(NULL));
    const char *tar_file = "archive.tar";
    
    for (int i = 0; i < MAX_TRIES; i++) {
        write_random_tar(tar_file);
        
        int rv = 0;
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "%s %s", argv[1], tar_file);
        char buf[33];
        FILE *fp;

        if ((fp = popen(cmd, "r")) == NULL) {
            printf("Error opening pipe!\n");
            return -1;
        }

        if(fgets(buf, 33, fp) == NULL) {
            printf("No output\n");
            goto finally;
        }
        if(strncmp(buf, "*** The program has crashed ***", 30) != 0) {
            printf("Not the crash message\n");
            goto finally;
        } else {
            printf("Crash detected on attempt #%d\n", i+1);
            char dest[256];
            snprintf(dest, sizeof(dest), "./success_%d_%s", i+1, tar_file);

            FILE *src = fopen(tar_file, "rb");
            if (src) {
                FILE *dst = fopen(dest, "wb");
                if (dst) {
                    char buffer[1024];
                    size_t n;
                    while ((n = fread(buffer, 1, sizeof(buffer), src)) > 0) {
                        fwrite(buffer, 1, n, dst);
                    }
                    fclose(dst);
                    printf("Archive saved as %s\n", dest);
                } else {
                    printf("Failed to open destination file.\n");
                    rv = -1;
                }
                fclose(src);
            } else {
                printf("Failed to open source file.\n");
                rv = -1;
            }
        }
    
    finally:
        if(pclose(fp) == -1) {
            printf("Command not found\n");
            rv = -1;
        }
        delete_extracted_files();
    }
    delete_extracted_files();
    return 0;
}
