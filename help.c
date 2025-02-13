#include <stdio.h>
#include <string.h>
#include <stdlib.h>
/*Hello world*/
struct tar_t
{                              /* byte offset */
    char name[100];               /*   0 */
    char mode[8];                 /* 100 */
    char uid[8];                  /* 108 */
    char gid[8];                  /* 116 */
    char size[12];                /* 124 */
    char mtime[12];               /* 136 */
    char chksum[8];               /* 148 */
    char typeflag;                /* 156 */
    char linkname[100];           /* 157 */
    char magic[6];                /* 257 */
    char version[2];              /* 263 */
    char uname[32];               /* 265 */
    char gname[32];               /* 297 */
    char devmajor[8];             /* 329 */
    char devminor[8];             /* 337 */
    char prefix[155];             /* 345 */
    char padding[12];             /* 500 */
};

void trim(char *str) {
    int start = 0, end = strlen(str) - 1;

    // Trouver le premier caractère non espace
    while (isspace((unsigned char)str[start])) {
        start++;
    }

    // Trouver le dernier caractère non espace
    while (end > start && isspace((unsigned char)str[end])) {
        end--;
    }

    // Décaler la chaîne pour enlever les espaces en début
    int i, j = 0;
    for (i = start; i <= end; i++) {
        str[j++] = str[i];
    }
    str[j] = '\0';  // Terminer la nouvelle chaîne
}

/**
 * Launches another executable given as argument,
 * parses its output and check whether or not it matches "*** The program has crashed ***".
 * @param the path to the executable
 * @return -1 if the executable cannot be launched,
 *          0 if it is launched but does not print "*** The program has crashed ***",
 *          1 if it is launched and prints "*** The program has crashed ***".
 *
 * BONUS (for fun, no additional marks) without modifying this code,
 * compile it and use the executable to restart our computer.
 */
int main(int argc, char* argv[])
{
    if (argc < 2)
        return -1;
    int rv = 0;
    char cmd[51];
    strncpy(cmd, argv[1], 25);
    cmd[26] = '\0';
    char archive_name[256] = " archive.tar";
    strncat(cmd, archive_name, 25);
    trim(archive_name);
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
    if(!(strncmp(buf, "*** The program has crashed ***\n", 33))) {
        printf("Not the crash message\n");
        goto finally;
    } else {
        printf("Crash message\n");
        rv = 1;

        // Calculer la taille restante pour le préfixe dans "dest"
        char dest[256];
        // L'espace réservé pour "success_" est de 8 caractères, donc l'espace restant est de 247
        int remaining_space = sizeof(dest) - strlen("./success_") - 1;  // -1 pour le '\0'
        
        // Vérifier si l'archive_name s'adapte dans l'espace restant
        if (strlen(archive_name) <= remaining_space) {
            snprintf(dest, sizeof(dest), "./success_%s", archive_name);
        } else {
            // Si le nom est trop long, le tronquer pour s'assurer qu'il ne dépasse pas la taille
            snprintf(dest, sizeof(dest), "./success_%.*s", remaining_space, archive_name);
        }

        // Copier l'archive dans le répertoire courant avec le nouveau nom
        FILE *src = fopen(argv[1], "rb");  // Ouvrir le fichier source
        if (src) {
            // Ouvrir le fichier de destination avant de commencer à copier
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

        goto finally;
    }
    finally:
    if(pclose(fp) == -1) {
        printf("Command not found\n");
        rv = -1;
    }
    return rv;
}

/**
 * Computes the checksum for a tar header and encode it on the header
 * @param entry: The tar header
 * @return the value of the checksum
 */
unsigned int calculate_checksum(struct tar_t* entry){
    // use spaces for the checksum bytes while calculating the checksum
    memset(entry->chksum, ' ', 8);

    // sum of entire metadata
    unsigned int check = 0;
    unsigned char* raw = (unsigned char*) entry;
    for(int i = 0; i < 512; i++){
        check += raw[i];
    }

    snprintf(entry->chksum, sizeof(entry->chksum), "%06o0", check);

    entry->chksum[6] = '\0';
    entry->chksum[7] = ' ';
    return check;
}