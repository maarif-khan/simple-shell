#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>

#define MAX_ARGS 512
#define MAX_HISTORY 100
#define MAX_COMMAND_LEN 1024
#define MAX_PIPES 10
#define MAX_HEREDOC_LEN 4096

typedef struct {
    char commands[MAX_HISTORY][MAX_COMMAND_LEN];
    int count;
    int current;
} History;

typedef struct {
    char* input_file;
    char* output_file;
    char* heredoc_delimiter;
    char* heredoc_content;
    int output_append;
    int has_heredoc;
} Redirection;

History history = {0};

void print_prompt();
void parse_input(char* input, char** argv);
void add_to_history(const char* command);
char* get_last_command();
void print_history();
int count_pipes(char* input);
void execute_piped_commands(char* input);
void execute_single_command(char** args);
void parse_redirections(char* input, char** argv, Redirection* redir);
void setup_redirections(Redirection* redir);
void cleanup_redirections(Redirection* redir);
char* read_heredoc(const char* delimiter);

int main(void) {
    char* input = NULL;
    size_t len = 0;
    ssize_t read;
    char* args[MAX_ARGS];
    int should_run = 1;

    while (should_run) {
        print_prompt();
        fflush(stdout);
        read = getline(&input, &len, stdin);
        if (read == -1) break;
        if (input[read - 1] == '\n') input[read - 1] = '\0';

        if (strlen(input) == 0) continue;

        if (strcmp(input, "exit") == 0) {
            should_run = 0;
            continue;
        }

        if (strcmp(input, "history") == 0) {
            print_history();
            continue;
        }

        char* command_to_execute = NULL;
        int should_free_command = 0;

        if (strncmp(input, "!!", 2) == 0) {
            char* last_cmd = get_last_command();
            if (last_cmd == NULL) {
                printf("No previous command found\n");
                continue;
            }

            if (strcmp(input, "!!") == 0) {
                command_to_execute = last_cmd;
            } else {
                size_t new_len = strlen(last_cmd) + strlen(input) - 2 + 1;
                command_to_execute = malloc(new_len);
                if (command_to_execute == NULL) {
                    perror("malloc failed");
                    continue;
                }
                strcpy(command_to_execute, last_cmd);
                strcat(command_to_execute, input + 2);
                should_free_command = 1;
            }
            printf("%s\n", command_to_execute);
        } else {
            command_to_execute = input;
        }

        if (strncmp(input, "!!", 2) != 0) {
            add_to_history(command_to_execute);
        }

        if (count_pipes(command_to_execute) > 0) {
            execute_piped_commands(command_to_execute);
        } else {
            Redirection redir = {0};
            parse_redirections(command_to_execute, args, &redir);
            if (args[0] == NULL) {
                if (should_free_command) free(command_to_execute);
                cleanup_redirections(&redir);
                continue;
            }

            pid_t pid = fork();
            if (pid == 0) {
                setup_redirections(&redir);
                execvp(args[0], args);
                fprintf(stderr, "%s: command not found\n", args[0]);
                exit(EXIT_FAILURE);
            }
            else if (pid > 0) {
                int status;
                waitpid(pid, &status, 0);
                cleanup_redirections(&redir);
                for (int j = 0; args[j] != NULL; j++) {
                    free(args[j]);
                }
            }
            else {
                perror("fork failed");
                cleanup_redirections(&redir);
                for (int j = 0; args[j] != NULL; j++) {
                    free(args[j]);
                }
            }
        }

        if (should_free_command) {
            free(command_to_execute);
        }
    }

    free(input);
    return EXIT_SUCCESS;
}

void print_prompt() {
    printf("$ ");
}

void parse_input(char* input, char** argv) {
    int i = 0;
    char* token = strtok(input, " ");
    while (token != NULL && i < MAX_ARGS - 1) {
        argv[i++] = token;
        token = strtok(NULL, " ");
    }
    argv[i] = NULL;
}

void add_to_history(const char* command) {
    if (strlen(command) == 0) return;

    if (history.count > 0) {
        int last_index = (history.current - 1 + MAX_HISTORY) % MAX_HISTORY;
        if (strcmp(history.commands[last_index], command) == 0) {
            return;
        }
    }

    strncpy(history.commands[history.current], command, MAX_COMMAND_LEN - 1);
    history.commands[history.current][MAX_COMMAND_LEN - 1] = '\0';

    history.current = (history.current + 1) % MAX_HISTORY;
    if (history.count < MAX_HISTORY) {
        history.count++;
    }
}

char* get_last_command() {
    if (history.count == 0) return NULL;

    int last_index = (history.current - 1 + MAX_HISTORY) % MAX_HISTORY;
    return history.commands[last_index];
}

void print_history() {
    if (history.count == 0) {
        printf("No commands in history\n");
        return;
    }

    int start_index = (history.count < MAX_HISTORY) ? 0 : history.current;

    for (int i = 0; i < history.count; i++) {
        int index = (start_index + i) % MAX_HISTORY;
        printf("%4d  %s\n", i + 1, history.commands[index]);
    }
}

int count_pipes(char* input) {
    int count = 0;
    for (int i = 0; input[i]; i++) {
        if (input[i] == '|') count++;
    }
    return count;
}

void execute_single_command(char** args) {
    pid_t pid = fork();
    if (pid == 0) {
        execvp(args[0], args);
        fprintf(stderr, "%s: command not found\n", args[0]);
        exit(EXIT_FAILURE);
    }
    else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
    }
    else {
        perror("fork failed");
    }
}

void parse_redirections(char* input, char** argv, Redirection* redir) {
    memset(redir, 0, sizeof(Redirection));
    char* input_copy = strdup(input);
    if (input_copy == NULL) {
        perror("strdup failed");
        return;
    }

    int argc = 0;
    char* token = strtok(input_copy, " ");

    while (token != NULL && argc < MAX_ARGS - 1) {
        if (strcmp(token, ">") == 0) {
            token = strtok(NULL, " ");
            if (token) {
                redir->output_file = strdup(token);
                redir->output_append = 0;
            }
        }
        else if (strcmp(token, ">>") == 0) {
            token = strtok(NULL, " ");
            if (token) {
                redir->output_file = strdup(token);
                redir->output_append = 1;
            }
        }
        else if (strcmp(token, "<") == 0) {
            token = strtok(NULL, " ");
            if (token) {
                redir->input_file = strdup(token);
                redir->has_heredoc = 0;
            }
        }
        else if (strcmp(token, "<<") == 0) {
            token = strtok(NULL, " ");
            if (token) {
                redir->heredoc_delimiter = strdup(token);
                redir->has_heredoc = 1;
                redir->heredoc_content = read_heredoc(token);
            }
        }
        else {
            argv[argc++] = strdup(token);
        }
        token = strtok(NULL, " ");
    }
    argv[argc] = NULL;

    free(input_copy);
}

void setup_redirections(Redirection* redir) {
    if (redir->has_heredoc && redir->heredoc_content) {
        int pipefd[2];
        if (pipe(pipefd) == -1) {
            perror("pipe failed for heredoc");
            return;
        }

        pid_t pid = fork();
        if (pid == 0) {
            close(pipefd[0]);
            write(pipefd[1], redir->heredoc_content, strlen(redir->heredoc_content));
            close(pipefd[1]);
            free(redir->heredoc_content);
            exit(0);
        } else if (pid > 0) {
            close(pipefd[1]);
            dup2(pipefd[0], STDIN_FILENO);
            close(pipefd[0]);
        }
    }
    else if (redir->input_file) {
        int fd = open(redir->input_file, O_RDONLY);
        if (fd == -1) {
            perror("open input file failed");
            return;
        }
        dup2(fd, STDIN_FILENO);
        close(fd);
    }

    if (redir->output_file) {
        int flags = O_WRONLY | O_CREAT;
        if (redir->output_append) {
            flags |= O_APPEND;
        } else {
            flags |= O_TRUNC;
        }

        int fd = open(redir->output_file, flags, 0644);
        if (fd == -1) {
            perror("open output file failed");
            return;
        }
        dup2(fd, STDOUT_FILENO);
        close(fd);
    }
}

void cleanup_redirections(Redirection* redir) {
    if (redir->input_file) {
        free(redir->input_file);
        redir->input_file = NULL;
    }
    if (redir->output_file) {
        free(redir->output_file);
        redir->output_file = NULL;
    }
    if (redir->heredoc_delimiter) {
        free(redir->heredoc_delimiter);
        redir->heredoc_delimiter = NULL;
    }
    if (redir->heredoc_content) {
        free(redir->heredoc_content);
        redir->heredoc_content = NULL;
    }
}

char* read_heredoc(const char* delimiter) {
    printf("Enter text (end with '%s' on a new line):\n", delimiter);
    char* content = malloc(MAX_HEREDOC_LEN);
    if (content == NULL) {
        perror("malloc failed for heredoc");
        return NULL;
    }

    content[0] = '\0';
    char* line = NULL;
    size_t len = 0;
    ssize_t read;

    while ((read = getline(&line, &len, stdin)) != -1) {
        if (line[read - 1] == '\n') line[read - 1] = '\0';

        if (strcmp(line, delimiter) == 0) {
            break;
        }

        if (strlen(content) + strlen(line) + 2 < MAX_HEREDOC_LEN) {
            strcat(content, line);
            strcat(content, "\n");
        } else {
            printf("Heredoc content too large\n");
            break;
        }
    }

    if (line) free(line);
    return content;
}

void execute_piped_commands(char* input) {
    char* input_copy = strdup(input);
    if (input_copy == NULL) {
        perror("strdup failed");
        return;
    }

    char* commands[MAX_PIPES + 1];
    int num_commands = 0;

    char* token = strtok(input_copy, "|");
    while (token != NULL && num_commands < MAX_PIPES) {
        while (*token == ' ') token++;
        size_t len = strlen(token);
        while (len > 0 && token[len - 1] == ' ') {
            token[len - 1] = '\0';
            len--;
        }
        commands[num_commands++] = token;
        token = strtok(NULL, "|");
    }

    if (num_commands == 0) {
        free(input_copy);
        return;
    }

    int pipes[MAX_PIPES - 1][2];
    for (int i = 0; i < num_commands - 1; i++) {
        if (pipe(pipes[i]) == -1) {
            perror("pipe failed");
            free(input_copy);
            return;
        }
    }

    pid_t pids[MAX_PIPES];
    for (int i = 0; i < num_commands; i++) {
        char* args[MAX_ARGS];
        Redirection redir = {0};

        parse_redirections(commands[i], args, &redir);

        if (args[0] == NULL) {
            cleanup_redirections(&redir);
            continue;
        }

        pids[i] = fork();
        if (pids[i] == 0) {
            if (i > 0 && !redir.input_file && !redir.has_heredoc) {
                dup2(pipes[i - 1][0], STDIN_FILENO);
            }

            if (i < num_commands - 1 && !redir.output_file) {
                dup2(pipes[i][1], STDOUT_FILENO);
            }

            for (int j = 0; j < num_commands - 1; j++) {
                close(pipes[j][0]);
                close(pipes[j][1]);
            }

            setup_redirections(&redir);

            execvp(args[0], args);
            fprintf(stderr, "%s: command not found\n", args[0]);
            exit(EXIT_FAILURE);
        }
        else if (pids[i] < 0) {
            perror("fork failed");
        }

        cleanup_redirections(&redir);
        for (int j = 0; args[j] != NULL; j++) {
            free(args[j]);
        }
    }

    for (int i = 0; i < num_commands - 1; i++) {
        close(pipes[i][0]);
        close(pipes[i][1]);
    }

    for (int i = 0; i < num_commands; i++) {
        if (pids[i] > 0) {
            int status;
            waitpid(pids[i], &status, 0);
        }
    }

    free(input_copy);
}

