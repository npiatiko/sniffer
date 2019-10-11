NAME_DAEMON = sniff
NAME_CLI = cli

FLAGS = -Wall -Wextra -Werror

SRCS_DAEMON =	./src/file_worker.c
                ./src/filter_exp.c
                ./src/ip_list.c
                ./src/main.c
                ./src/signal_handler.c

SRCS_CLI = 		src/cli.c

INC =			./include/hh.h

OBJ_DAEMON = $(SRCS_DAEMON:.c=.o)

OBJ_CLI = $(SRCS_CLI:.c=.o)

.PHONY : re clean fclean all

all: $(NAME_DAEMON) $(NAME_CLI)

$(NAME_DAEMON): $(OBJ_DAEMON)
	gcc -o $(NAME_DAEMON) $(OBJ_DAEMON) -lpcap

$(NAME_CLI): $(OBJ_CLI)
	gcc -o $(NAME_CLI) $(OBJ_CLI)

./src/%.o: ./src/%.c $(INC)
	gcc $(FLAGS) -I./include -o $@ -c $<

clean:
	rm -f $(OBJ_DAEMON)
	rm -f $(OBJ_CLI)

fclean: clean
	rm -f $(NAME_DAEMON)
	rm -f $(NAME_CLI)

re: fclean all
