CC = clang
FLAGS = -Wall -Wextra -pedantic -O0 -O3 -g -fsanitize=address -fno-omit-frame-pointer -fno-optimize-sibling-calls
ODIR = build
SDIR = src
INDIC = [make]
CWD = $(shell pwd)
CHECKMARK = ✅


all : scanner


scanner : $(ODIR)/scan_tools.o  $(ODIR)/client.o 
	@$(CC) $(FLAGS) $(ODIR)/scan_tools.o  $(ODIR)/client.o  -o scanner.out
	@echo $(INDIC) build $(CHECKMARK)

$(ODIR)/scan_tools.o : $(SDIR)/scan_tools/scan_tools.c $(SDIR)/scan_tools/scan_tools.h
	@$(CC) -c $(FLAGS) $(SDIR)/scan_tools/scan_tools.c -o  $(ODIR)/scan_tools.o 

$(ODIR)/client.o : $(SDIR)/client/client.c $(SDIR)/client/client.h
	@$(CC) -c $(FLAGS) $(SDIR)/client/client.c -o  $(ODIR)/client.o 

clean :
	@rm -rf $(ODIR)/*.o
	@rm -rf *.out	
	@echo $(INDIC) clean $(CHECKMARK)


