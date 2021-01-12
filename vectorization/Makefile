CXX=g++
OPT_FLAG=-g
CXX_FLAGS=-c -Wall --std=c++2a ${OPT_FLAG}
SRC_PATH=./src
OBJ_PATH=./obj
OUT_PATH=./out
LDFLAGS=

SRC=$(wildcard $(SRC_PATH)/*.cpp)
OBJ=$(subst $(SRC_PATH),$(OBJ_PATH),$(SRC:.cpp=.o))
OUT=$(subst $(OBJ_PATH),$(OUT_PATH),$(OBJ:.o=))

.PHONY: all
all: $(SRC) $(OUT)

$(OBJ): $(OBJ_PATH)/%.o: $(SRC_PATH)/%.cpp | $(OBJ_PATH)
	$(CXX) $(CXX_FLAGS) $< -o $@

$(OUT): $(OUT_PATH)/%: $(OBJ_PATH)/%.o | $(OUT_PATH)
	$(CXX) $(LDFLAGS) $< -o $@

$(OBJ_PATH):
	@mkdir -p $(OBJ_PATH)

$(OUT_PATH):
	@mkdir -p $(OUT_PATH)

.PHONY: O3
O3: OPT_FLAG=-O3
O3: all

.PHONY: clean
clean:
	@rm -rf run $(OBJ_PATH)
	@rm -rf run $(OUT_PATH)