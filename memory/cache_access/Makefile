CXX=g++
CXX_FLAGS=-Wall --std=c++2a -g -march=native
LDFLAGS=

SRC_PATH=./src
INC_PATH=./inc
OUT_PATH=./out

_DEPS = matrix_common.hpp
DEPS = $(patsubst %,$(INC_PATH)/%,$(_DEPS))

CLS=$(shell getconf LEVEL1_DCACHE_LINESIZE)
CXX_FLAGS += -DCLS=${CLS}

SRC=$(wildcard $(SRC_PATH)/*.cpp)
OUT=$(subst $(OBJ_PATH),$(OUT_PATH),$(OBJ:.o=))

.PHONY: all
all: sf tr ca playground

# straight forward
sf: $(SRC_PATH)/sf.cpp | $(OUT_PATH)
	$(CXX) $(CXX_FLAGS) -I$(INC_PATH) $< $(SRC_PATH)/matrix_common.cpp -o $(OUT_PATH)/$@

# transposed
tr: $(SRC_PATH)/tr.cpp | $(OUT_PATH)
	$(CXX) $(CXX_FLAGS) -I$(INC_PATH) $< $(SRC_PATH)/matrix_common.cpp -o $(OUT_PATH)/$@

# cache aligned
ca: $(SRC_PATH)/ca.cpp | $(OUT_PATH)
	$(CXX) $(CXX_FLAGS) -I$(INC_PATH) $< $(SRC_PATH)/matrix_common.cpp -o $(OUT_PATH)/$@


# playground
playground: $(SRC_PATH)/intrinsics_playground.cpp | $(OUT_PATH)
	$(CXX) $(CXX_FLAGS) $< -o $(OUT_PATH)/$@

$(OUT_PATH):
	@mkdir -p $(OUT_PATH)

.PHONY: clean
clean:
	@rm -rf run $(OUT_PATH)