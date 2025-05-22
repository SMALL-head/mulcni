# 定义需要处理的BPF目录列表
BPF_DIRS := redirect tc xdp

build-bpf:
	@echo "Building BPF programs in 'go generate'..."
	@for dir in $(BPF_DIRS); do \
		echo "处理 $$dir 目录..."; \
		# 阶段1: 运行 go generate \
		(cd ./pkg/ebpfProc/$$dir && go generate) || { \
			echo "在 $$dir 中执行 go generate 失败"; \
			exit 1; \
		}; \
		# 阶段2: 使用 clang 和 llc 编译 BPF 程序 \
		echo "building BPF program in clang'..."; \
		(cd ./pkg/ebpfProc/$$dir && \
		clang -g -O2 -I../include -Wall -target bpf -c $$dir.bpf.c -o $$dir.o) || { \
			echo "在 $$dir 中编译 BPF 程序失败"; \
			exit 1; \
		}; \
	done
	@echo "BPF 程序构建完成"
