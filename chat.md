现在我需要编写一个生成bpf的make命令，它分为两个阶段：
遍历进入./pkg/ebpfProc下的选定目录（这个选定文件以变量的形式写在Makefile中，比如说redirect目录），然后每个目录里执行下面两个阶段
阶段1：在这些目录中使用`go generate`命令生成对应的文件
阶段2：在这些目录中使用`clang -O2 -emit-llvm -c {目录名}.bpf.c -o - | llc -march=bpf -filetype=obj -o {目录名}.o`

请帮我比较下面两种map的声明方式的区别，注意一个有意思的现象，第一种声明方式可以在tc中挂载，但是第二种不能。
```c
// 第一种
struct bpf_elf_map __section("maps") testmap = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(int),
	.size_value	= sizeof(int),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= 8,
};
```

```c
// 第二种
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} testmap SEC(".maps");
```
