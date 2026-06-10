package main

//go:generate go tool bpf2go -cc bpf-clang -tags linux counter ./counter.c
