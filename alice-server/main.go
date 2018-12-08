package main

import (
	"cryptmail/alice"
	"cryptmail/protocol"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"log"
	"net"
	"os"
	"path/filepath"
)

const (
	dirname = ".cmail"
	port    = ":6600"
)

func homeDir() string {
	if home := os.Getenv("HOME"); home != "" {
		return home
	}
	return ""
}

func main() {
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	home := homeDir()
	dirPath := filepath.Join(home, dirname)
	server := alice.NewAlice(dirPath)
	err = server.Init()
	if err != nil {
		log.Fatalf("failed to init alice server: %v", err)
	}
	protocol.RegisterAliceServer(s, server)
	reflection.Register(s)
	if err = s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
