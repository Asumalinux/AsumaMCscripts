package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gorcon/rcon"
)

const (
	serverAddr = "5.83.140.252:25888" 
	password   = "easy123"  
)

func main() {
	fmt.Printf("[*] Подключение к RCON %s...\n", serverAddr)

	// Правильный синтаксис подключения с таймаутом для библиотеки gorcon
	conn, err := rcon.Dial(serverAddr, password, rcon.SetDialTimeout(5*time.Second))
	if err != nil {
		fmt.Printf("[-] Ошибка подключения: %v\n", err)
		return
	}
	defer conn.Close()

	fmt.Println("[+] Успешное подключение к консоли сервера!")
	fmt.Println("Введите 'exit' или 'quit' для завершения работы.\n")

	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("RCON_Console> ")
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("[-] Ошибка чтения ввода: %v\n", err)
			break
		}

		command := strings.TrimSpace(input)
		if command == "" {
			continue
		}
		if command == "exit" || command == "quit" {
			fmt.Println("[*] Выход из консоли.")
			break
		}

		response, err := conn.Execute(command)
		if err != nil {
			fmt.Printf("[-] Ошибка выполнения команды: %v\n", err)
			break
		}
		fmt.Println(response)
	}
}
